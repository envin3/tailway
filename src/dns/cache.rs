//! A small answer cache for the forwarder, one scope per upstream.
//!
//! Entries are keyed by the upstream (address and routing mark) as well as the
//! question, so an answer fetched through one route is never served to a
//! device on another. Only plain answers are kept: success or NXDOMAIN, not
//! truncated, for queries without EDNS options (cookies or client subnet would
//! tie an answer to one client). TTLs count down while an entry is cached, and
//! lifetimes are capped so a changed tunnel or server is picked up quickly.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use tokio::time::Instant;

use super::Upstream;

/// Longest time a positive answer is served from the cache.
const MAX_POSITIVE: u32 = 300;
/// Longest time a negative answer (NXDOMAIN or no data) is served.
const MAX_NEGATIVE: u32 = 60;
const MAX_ENTRIES: usize = 4096;
/// Largest UDP answer a client accepts without EDNS.
const PLAIN_UDP_LIMIT: usize = 512;
const HEADER: usize = 12;
const TYPE_OPT: u16 = 41;
const NXDOMAIN: u8 = 3;

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(super) struct Key {
    upstream: Upstream,
    /// The flags that change an answer (RD, AD, CD, DO), then the lowercased
    /// question name, type, and class.
    question: Vec<u8>,
}

/// A query that may be answered from the cache.
pub(super) struct Lookup {
    pub key: Key,
    /// End of the question section, the same in the query and its answer.
    question_end: usize,
    /// The largest answer the client accepts over UDP.
    udp_limit: usize,
}

impl Lookup {
    /// `None` for queries the cache does not handle.
    pub fn of(upstream: Upstream, query: &[u8]) -> Option<Self> {
        if query.len() < HEADER || query[2] & 0x80 != 0 || (query[2] >> 3) & 0x0f != 0 {
            return None;
        }
        if count(query, 4) != 1 || count(query, 6) != 0 || count(query, 8) != 0 {
            return None;
        }
        let additional = count(query, 10);
        let name_end = plain_name_end(query, HEADER)?;
        let question_end = name_end + 4;
        let (udp_limit, dnssec_ok) = match additional {
            0 if question_end == query.len() => (PLAIN_UDP_LIMIT, false),
            1 => {
                // Only a bare OPT record: root name, type OPT, version 0, no options.
                let opt = query.get(question_end..)?;
                if opt.len() != 11
                    || opt[0] != 0
                    || u16::from_be_bytes([opt[1], opt[2]]) != TYPE_OPT
                {
                    return None;
                }
                if opt[6] != 0 || opt[9..11] != [0, 0] {
                    return None;
                }
                let size = usize::from(u16::from_be_bytes([opt[3], opt[4]]));
                (size.max(PLAIN_UDP_LIMIT), opt[7] & 0x80 != 0)
            }
            _ => return None,
        };
        let mut question = vec![query[2] & 0x01, query[3] & 0x30, u8::from(dnssec_ok)];
        question.extend(
            query[HEADER..question_end]
                .iter()
                .map(u8::to_ascii_lowercase),
        );
        Some(Self {
            key: Key { upstream, question },
            question_end,
            udp_limit,
        })
    }
}

struct Entry {
    response: Vec<u8>,
    /// Offsets of every TTL to count down (all records but OPT).
    ttls: Vec<usize>,
    stored: Instant,
    lifetime: u32,
}

impl Entry {
    fn expires(&self) -> Instant {
        self.stored + Duration::from_secs(self.lifetime.into())
    }
}

#[derive(Default)]
pub(super) struct Cache {
    entries: Mutex<HashMap<Key, Entry>>,
}

impl Cache {
    /// The cached answer for `query`, with its ID, question spelling, and
    /// remaining TTLs; `None` on a miss or if it is too large for the client.
    pub fn get(&self, lookup: &Lookup, query: &[u8], udp: bool) -> Option<Vec<u8>> {
        let mut entries = self.lock();
        let entry = entries.get(&lookup.key)?;
        let elapsed = u32::try_from(entry.stored.elapsed().as_secs()).unwrap_or(u32::MAX);
        if elapsed >= entry.lifetime {
            entries.remove(&lookup.key);
            return None;
        }
        if udp && entry.response.len() > lookup.udp_limit {
            return None;
        }
        let mut response = entry.response.clone();
        response[..2].copy_from_slice(&query[..2]);
        // Echo the client's own letter case (some randomise it).
        response[HEADER..lookup.question_end].copy_from_slice(&query[HEADER..lookup.question_end]);
        for &offset in &entry.ttls {
            let ttl = &mut response[offset..offset + 4];
            let remaining =
                u32::from_be_bytes([ttl[0], ttl[1], ttl[2], ttl[3]]).saturating_sub(elapsed);
            ttl.copy_from_slice(&remaining.to_be_bytes());
        }
        Some(response)
    }

    /// Keeps `response` if it is a cacheable answer to the looked-up query.
    pub fn insert(&self, lookup: Lookup, query: &[u8], response: &[u8]) {
        let Some((ttls, lifetime)) = cacheable(query, lookup.question_end, response) else {
            return;
        };
        let now = Instant::now();
        let mut entries = self.lock();
        if entries.len() >= MAX_ENTRIES && !entries.contains_key(&lookup.key) {
            entries.retain(|_, entry| entry.expires() > now);
            if entries.len() >= MAX_ENTRIES {
                let soonest = entries
                    .iter()
                    .min_by_key(|(_, entry)| entry.expires())
                    .map(|(key, _)| key.clone());
                if let Some(key) = soonest {
                    entries.remove(&key);
                }
            }
        }
        entries.insert(
            lookup.key,
            Entry {
                response: response.to_vec(),
                ttls,
                stored: now,
                lifetime,
            },
        );
    }

    pub fn clear(&self) {
        self.lock().clear();
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.lock().len()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<Key, Entry>> {
        self.entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// The TTL offsets and cache lifetime of a well-formed, complete answer to
/// `query`, or `None` if it must not be cached.
fn cacheable(query: &[u8], question_end: usize, response: &[u8]) -> Option<(Vec<usize>, u32)> {
    if response.len() < question_end || response[..2] != query[..2] {
        return None;
    }
    // A response, standard query, not truncated.
    if response[2] & 0x80 == 0 || (response[2] >> 3) & 0x0f != 0 || response[2] & 0x02 != 0 {
        return None;
    }
    let rcode = response[3] & 0x0f;
    if rcode != 0 && rcode != NXDOMAIN {
        return None;
    }
    if count(response, 4) != 1
        || !response[HEADER..question_end].eq_ignore_ascii_case(&query[HEADER..question_end])
    {
        return None;
    }
    let answers = count(response, 6);
    let records =
        usize::from(answers) + usize::from(count(response, 8)) + usize::from(count(response, 10));
    let mut position = question_end;
    let mut ttls = Vec::new();
    let mut shortest = u32::MAX;
    for _ in 0..records {
        position = name_end(response, position)?;
        let fixed = response.get(position..position + 10)?;
        let kind = u16::from_be_bytes([fixed[0], fixed[1]]);
        let length = usize::from(u16::from_be_bytes([fixed[8], fixed[9]]));
        if kind != TYPE_OPT {
            ttls.push(position + 4);
            shortest = shortest.min(u32::from_be_bytes([fixed[4], fixed[5], fixed[6], fixed[7]]));
        }
        position += 10 + length;
    }
    if position != response.len() || ttls.is_empty() {
        // Malformed, or a negative answer without the SOA that dates it.
        return None;
    }
    let cap = if rcode == NXDOMAIN || answers == 0 {
        MAX_NEGATIVE
    } else {
        MAX_POSITIVE
    };
    let lifetime = shortest.min(cap);
    (lifetime > 0).then_some((ttls, lifetime))
}

fn count(message: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([message[offset], message[offset + 1]])
}

/// End of an uncompressed name (a question's).
fn plain_name_end(message: &[u8], mut position: usize) -> Option<usize> {
    loop {
        let label = usize::from(*message.get(position)?);
        position += 1;
        match label {
            0 => return Some(position),
            1..=63 => position += label,
            _ => return None,
        }
    }
}

/// End of a possibly compressed name.
fn name_end(message: &[u8], mut position: usize) -> Option<usize> {
    loop {
        let label = usize::from(*message.get(position)?);
        match label {
            0 => return Some(position + 1),
            1..=63 => position += 1 + label,
            _ if label & 0xc0 == 0xc0 => {
                message.get(position + 1)?;
                return Some(position + 2);
            }
            _ => return None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddrV4};

    use super::*;

    fn upstream(mark: Option<u32>) -> Upstream {
        Upstream {
            address: SocketAddrV4::new(Ipv4Addr::new(10, 2, 0, 1), 53),
            mark,
        }
    }

    /// A query for `name` (type A), optionally with a bare OPT record.
    fn query(id: u16, name: &str, edns: Option<u16>) -> Vec<u8> {
        let mut message = id.to_be_bytes().to_vec();
        message.extend([0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, u8::from(edns.is_some())]);
        for label in name.split('.') {
            message.push(label.len() as u8);
            message.extend(label.as_bytes());
        }
        message.extend([0, 0, 1, 0, 1]);
        if let Some(size) = edns {
            message.extend([0, 0, 41]);
            message.extend(size.to_be_bytes());
            message.extend([0, 0, 0, 0, 0, 0]);
        }
        message
    }

    /// An answer to `query` with one A record per TTL (compressed names).
    fn answer(query: &[u8], ttls: &[u32]) -> Vec<u8> {
        let question_end = plain_name_end(query, HEADER).unwrap() + 4;
        let mut message = query[..question_end].to_vec();
        message[2] = 0x81;
        message[3] = 0x80;
        message[6..8].copy_from_slice(&(ttls.len() as u16).to_be_bytes());
        message[10..12].fill(0);
        for ttl in ttls {
            message.extend([0xc0, 12, 0, 1, 0, 1]);
            message.extend(ttl.to_be_bytes());
            message.extend([0, 4, 192, 0, 2, 1]);
        }
        message
    }

    fn ttls_of(response: &[u8]) -> Vec<u32> {
        let (offsets, _) = cacheable(
            response,
            plain_name_end(response, HEADER).unwrap() + 4,
            response,
        )
        .unwrap();
        offsets
            .iter()
            .map(|&offset| u32::from_be_bytes(response[offset..offset + 4].try_into().unwrap()))
            .collect()
    }

    fn store(cache: &Cache, upstream: Upstream, query: &[u8], response: &[u8]) {
        cache.insert(Lookup::of(upstream, query).unwrap(), query, response);
    }

    fn fetch(cache: &Cache, upstream: Upstream, query: &[u8]) -> Option<Vec<u8>> {
        cache.get(&Lookup::of(upstream, query).unwrap(), query, true)
    }

    #[tokio::test(start_paused = true)]
    async fn serves_with_the_callers_id_and_counts_ttls_down() {
        let cache = Cache::default();
        let first = query(1, "example.com", None);
        store(
            &cache,
            upstream(Some(0x100)),
            &first,
            &answer(&first, &[60, 30]),
        );

        tokio::time::advance(Duration::from_secs(10)).await;
        let second = query(2, "Example.COM", None);
        let cached = fetch(&cache, upstream(Some(0x100)), &second).unwrap();
        assert_eq!(cached[..2], [0, 2]);
        assert_eq!(cached[12..25], second[12..25], "echoes the caller's case");
        assert_eq!(ttls_of(&cached), [50, 20]);

        tokio::time::advance(Duration::from_secs(20)).await;
        assert!(fetch(&cache, upstream(Some(0x100)), &second).is_none());
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn never_crosses_routes() {
        let cache = Cache::default();
        let query = query(1, "example.com", None);
        store(
            &cache,
            upstream(Some(0x100)),
            &query,
            &answer(&query, &[60]),
        );
        assert!(fetch(&cache, upstream(Some(0x200)), &query).is_none());
        assert!(fetch(&cache, upstream(None), &query).is_none());
        assert!(fetch(&cache, upstream(Some(0x100)), &query).is_some());
    }

    #[tokio::test(start_paused = true)]
    async fn caps_lifetimes() {
        let cache = Cache::default();
        let query = query(1, "example.com", None);
        store(&cache, upstream(None), &query, &answer(&query, &[86_400]));
        tokio::time::advance(Duration::from_secs(u64::from(MAX_POSITIVE))).await;
        assert!(fetch(&cache, upstream(None), &query).is_none());

        let mut nxdomain = answer(&query, &[]);
        nxdomain[3] = 0x83;
        // Authority: an SOA-like record with a long TTL.
        nxdomain[8..10].copy_from_slice(&[0, 1]);
        nxdomain.extend([0xc0, 12, 0, 6, 0, 1, 0, 0, 0x0e, 0x10, 0, 1, 0]);
        store(&cache, upstream(None), &query, &nxdomain);
        assert!(fetch(&cache, upstream(None), &query).is_some());
        tokio::time::advance(Duration::from_secs(u64::from(MAX_NEGATIVE))).await;
        assert!(fetch(&cache, upstream(None), &query).is_none());
    }

    #[test]
    fn skips_what_it_cannot_serve_faithfully() {
        let cache = Cache::default();
        let plain = query(1, "example.com", None);
        for response in [
            {
                let mut truncated = answer(&plain, &[60]);
                truncated[2] |= 0x02;
                truncated
            },
            {
                let mut servfail = answer(&plain, &[60]);
                servfail[3] = 0x82;
                servfail
            },
            answer(&plain, &[0]),
            answer(&plain, &[]),
            answer(&plain, &[60])[..40].to_vec(),
        ] {
            store(&cache, upstream(None), &plain, &response);
        }
        assert_eq!(cache.len(), 0);

        // Queries with EDNS options (here a cookie) are not looked up at all.
        let mut cookie = query(1, "example.com", Some(1232));
        let length = cookie.len();
        cookie[length - 2..].copy_from_slice(&[0, 12]);
        cookie.extend([0, 10, 0, 8, 1, 2, 3, 4, 5, 6, 7, 8]);
        assert!(Lookup::of(upstream(None), &cookie).is_none());
    }

    #[test]
    fn respects_the_clients_udp_size() {
        let cache = Cache::default();
        let large = query(1, "example.com", Some(4096));
        let ttls = [60; 40];
        let response = answer(&large, &ttls);
        assert!(response.len() > PLAIN_UDP_LIMIT);
        store(&cache, upstream(None), &large, &response);
        // A client that takes only 512 bytes over UDP is sent upstream instead.
        let plain = query(2, "example.com", Some(512));
        let lookup = Lookup::of(upstream(None), &plain).unwrap();
        assert!(cache.get(&lookup, &plain, true).is_none());
        assert!(
            cache.get(&lookup, &plain, false).is_some(),
            "TCP has no limit"
        );
    }

    #[test]
    fn keys_on_the_flags_that_change_answers() {
        let cache = Cache::default();
        let query = query(1, "example.com", Some(1232));
        store(&cache, upstream(None), &query, &answer(&query, &[60]));
        let mut dnssec = query.clone();
        let length = dnssec.len();
        dnssec[length - 4] = 0x80;
        assert!(fetch(&cache, upstream(None), &dnssec).is_none());
        let mut checking_disabled = query.clone();
        checking_disabled[3] |= 0x10;
        assert!(fetch(&cache, upstream(None), &checking_disabled).is_none());
    }

    #[test]
    fn stays_bounded() {
        let cache = Cache::default();
        for index in 0..MAX_ENTRIES + 10 {
            let query = query(1, &format!("host{index}.example"), None);
            store(&cache, upstream(None), &query, &answer(&query, &[60]));
        }
        assert_eq!(cache.len(), MAX_ENTRIES);
    }
}
