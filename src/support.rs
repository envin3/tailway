//! Redaction for the support bundle, a JSON summary to attach to a bug
//! report: device names become `device-1`, `device-2`, …, and tailnet
//! addresses are hidden. Keys and tokens are never included in the bundle.

use std::net::{IpAddr, Ipv4Addr};

pub struct Redactor {
    /// Device names and their replacements, longest first so that a name
    /// containing another is replaced whole.
    names: Vec<(String, String)>,
}

impl Redactor {
    pub fn new(device_names: impl IntoIterator<Item = String>) -> Self {
        let mut unique: Vec<String> = device_names
            .into_iter()
            .filter(|name| !name.is_empty())
            .collect();
        unique.sort();
        unique.dedup();
        let mut names: Vec<(String, String)> = unique
            .into_iter()
            .enumerate()
            .map(|(index, name)| (name, format!("device-{}", index + 1)))
            .collect();
        names.sort_by_key(|(name, _)| std::cmp::Reverse(name.len()));
        Self { names }
    }

    pub fn text(&self, value: &str) -> String {
        let mut value = value.to_owned();
        for (name, replacement) in &self.names {
            value = replace_word(&value, name, replacement);
        }
        hide_tailnet_addresses(&value)
    }
}

/// Replaces `word` where it stands alone: a device named `tv` must not turn
/// `tvOS` into `device-1OS`.
fn replace_word(value: &str, word: &str, replacement: &str) -> String {
    let part_of_name = |character: Option<char>| {
        character.is_some_and(|character| {
            character.is_alphanumeric() || character == '-' || character == '_'
        })
    };
    let mut out = String::with_capacity(value.len());
    let mut rest = value;
    while let Some(index) = rest.find(word) {
        let before = rest[..index]
            .chars()
            .next_back()
            .or_else(|| out.chars().next_back());
        let after = rest[index + word.len()..].chars().next();
        out.push_str(&rest[..index]);
        if part_of_name(before) || part_of_name(after) {
            out.push_str(word);
        } else {
            out.push_str(replacement);
        }
        rest = &rest[index + word.len()..];
    }
    out.push_str(rest);
    out
}

fn tailnet(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            let [first, second, ..] = address.octets();
            first == 100 && second & 0xc0 == 64
        }
        IpAddr::V6(address) => address.segments()[..3] == [0xfd7a, 0x115c, 0xa1e0],
    }
}

/// Replaces every tailnet IPv4 (100.64.0.0/10) or IPv6 (fd7a:115c:a1e0::/48)
/// address in `value` with `<tailnet address>`.
fn hide_tailnet_addresses(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut token = String::new();
    let flush = |token: &mut String, out: &mut String| {
        let parsed = token
            .parse::<IpAddr>()
            .ok()
            .or_else(|| token.parse::<Ipv4Addr>().ok().map(IpAddr::V4));
        if parsed.is_some_and(tailnet) {
            out.push_str("<tailnet address>");
        } else {
            out.push_str(token);
        }
        token.clear();
    };
    for character in value.chars() {
        if character.is_ascii_hexdigit() || character == '.' || character == ':' {
            token.push(character);
        } else {
            flush(&mut token, &mut out);
            out.push(character);
        }
    }
    flush(&mut token, &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hides_device_names_and_tailnet_addresses() {
        let redactor = Redactor::new(["envin-desktop".to_owned(), "envin".to_owned()]);
        assert_eq!(
            redactor.text("envin-desktop (100.113.53.91): ES#146 → blocked; envin signed in from fd7a:115c:a1e0::7131:bc68"),
            "device-2 (<tailnet address>): ES#146 → blocked; device-1 signed in from <tailnet address>"
        );
        let short = Redactor::new(["tv".to_owned()]);
        assert_eq!(
            short.text("tv uses tvOS; the tv."),
            "device-1 uses tvOS; the device-1."
        );
        assert_eq!(
            redactor.text("public IP 79.127.139.149 via 192.168.0.52"),
            "public IP 79.127.139.149 via 192.168.0.52"
        );
    }
}
