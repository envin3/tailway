//! Per-device DNS for tailnet clients.
//!
//! When the tailnet's DNS server is this gateway, every client's lookups arrive
//! here with the client's own tailnet address. Devices routed through a Proton
//! exit are answered by that exit's resolver through the same tunnel; every other
//! device uses its configured DNS server. A Proton device whose tunnel is down
//! gets SERVFAIL unless its kill switch is off.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use anyhow::{Context, Result};
use socket2::SockRef;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket, TcpStream, UdpSocket};
use tokio::sync::Semaphore;
use tracing::warn;

use crate::domain::{Assignment, Device, Exit, NodeDns, is_builtin_route};
use crate::policy::routable;

/// Proton's resolver, reachable only inside a Proton tunnel.
pub const PROTON_RESOLVER: Ipv4Addr = Ipv4Addr::new(10, 2, 0, 1);
const DNS_PORT: u16 = 53;
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(3);
const CLIENT_IDLE_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_UDP_MESSAGE: usize = 4096;
const MAX_IN_FLIGHT: usize = 256;
pub const SERVFAIL: u8 = 2;
pub const REFUSED: u8 = 5;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Defaults {
    pub server: Ipv4Addr,
    pub kill_switch: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Upstream {
    pub address: SocketAddrV4,
    /// Routing mark selecting a Proton tunnel; `None` uses the gateway's own route.
    pub mark: Option<u32>,
}

impl Upstream {
    fn server(address: Ipv4Addr) -> Self {
        Self {
            address: SocketAddrV4::new(address, DNS_PORT),
            mark: None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Resolution {
    /// Through the device's own Proton tunnel. `fallback` is set only when the
    /// kill switch is off and is used if the tunnel resolver does not answer.
    Proton {
        exit_id: String,
        upstream: Upstream,
        fallback: Option<Upstream>,
    },
    /// The device's Proton exit is unavailable and its kill switch is on.
    Blocked {
        exit_id: String,
    },
    Server(Upstream),
    /// No plan has been published yet (agent starting): nobody is known, so
    /// fail closed rather than send a Proton device's lookups over the WAN.
    NotReady,
}

impl Resolution {
    pub fn kind(&self) -> &'static str {
        match self {
            Resolution::Proton { .. } => "proton",
            Resolution::Blocked { .. } => "blocked",
            Resolution::Server(_) => "server",
            Resolution::NotReady => "starting",
        }
    }
}

pub struct PlanInput<'a> {
    pub devices: &'a [Device],
    pub assignments: &'a [Assignment],
    /// Runtime exits carrying health and routing marks.
    pub exits: &'a [Exit],
    pub settings: &'a [NodeDns],
    pub defaults: Defaults,
}

/// Effective settings for one node after applying defaults.
pub fn effective(setting: Option<&NodeDns>, defaults: Defaults) -> (Ipv4Addr, bool) {
    (
        setting
            .and_then(|setting| setting.server)
            .unwrap_or(defaults.server),
        setting
            .and_then(|setting| setting.kill_switch)
            .unwrap_or(defaults.kill_switch),
    )
}

pub fn plan(input: PlanInput<'_>) -> HashMap<Ipv4Addr, Resolution> {
    let assignments: HashMap<&str, &str> = input
        .assignments
        .iter()
        .map(|assignment| (assignment.node_id.as_str(), assignment.exit_id.as_str()))
        .collect();
    let settings: HashMap<&str, &NodeDns> = input
        .settings
        .iter()
        .map(|setting| (setting.node_id.as_str(), setting))
        .collect();
    let exits: HashMap<&str, &Exit> = input
        .exits
        .iter()
        .map(|exit| (exit.id.as_str(), exit))
        .collect();
    let mut plan = HashMap::new();
    for device in input.devices {
        let (server, kill_switch) = effective(
            settings.get(device.node_id.as_str()).copied(),
            input.defaults,
        );
        let home = Upstream::server(server);
        let resolution = match assignments.get(device.node_id.as_str()) {
            Some(exit_id) if !is_builtin_route(exit_id) => match exits.get(exit_id) {
                Some(exit) if routable(&exit.status) => Resolution::Proton {
                    exit_id: (*exit_id).to_owned(),
                    upstream: Upstream {
                        address: SocketAddrV4::new(PROTON_RESOLVER, DNS_PORT),
                        mark: Some(exit.mark),
                    },
                    fallback: (!kill_switch).then_some(home),
                },
                _ if kill_switch => Resolution::Blocked {
                    exit_id: (*exit_id).to_owned(),
                },
                _ => Resolution::Server(home),
            },
            _ => Resolution::Server(home),
        };
        for address in &device.addresses {
            if let IpAddr::V4(address) = address {
                plan.insert(*address, resolution.clone());
            }
        }
    }
    plan
}

/// The current per-client plan, replaced atomically after every reconcile.
pub struct Resolver {
    defaults: Defaults,
    plan: RwLock<Option<Arc<HashMap<Ipv4Addr, Resolution>>>>,
}

impl Resolver {
    pub fn new(defaults: Defaults) -> Self {
        Self {
            defaults,
            plan: RwLock::new(None),
        }
    }

    pub fn defaults(&self) -> Defaults {
        self.defaults
    }

    /// Back to answering SERVFAIL for everyone, e.g. while Tailscale is not running.
    pub fn clear(&self) {
        *self
            .plan
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
    }

    pub fn replace(&self, plan: HashMap<Ipv4Addr, Resolution>) {
        *self
            .plan
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Arc::new(plan));
    }

    /// Clients not in the published plan (new devices) use the default server.
    pub fn resolve(&self, client: Ipv4Addr) -> Resolution {
        let plan = self
            .plan
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(plan) = plan.as_ref() else {
            return Resolution::NotReady;
        };
        plan.get(&client)
            .cloned()
            .unwrap_or(Resolution::Server(Upstream::server(self.defaults.server)))
    }
}

/// Only tailnet peers (100.64.0.0/10) may use the forwarder.
pub fn is_tailnet(address: IpAddr) -> bool {
    matches!(address, IpAddr::V4(address) if address.octets()[0] == 100 && address.octets()[1] & 0xc0 == 64)
}

pub struct DnsServer {
    udp: Arc<UdpSocket>,
    tcp: TcpListener,
}

impl DnsServer {
    /// Binds UDP and TCP on the same port (port 0 picks one port for both).
    pub async fn bind(address: SocketAddr) -> Result<Self> {
        let udp = UdpSocket::bind(address)
            .await
            .context("bind DNS forwarder (UDP)")?;
        let port = udp.local_addr()?.port();
        let tcp = TcpListener::bind(SocketAddr::new(address.ip(), port))
            .await
            .context("bind DNS forwarder (TCP)")?;
        Ok(Self {
            udp: Arc::new(udp),
            tcp,
        })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.udp.local_addr()
    }

    pub async fn run(self, resolver: Arc<Resolver>, allow: fn(IpAddr) -> bool) {
        let limit = Arc::new(Semaphore::new(MAX_IN_FLIGHT));
        tokio::join!(
            serve_udp(self.udp, resolver.clone(), allow, limit.clone()),
            serve_tcp(self.tcp, resolver, allow, limit),
        );
    }
}

#[derive(Clone, Copy)]
enum Transport {
    Udp,
    Tcp,
}

async fn serve_udp(
    socket: Arc<UdpSocket>,
    resolver: Arc<Resolver>,
    allow: fn(IpAddr) -> bool,
    limit: Arc<Semaphore>,
) {
    loop {
        let mut buffer = vec![0_u8; MAX_UDP_MESSAGE];
        let (length, client) = match socket.recv_from(&mut buffer).await {
            Ok(received) => received,
            Err(error) => {
                warn!(%error, "DNS forwarder UDP receive failed");
                continue;
            }
        };
        if !allow(client.ip()) {
            continue;
        }
        // Shed load rather than queue unboundedly.
        let Ok(permit) = limit.clone().try_acquire_owned() else {
            continue;
        };
        buffer.truncate(length);
        let socket = socket.clone();
        let resolver = resolver.clone();
        tokio::spawn(async move {
            let _permit = permit;
            if let Some(response) = answer(&resolver, client.ip(), &buffer, Transport::Udp).await {
                let _ = socket.send_to(&response, client).await;
            }
        });
    }
}

async fn serve_tcp(
    listener: TcpListener,
    resolver: Arc<Resolver>,
    allow: fn(IpAddr) -> bool,
    limit: Arc<Semaphore>,
) {
    loop {
        let (stream, client) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(error) => {
                warn!(%error, "DNS forwarder TCP accept failed");
                continue;
            }
        };
        if !allow(client.ip()) {
            continue;
        }
        let Ok(permit) = limit.clone().try_acquire_owned() else {
            continue;
        };
        let resolver = resolver.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let _ = serve_tcp_client(stream, client.ip(), &resolver).await;
        });
    }
}

async fn serve_tcp_client(
    mut stream: TcpStream,
    client: IpAddr,
    resolver: &Resolver,
) -> Result<()> {
    loop {
        let Ok(length) = tokio::time::timeout(CLIENT_IDLE_TIMEOUT, stream.read_u16()).await else {
            return Ok(());
        };
        let mut query = vec![0_u8; usize::from(length?)];
        stream.read_exact(&mut query).await?;
        if let Some(response) = answer(resolver, client, &query, Transport::Tcp).await {
            let length = u16::try_from(response.len()).context("DNS response too large")?;
            stream.write_all(&length.to_be_bytes()).await?;
            stream.write_all(&response).await?;
        }
    }
}

async fn answer(
    resolver: &Resolver,
    client: IpAddr,
    query: &[u8],
    transport: Transport,
) -> Option<Vec<u8>> {
    let IpAddr::V4(client) = client else {
        return error_response(query, REFUSED);
    };
    match resolver.resolve(client) {
        Resolution::Server(upstream) => exchange(upstream, query, transport)
            .await
            .ok()
            .or_else(|| error_response(query, SERVFAIL)),
        Resolution::Blocked { .. } | Resolution::NotReady => error_response(query, SERVFAIL),
        Resolution::Proton {
            upstream, fallback, ..
        } => match exchange(upstream, query, transport).await {
            Ok(response) => Some(response),
            Err(_) => match fallback {
                Some(fallback) => exchange(fallback, query, transport).await.ok(),
                None => None,
            }
            .or_else(|| error_response(query, SERVFAIL)),
        },
    }
}

async fn exchange(upstream: Upstream, query: &[u8], transport: Transport) -> Result<Vec<u8>> {
    let exchange = async {
        match transport {
            Transport::Udp => exchange_udp(upstream, query).await,
            Transport::Tcp => exchange_tcp(upstream, query).await,
        }
    };
    tokio::time::timeout(UPSTREAM_TIMEOUT, exchange)
        .await
        .context("DNS upstream timed out")?
}

async fn exchange_udp(upstream: Upstream, query: &[u8]) -> Result<Vec<u8>> {
    let socket = UdpSocket::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))).await?;
    if let Some(mark) = upstream.mark {
        // The mark must be set before connect() so the route lookup uses the tunnel.
        SockRef::from(&socket).set_mark(mark)?;
    }
    socket.connect(SocketAddr::V4(upstream.address)).await?;
    socket.send(query).await?;
    let mut buffer = vec![0_u8; MAX_UDP_MESSAGE];
    loop {
        let length = socket.recv(&mut buffer).await?;
        // Ignore anything that is not the reply to this query.
        if length >= 2 && query.len() >= 2 && buffer[..2] == query[..2] {
            buffer.truncate(length);
            return Ok(buffer);
        }
    }
}

async fn exchange_tcp(upstream: Upstream, query: &[u8]) -> Result<Vec<u8>> {
    let socket = TcpSocket::new_v4()?;
    if let Some(mark) = upstream.mark {
        SockRef::from(&socket).set_mark(mark)?;
    }
    let mut stream = socket.connect(SocketAddr::V4(upstream.address)).await?;
    let length = u16::try_from(query.len()).context("DNS query too large")?;
    stream.write_all(&length.to_be_bytes()).await?;
    stream.write_all(query).await?;
    let mut response = vec![0_u8; usize::from(stream.read_u16().await?)];
    stream.read_exact(&mut response).await?;
    Ok(response)
}

/// A minimal error reply that echoes the query ID, opcode, RD bit, and question.
pub fn error_response(query: &[u8], rcode: u8) -> Option<Vec<u8>> {
    if query.len() < 12 {
        return None;
    }
    let questions = u16::from_be_bytes([query[4], query[5]]);
    let mut end = 12;
    if questions == 1 {
        loop {
            let label = usize::from(*query.get(end)?);
            end += 1;
            if label == 0 {
                break;
            }
            if label & 0xc0 != 0 {
                return None;
            }
            end += label;
        }
        end += 4;
        if end > query.len() {
            return None;
        }
    } else {
        end = 12;
    }
    let mut response = query[..end].to_vec();
    response[2] = 0x80 | (query[2] & 0x79);
    response[3] = 0x80 | (rcode & 0x0f);
    let questions = if end > 12 { 1_u16 } else { 0 };
    response[4..6].copy_from_slice(&questions.to_be_bytes());
    response[6..12].fill(0);
    Some(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{DIRECT_ROUTE_ID, ExitStatus, LOCAL_ROUTE_ID};

    const DEFAULTS: Defaults = Defaults {
        server: Ipv4Addr::new(9, 9, 9, 9),
        kill_switch: true,
    };

    fn device(node_id: &str, last_octet: u8) -> Device {
        Device {
            node_id: node_id.into(),
            display_name: String::new(),
            addresses: vec![IpAddr::V4(Ipv4Addr::new(100, 64, 0, last_octet))],
            online: true,
            active: true,
        }
    }

    fn assign(node_id: &str, exit_id: &str) -> Assignment {
        Assignment {
            node_id: node_id.into(),
            exit_id: exit_id.into(),
        }
    }

    fn exit(id: &str, mark: u32, status: ExitStatus) -> Exit {
        Exit {
            id: id.into(),
            mark,
            status,
            ..Exit::default()
        }
    }

    fn setting(node_id: &str, kill_switch: Option<bool>, server: Option<Ipv4Addr>) -> NodeDns {
        NodeDns {
            node_id: node_id.into(),
            kill_switch,
            server,
        }
    }

    fn address(last_octet: u8) -> Ipv4Addr {
        Ipv4Addr::new(100, 64, 0, last_octet)
    }

    /// A 12-byte header plus one question for "a." type A.
    fn query(id: u16) -> Vec<u8> {
        let mut query = id.to_be_bytes().to_vec();
        query.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 1]);
        query.extend_from_slice(&[1, b'a', 0, 0, 1, 0, 1]);
        // EDNS OPT record in the additional section.
        query.extend_from_slice(&[0, 0, 41, 0x10, 0, 0, 0, 0, 0, 0, 0]);
        query
    }

    #[test]
    fn plans_proton_blocked_and_server_resolution() {
        let devices = vec![
            device("vpn", 10),
            device("vpn-down", 11),
            device("vpn-down-no-kill", 12),
            device("direct", 13),
            device("local", 14),
            device("unassigned", 15),
            device("custom", 16),
        ];
        let assignments = vec![
            assign("vpn", "exit-nl"),
            assign("vpn-down", "exit-us"),
            assign("vpn-down-no-kill", "exit-us"),
            assign("direct", DIRECT_ROUTE_ID),
            assign("local", LOCAL_ROUTE_ID),
        ];
        let exits = vec![
            exit("exit-nl", 0x100, ExitStatus::Healthy),
            exit("exit-us", 0x200, ExitStatus::Failed),
        ];
        let router = Ipv4Addr::new(192, 168, 0, 1);
        let settings = vec![
            setting("vpn-down-no-kill", Some(false), Some(router)),
            setting("custom", None, Some(router)),
        ];
        let plan = plan(PlanInput {
            devices: &devices,
            assignments: &assignments,
            exits: &exits,
            settings: &settings,
            defaults: DEFAULTS,
        });
        assert_eq!(
            plan[&address(10)],
            Resolution::Proton {
                exit_id: "exit-nl".into(),
                upstream: Upstream {
                    address: SocketAddrV4::new(PROTON_RESOLVER, 53),
                    mark: Some(0x100)
                },
                fallback: None,
            }
        );
        assert_eq!(
            plan[&address(11)],
            Resolution::Blocked {
                exit_id: "exit-us".into()
            }
        );
        assert_eq!(
            plan[&address(12)],
            Resolution::Server(Upstream::server(router))
        );
        for last_octet in [13, 14, 15] {
            assert_eq!(
                plan[&address(last_octet)],
                Resolution::Server(Upstream::server(DEFAULTS.server))
            );
        }
        assert_eq!(
            plan[&address(16)],
            Resolution::Server(Upstream::server(router))
        );
    }

    #[test]
    fn kill_switch_off_adds_a_fallback_for_healthy_proton_exits() {
        let devices = vec![device("vpn", 10)];
        let assignments = vec![assign("vpn", "exit-nl")];
        let exits = vec![exit("exit-nl", 0x100, ExitStatus::Degraded)];
        let settings = vec![setting("vpn", Some(false), None)];
        let plan = plan(PlanInput {
            devices: &devices,
            assignments: &assignments,
            exits: &exits,
            settings: &settings,
            defaults: DEFAULTS,
        });
        let Resolution::Proton { fallback, .. } = &plan[&address(10)] else {
            panic!("expected Proton resolution");
        };
        assert_eq!(*fallback, Some(Upstream::server(DEFAULTS.server)));
    }

    #[test]
    fn unknown_clients_use_the_default_server() {
        let resolver = Resolver::new(DEFAULTS);
        assert_eq!(resolver.resolve(address(99)), Resolution::NotReady);
        resolver.replace(HashMap::new());
        assert_ne!(resolver.resolve(address(99)), Resolution::NotReady);
        resolver.clear();
        assert_eq!(resolver.resolve(address(99)), Resolution::NotReady);
        resolver.replace(HashMap::new());
        assert_eq!(
            resolver.resolve(address(99)),
            Resolution::Server(Upstream::server(DEFAULTS.server))
        );
    }

    #[test]
    fn accepts_only_tailnet_sources() {
        assert!(is_tailnet("100.64.0.1".parse().unwrap()));
        assert!(is_tailnet("100.127.255.254".parse().unwrap()));
        assert!(!is_tailnet("100.128.0.1".parse().unwrap()));
        assert!(!is_tailnet("192.168.0.10".parse().unwrap()));
        assert!(!is_tailnet("fd7a:115c:a1e0::1".parse().unwrap()));
    }

    #[test]
    fn error_response_echoes_id_and_question_only() {
        let query = query(0xbeef);
        let response = error_response(&query, SERVFAIL).unwrap();
        assert_eq!(&response[..2], &[0xbe, 0xef]);
        assert_eq!(response[2] & 0x80, 0x80, "QR bit");
        assert_eq!(response[2] & 0x01, 0x01, "RD bit kept");
        assert_eq!(response[3] & 0x0f, SERVFAIL);
        assert_eq!(&response[4..12], &[0, 1, 0, 0, 0, 0, 0, 0]);
        assert_eq!(response.len(), 12 + 7, "additional OPT record dropped");
        assert!(error_response(&[0; 5], SERVFAIL).is_none());
    }

    async fn fake_udp_upstream() -> SocketAddrV4 {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let SocketAddr::V4(address) = socket.local_addr().unwrap() else {
            unreachable!()
        };
        tokio::spawn(async move {
            let mut buffer = [0_u8; 512];
            loop {
                let (length, peer) = socket.recv_from(&mut buffer).await.unwrap();
                let mut reply = buffer[..length].to_vec();
                reply[2] |= 0x80;
                reply.extend_from_slice(b"upstream");
                socket.send_to(&reply, peer).await.unwrap();
            }
        });
        address
    }

    async fn fake_tcp_upstream() -> SocketAddrV4 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let SocketAddr::V4(address) = listener.local_addr().unwrap() else {
            unreachable!()
        };
        tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let length = stream.read_u16().await.unwrap();
                let mut query = vec![0; usize::from(length)];
                stream.read_exact(&mut query).await.unwrap();
                query[2] |= 0x80;
                query.extend_from_slice(b"tcp-upstream");
                stream
                    .write_all(&u16::try_from(query.len()).unwrap().to_be_bytes())
                    .await
                    .unwrap();
                stream.write_all(&query).await.unwrap();
            }
        });
        address
    }

    fn closed_port() -> SocketAddrV4 {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let SocketAddr::V4(address) = socket.local_addr().unwrap() else {
            unreachable!()
        };
        address
    }

    async fn start(plan: HashMap<Ipv4Addr, Resolution>, allow: fn(IpAddr) -> bool) -> SocketAddr {
        let resolver = Arc::new(Resolver::new(DEFAULTS));
        resolver.replace(plan);
        let server = DnsServer::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let address = server.local_addr().unwrap();
        tokio::spawn(server.run(resolver, allow));
        address
    }

    async fn ask_udp(server: SocketAddr, id: u16) -> Option<Vec<u8>> {
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.send_to(&query(id), server).await.unwrap();
        let mut buffer = [0_u8; 512];
        let length = tokio::time::timeout(Duration::from_secs(5), client.recv(&mut buffer))
            .await
            .ok()?
            .unwrap();
        Some(buffer[..length].to_vec())
    }

    fn loopback() -> Ipv4Addr {
        Ipv4Addr::LOCALHOST
    }

    #[tokio::test]
    async fn forwards_to_the_planned_upstream_over_udp() {
        let upstream = fake_udp_upstream().await;
        let plan = HashMap::from([(
            loopback(),
            Resolution::Server(Upstream {
                address: upstream,
                mark: None,
            }),
        )]);
        let server = start(plan, |_| true).await;
        let response = ask_udp(server, 0x1234).await.unwrap();
        assert_eq!(&response[..2], &[0x12, 0x34]);
        assert!(response.ends_with(b"upstream"));
    }

    #[tokio::test]
    async fn forwards_over_tcp() {
        let upstream = fake_tcp_upstream().await;
        let plan = HashMap::from([(
            loopback(),
            Resolution::Server(Upstream {
                address: upstream,
                mark: None,
            }),
        )]);
        let server = start(plan, |_| true).await;
        let mut stream = TcpStream::connect(server).await.unwrap();
        let query = query(0x4242);
        stream
            .write_all(&u16::try_from(query.len()).unwrap().to_be_bytes())
            .await
            .unwrap();
        stream.write_all(&query).await.unwrap();
        let mut response = vec![0; usize::from(stream.read_u16().await.unwrap())];
        stream.read_exact(&mut response).await.unwrap();
        assert!(response.ends_with(b"tcp-upstream"));
    }

    #[tokio::test]
    async fn answers_servfail_until_the_first_plan_is_published() {
        let resolver = Arc::new(Resolver::new(DEFAULTS));
        let server = DnsServer::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let address = server.local_addr().unwrap();
        tokio::spawn(server.run(resolver, |_| true));
        assert_eq!(ask_udp(address, 5).await.unwrap()[3] & 0x0f, SERVFAIL);
    }

    #[tokio::test]
    async fn kill_switch_answers_servfail_without_querying() {
        let plan = HashMap::from([(
            loopback(),
            Resolution::Blocked {
                exit_id: "exit-us".into(),
            },
        )]);
        let server = start(plan, |_| true).await;
        let response = ask_udp(server, 7).await.unwrap();
        assert_eq!(response[3] & 0x0f, SERVFAIL);
    }

    #[tokio::test]
    async fn failed_proton_resolver_uses_fallback_only_without_kill_switch() {
        let fallback = fake_udp_upstream().await;
        let dead_tunnel = Upstream {
            address: closed_port(),
            mark: None,
        };
        let with_fallback = start(
            HashMap::from([(
                loopback(),
                Resolution::Proton {
                    exit_id: "exit-nl".into(),
                    upstream: dead_tunnel,
                    fallback: Some(Upstream {
                        address: fallback,
                        mark: None,
                    }),
                },
            )]),
            |_| true,
        )
        .await;
        assert!(
            ask_udp(with_fallback, 1)
                .await
                .unwrap()
                .ends_with(b"upstream")
        );

        let without_fallback = start(
            HashMap::from([(
                loopback(),
                Resolution::Proton {
                    exit_id: "exit-nl".into(),
                    upstream: dead_tunnel,
                    fallback: None,
                },
            )]),
            |_| true,
        )
        .await;
        assert_eq!(
            ask_udp(without_fallback, 2).await.unwrap()[3] & 0x0f,
            SERVFAIL
        );
    }

    #[tokio::test]
    async fn ignores_clients_outside_the_allow_list() {
        let upstream = fake_udp_upstream().await;
        let plan = HashMap::from([(
            loopback(),
            Resolution::Server(Upstream {
                address: upstream,
                mark: None,
            }),
        )]);
        let server = start(plan, is_tailnet).await;
        assert!(ask_udp(server, 3).await.is_none());
    }
}
