//! Diagnostics over IP (DoIP), ISO 13400-2.
//!
//! A DoIP entity is reached over TCP 13400. After a routing activation the
//! socket carries UDS PDUs addressed to a logical ECU address, so
//! [`DoIpTransport`] implements [`TransportLayer`] and `UDSClient` drives an
//! Ethernet ECU unchanged. [`discover`] finds entities over UDP.

mod constants;
mod error;

pub use constants::{
    PayloadType, ACTIVATION_TYPE_DEFAULT, DEFAULT_TESTER_ADDRESS, PORT, PROTOCOL_VERSION,
};
pub use error::Error;

use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;

use async_stream::stream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{lookup_host, TcpSocket, TcpStream, UdpSocket};
use tokio::sync::{broadcast, mpsc, oneshot};
use tracing::debug;

use crate::{Result, Stream, TransportLayer};

use constants::{
    diagnostic_nack_reason, header_nack_reason, routing_activation_reason, ACK_OK, HEADER_LEN,
    MAX_PAYLOAD, ROUTING_ACTIVATION_SUCCESS, VEHICLE_ID_VERSION,
};

const DEFAULT_TIMEOUT_MS: u64 = 2000;
/// Depth of the inbound-PDU broadcast; a burst of responses must not lag it.
const PDU_CHANNEL_DEPTH: usize = 64;

/// Configuration for a [`DoIpTransport`].
#[derive(Debug, Clone)]
pub struct DoIpConfig {
    /// Entity host — usually the gateway's link-local address.
    pub host: String,
    pub port: u16,
    /// Our logical address (`CP_DoIPLogicalTesterAddress`).
    pub tester_address: u16,
    /// Logical address of the ECU to talk to (`CP_DoIPLogicalEcuAddress`).
    pub ecu_address: u16,
    pub activation_type: u8,
    /// Connect, routing-activation and acknowledgement timeout.
    pub timeout: Duration,
    /// Local address to connect from — [`VehicleAnnouncement::local`] of the
    /// entity this config addresses. `None` lets the routing table choose,
    /// which only works when one interface can reach `host`.
    pub local_address: Option<IpAddr>,
}

impl DoIpConfig {
    pub fn new(host: impl Into<String>, ecu_address: u16) -> Self {
        Self {
            host: host.into(),
            port: PORT,
            tester_address: DEFAULT_TESTER_ADDRESS,
            ecu_address,
            activation_type: ACTIVATION_TYPE_DEFAULT,
            timeout: Duration::from_millis(DEFAULT_TIMEOUT_MS),
            local_address: None,
        }
    }
}

/// One entity's answer to a vehicle identification request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VehicleAnnouncement {
    pub source: SocketAddr,
    /// Local interface address the answer arrived on. Carry it into
    /// [`DoIpConfig::local_address`]: on a multi-homed host it is the only
    /// record of which NIC the entity is actually reachable through.
    pub local: Option<IpAddr>,
    pub vin: String,
    pub logical_address: u16,
    pub eid: [u8; 6],
    pub gid: [u8; 6],
    pub further_action: u8,
}

// ── Message framing ─────────────────────────────────────────────────────────

/// Identification requests carry [`VEHICLE_ID_VERSION`], everything else
/// [`PROTOCOL_VERSION`].
fn request_version(payload_type: PayloadType) -> u8 {
    match payload_type {
        PayloadType::VehicleIdRequest
        | PayloadType::VehicleIdRequestEid
        | PayloadType::VehicleIdRequestVin => VEHICLE_ID_VERSION,
        _ => PROTOCOL_VERSION,
    }
}

fn encode(payload_type: PayloadType, payload: &[u8]) -> Vec<u8> {
    let version = request_version(payload_type);
    let mut out = Vec::with_capacity(HEADER_LEN + payload.len());
    out.push(version);
    out.push(!version);
    out.extend_from_slice(&(payload_type as u16).to_be_bytes());
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// Split a datagram into `(raw payload type, payload)`.
fn decode(buf: &[u8]) -> std::result::Result<(u16, &[u8]), Error> {
    if buf.len() < HEADER_LEN {
        return Err(Error::MalformedMessage);
    }
    let (version, inverse) = (buf[0], buf[1]);
    if version != !inverse {
        return Err(Error::BadVersion(version, inverse));
    }
    let payload_type = u16::from_be_bytes([buf[2], buf[3]]);
    let len = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]) as usize;
    let payload = buf
        .get(HEADER_LEN..HEADER_LEN + len)
        .ok_or(Error::MalformedMessage)?;
    Ok((payload_type, payload))
}

/// Read one whole message off a TCP stream.
async fn read_message(rd: &mut OwnedReadHalf) -> std::result::Result<(u16, Vec<u8>), Error> {
    let mut header = [0u8; HEADER_LEN];
    rd.read_exact(&mut header).await?;
    let (version, inverse) = (header[0], header[1]);
    if version != !inverse {
        return Err(Error::BadVersion(version, inverse));
    }
    let payload_type = u16::from_be_bytes([header[2], header[3]]);
    let len = u32::from_be_bytes([header[4], header[5], header[6], header[7]]) as usize;
    if len > MAX_PAYLOAD {
        return Err(Error::PayloadTooLarge(len, MAX_PAYLOAD));
    }
    let mut payload = vec![0u8; len];
    rd.read_exact(&mut payload).await?;
    Ok((payload_type, payload))
}

async fn write_message(
    wr: &mut OwnedWriteHalf,
    payload_type: PayloadType,
    payload: &[u8],
) -> std::result::Result<(), Error> {
    wr.write_all(&encode(payload_type, payload)).await?;
    Ok(())
}

fn encode_routing_activation(config: &DoIpConfig) -> Vec<u8> {
    let mut p = Vec::with_capacity(7);
    p.extend_from_slice(&config.tester_address.to_be_bytes());
    p.push(config.activation_type);
    p.extend_from_slice(&[0u8; 4]);
    p
}

/// Returns the entity's logical address on success.
fn parse_routing_activation(payload: &[u8]) -> std::result::Result<u16, Error> {
    if payload.len() < 5 {
        return Err(Error::MalformedMessage);
    }
    let entity = u16::from_be_bytes([payload[2], payload[3]]);
    let code = payload[4];
    if code != ROUTING_ACTIVATION_SUCCESS {
        return Err(Error::RoutingActivationRefused(
            code,
            routing_activation_reason(code),
        ));
    }
    Ok(entity)
}

fn parse_announcement(
    source: SocketAddr,
    local: Option<IpAddr>,
    payload: &[u8],
) -> Option<VehicleAnnouncement> {
    if payload.len() < 32 {
        return None;
    }
    Some(VehicleAnnouncement {
        source,
        local,
        vin: String::from_utf8_lossy(&payload[0..17])
            .trim_matches(|c: char| c == '\0' || c.is_whitespace())
            .to_string(),
        logical_address: u16::from_be_bytes([payload[17], payload[18]]),
        eid: payload[19..25].try_into().ok()?,
        gid: payload[25..31].try_into().ok()?,
        further_action: payload[31],
    })
}

// ── Discovery ───────────────────────────────────────────────────────────────

/// How often the identification request is repeated while waiting. A single
/// datagram is easy to lose: the entity may still be bringing its Ethernet
/// stack up, and nothing retransmits UDP. A reference tester repeats at 2 s.
const DISCOVERY_RETRY: Duration = Duration::from_millis(500);

/// Depth of the channel carrying announcements back from the per-interface
/// tasks; a bus full of entities answering at once must not block a receive.
const DISCOVERY_CHANNEL_DEPTH: usize = 32;

/// A local interface to search from: the address to bind, and where to send.
struct DiscoveryIface {
    bind: Ipv4Addr,
    destinations: Vec<SocketAddrV4>,
}

/// The all-ones host address of `ip`'s subnet.
fn directed_broadcast(ip: Ipv4Addr, netmask: Ipv4Addr) -> Ipv4Addr {
    Ipv4Addr::from(u32::from(ip) | !u32::from(netmask))
}

/// Every non-loopback IPv4 interface, each with its own directed broadcast.
///
/// Sending from one wildcard socket is what makes discovery come back empty on
/// a multi-homed host: the destination alone picks the interface, via the
/// routing table. `255.255.255.255` leaves by the default route — the Wi-Fi or
/// LAN NIC, never the diagnostic one, which is APIPA-only and has no default
/// route. `169.254.255.255` is no safer: a VPN adapter that installs its own
/// `169.254.0.0/16` route at a lower metric wins it outright, and the request
/// disappears into the tunnel. Binding a socket per interface takes the
/// decision away from the routing table, so the request leaves every NIC the
/// entity could be on.
fn discovery_interfaces() -> Vec<DiscoveryIface> {
    let ifaces = match if_addrs::get_if_addrs() {
        Ok(i) => i,
        Err(e) => {
            debug!("DoIP: cannot enumerate interfaces: {e}");
            return Vec::new();
        }
    };
    ifaces
        .into_iter()
        .filter(|i| !i.is_loopback())
        .filter_map(|i| match i.addr {
            if_addrs::IfAddr::V4(v4) => Some(v4),
            if_addrs::IfAddr::V6(_) => None,
        })
        .map(|v4| {
            let directed = v4
                .broadcast
                .unwrap_or_else(|| directed_broadcast(v4.ip, v4.netmask));
            let mut destinations = vec![SocketAddrV4::new(directed, PORT)];
            // Entities that only listen for the limited broadcast still answer,
            // and the source binding keeps it on this interface.
            if directed != Ipv4Addr::BROADCAST {
                destinations.push(SocketAddrV4::new(Ipv4Addr::BROADCAST, PORT));
            }
            DiscoveryIface {
                bind: v4.ip,
                destinations,
            }
        })
        .collect()
}

/// Repeat the request on one socket and forward every announcement it draws,
/// until `deadline`. `Err` means no send ever succeeded on this interface.
async fn discovery_task(
    socket: UdpSocket,
    local: Option<IpAddr>,
    destinations: Vec<SocketAddrV4>,
    request: Vec<u8>,
    deadline: tokio::time::Instant,
    tx: mpsc::Sender<VehicleAnnouncement>,
) -> std::result::Result<(), std::io::Error> {
    let mut buf = [0u8; 1024];
    let mut sent = false;
    let mut last_error = None;
    let mut next_send = tokio::time::Instant::now();

    loop {
        tokio::select! {
            _ = tokio::time::sleep_until(deadline) => break,
            _ = tokio::time::sleep_until(next_send) => {
                for addr in &destinations {
                    // An unreachable destination must not sink the others.
                    match socket.send_to(&request, *addr).await {
                        Ok(_) => sent = true,
                        Err(e) => {
                            debug!("DoIP request to {addr} failed: {e}");
                            last_error = Some(e);
                        }
                    }
                }
                next_send += DISCOVERY_RETRY;
            }
            received = socket.recv_from(&mut buf) => {
                let Ok((n, source)) = received else { break };
                let Ok((payload_type, payload)) = decode(&buf[..n]) else {
                    continue;
                };
                if PayloadType::from_repr(payload_type) != Some(PayloadType::VehicleAnnouncement) {
                    continue;
                }
                if let Some(a) = parse_announcement(source, local, payload) {
                    if tx.send(a).await.is_err() {
                        break;
                    }
                }
            }
        }
    }

    match last_error {
        Some(e) if !sent => Err(e),
        _ => Ok(()),
    }
}

/// Broadcast a vehicle identification request on every local interface and
/// collect answers until `timeout` elapses. Entities are deduplicated by
/// source IP, so the repeats and the two destinations yield one entry each.
pub async fn discover(timeout: Duration) -> Result<Vec<VehicleAnnouncement>> {
    let request = encode(PayloadType::VehicleIdRequest, &[]);
    let deadline = tokio::time::Instant::now() + timeout;

    let mut ifaces = discovery_interfaces();
    if ifaces.is_empty() {
        // Enumeration failed; fall back to letting the routing table choose.
        ifaces.push(DiscoveryIface {
            bind: Ipv4Addr::UNSPECIFIED,
            destinations: vec![SocketAddrV4::new(Ipv4Addr::BROADCAST, PORT)],
        });
    }

    let (tx, mut rx) = mpsc::channel(DISCOVERY_CHANNEL_DEPTH);
    let mut tasks = Vec::new();
    let mut bind_error = None;
    for iface in ifaces {
        let socket = match UdpSocket::bind((iface.bind, 0)).await {
            Ok(s) => s,
            Err(e) => {
                debug!("DoIP: cannot bind {}: {e}", iface.bind);
                bind_error = Some(e);
                continue;
            }
        };
        if let Err(e) = socket.set_broadcast(true) {
            debug!("DoIP: cannot broadcast from {}: {e}", iface.bind);
            bind_error = Some(e);
            continue;
        }
        // An unspecified bind is the fallback: there is no NIC to record.
        let local = (!iface.bind.is_unspecified()).then_some(IpAddr::V4(iface.bind));
        tasks.push(tokio::spawn(discovery_task(
            socket,
            local,
            iface.destinations,
            request.clone(),
            deadline,
            tx.clone(),
        )));
    }
    // The receive loop below ends when the last task drops its sender.
    drop(tx);
    if tasks.is_empty() {
        return Err(Error::from(bind_error.expect("no socket means a bind failed")).into());
    }

    let mut found: Vec<VehicleAnnouncement> = Vec::new();
    while let Some(a) = rx.recv().await {
        if !found.iter().any(|f| f.source.ip() == a.source.ip()) {
            debug!("DoIP entity {} at {}", a.vin, a.source);
            found.push(a);
        }
    }

    let mut send_error = None;
    for task in tasks {
        if let Ok(Err(e)) = task.await {
            send_error = Some(e);
        }
    }
    // Every interface failing to send is the old single-socket error case.
    match send_error {
        Some(e) if found.is_empty() => Err(Error::from(e).into()),
        _ => Ok(found),
    }
}

// ── Transport ───────────────────────────────────────────────────────────────

enum Cmd {
    Send(Vec<u8>, oneshot::Sender<Result<()>>),
}

/// A live DoIP connection. A background task owns the socket;
/// [`TransportLayer::send`]/`recv` exchange whole UDS PDUs.
pub struct DoIpTransport {
    cmd_tx: mpsc::Sender<Cmd>,
    pdu_tx: broadcast::Sender<Vec<u8>>,
    shutdown: Option<oneshot::Sender<()>>,
    task: Option<tokio::task::JoinHandle<()>>,
    timeout: Duration,
    entity_address: u16,
}

impl DoIpTransport {
    /// Connect, activate routing, then spawn the socket task.
    pub async fn open(config: DoIpConfig) -> Result<Self> {
        let timeout = config.timeout;
        let stream = tokio::time::timeout(timeout, connect(&config))
            .await
            .map_err(|_| crate::Error::Timeout)??;
        stream.set_nodelay(true).map_err(Error::from)?;
        let (mut rd, mut wr) = stream.into_split();

        write_message(
            &mut wr,
            PayloadType::RoutingActivationRequest,
            &encode_routing_activation(&config),
        )
        .await?;
        let entity_address =
            match tokio::time::timeout(timeout, await_routing_activation(&mut rd)).await {
                Ok(r) => r?,
                Err(_) => return Err(crate::Error::Timeout),
            };
        debug!(
            "DoIP routing activated: entity 0x{:04x}, ECU 0x{:04x}",
            entity_address, config.ecu_address
        );

        let (cmd_tx, cmd_rx) = mpsc::channel(8);
        let (pdu_tx, _) = broadcast::channel(PDU_CHANNEL_DEPTH);
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let task = tokio::spawn(socket_task(
            rd,
            wr,
            config,
            cmd_rx,
            pdu_tx.clone(),
            shutdown_rx,
        ));

        Ok(Self {
            cmd_tx,
            pdu_tx,
            shutdown: Some(shutdown_tx),
            task: Some(task),
            timeout,
            entity_address,
        })
    }

    /// Logical address the entity reported during routing activation.
    pub fn entity_address(&self) -> u16 {
        self.entity_address
    }

    /// Close the socket and wait for the background task to release it.
    pub async fn shutdown(mut self) {
        if let Some(s) = self.shutdown.take() {
            let _ = s.send(());
        }
        if let Some(t) = self.task.take() {
            let _ = t.await;
        }
    }
}

/// Open the TCP socket, from [`DoIpConfig::local_address`] when one is set.
///
/// The source binding matters for the same reason discovery binds per
/// interface: several NICs can carry a route to a link-local entity, and the
/// one the routing table prefers is not necessarily the one that answered.
async fn connect(config: &DoIpConfig) -> std::result::Result<TcpStream, Error> {
    let Some(local) = config.local_address else {
        return Ok(TcpStream::connect((config.host.as_str(), config.port)).await?);
    };
    let mut last_error = None;
    for addr in lookup_host((config.host.as_str(), config.port)).await? {
        if addr.is_ipv4() != local.is_ipv4() {
            continue;
        }
        let socket = if local.is_ipv4() {
            TcpSocket::new_v4()?
        } else {
            TcpSocket::new_v6()?
        };
        socket.bind(SocketAddr::new(local, 0))?;
        match socket.connect(addr).await {
            Ok(s) => return Ok(s),
            Err(e) => {
                debug!("DoIP connect to {addr} from {local} failed: {e}");
                last_error = Some(e);
            }
        }
    }
    Err(last_error
        .unwrap_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::AddrNotAvailable,
                format!("no address of {} matches local {local}", config.host),
            )
        })
        .into())
}

impl Drop for DoIpTransport {
    fn drop(&mut self) {
        if let Some(s) = self.shutdown.take() {
            let _ = s.send(());
        }
    }
}

impl TransportLayer for DoIpTransport {
    fn send<'a>(&'a self, data: &'a [u8]) -> impl std::future::Future<Output = Result<()>> + 'a {
        let pdu = data.to_vec();
        async move {
            let (done_tx, done_rx) = oneshot::channel();
            self.cmd_tx
                .send(Cmd::Send(pdu, done_tx))
                .await
                .map_err(|_| crate::Error::Disconnected)?;
            done_rx.await.map_err(|_| crate::Error::Disconnected)?
        }
    }

    fn recv(&self) -> impl Stream<Item = Result<Vec<u8>>> + Unpin + '_ {
        let mut rx = self.pdu_tx.subscribe();
        let timeout = self.timeout;
        Box::pin(stream! {
            loop {
                match tokio::time::timeout(timeout, rx.recv()).await {
                    Err(_) => yield Err(crate::Error::Timeout),
                    Ok(Ok(pdu)) => yield Ok(pdu),
                    Ok(Err(broadcast::error::RecvError::Closed)) => {
                        yield Err(crate::Error::Disconnected);
                        return;
                    }
                    Ok(Err(broadcast::error::RecvError::Lagged(n))) => {
                        tracing::warn!("Receive too slow, dropping {} PDU(s).", n)
                    }
                }
            }
        })
    }
}

/// Consume messages until the routing activation response arrives.
async fn await_routing_activation(rd: &mut OwnedReadHalf) -> std::result::Result<u16, Error> {
    loop {
        let (payload_type, payload) = read_message(rd).await?;
        match PayloadType::from_repr(payload_type) {
            Some(PayloadType::RoutingActivationResponse) => {
                return parse_routing_activation(&payload)
            }
            Some(PayloadType::GenericNack) => {
                let code = payload.first().copied().unwrap_or(0xff);
                return Err(Error::HeaderNack(code, header_nack_reason(code)));
            }
            _ => debug!("DoIP: ignoring 0x{payload_type:04x} before routing activation"),
        }
    }
}

/// Sleeps until `at`, or forever when nothing is pending.
async fn until(at: Option<tokio::time::Instant>) {
    match at {
        Some(t) => tokio::time::sleep_until(t).await,
        None => std::future::pending().await,
    }
}

/// Reads whole messages off the socket and forwards them one at a time.
///
/// A dedicated task because `read_exact` is **not** cancellation-safe: polled
/// as a `select!` branch it would be dropped mid-header whenever a send or an
/// ACK timeout won the race, losing the bytes it had already consumed and
/// desynchronising the stream. An `mpsc::Receiver` is cancellation-safe, so
/// only this task ever holds a partial read.
async fn reader_task(
    mut rd: OwnedReadHalf,
    tx: mpsc::Sender<std::result::Result<(u16, Vec<u8>), Error>>,
) {
    loop {
        let message = read_message(&mut rd).await;
        let fatal = message.is_err();
        if tx.send(message).await.is_err() || fatal {
            return;
        }
    }
}

/// Owns the socket for the connection's lifetime. A send stays outstanding
/// until its `0x8002` acknowledgement arrives, so only one runs at a time.
async fn socket_task(
    rd: OwnedReadHalf,
    wr: OwnedWriteHalf,
    config: DoIpConfig,
    cmd_rx: mpsc::Receiver<Cmd>,
    pdu_tx: broadcast::Sender<Vec<u8>>,
    shutdown: oneshot::Receiver<()>,
) {
    let (msg_tx, msg_rx) = mpsc::channel(PDU_CHANNEL_DEPTH);
    let reader = tokio::spawn(reader_task(rd, msg_tx));
    dispatch(wr, config, cmd_rx, msg_rx, pdu_tx, shutdown).await;
    reader.abort();
}

async fn dispatch(
    mut wr: OwnedWriteHalf,
    config: DoIpConfig,
    mut cmd_rx: mpsc::Receiver<Cmd>,
    mut msg_rx: mpsc::Receiver<std::result::Result<(u16, Vec<u8>), Error>>,
    pdu_tx: broadcast::Sender<Vec<u8>>,
    mut shutdown: oneshot::Receiver<()>,
) {
    let mut pending: Option<(oneshot::Sender<Result<()>>, tokio::time::Instant)> = None;

    loop {
        let ack_deadline = pending.as_ref().map(|(_, t)| *t);
        tokio::select! {
            _ = &mut shutdown => return,
            cmd = cmd_rx.recv(), if pending.is_none() => match cmd {
                None => return,
                Some(Cmd::Send(pdu, done)) => {
                    let mut payload = Vec::with_capacity(4 + pdu.len());
                    payload.extend_from_slice(&config.tester_address.to_be_bytes());
                    payload.extend_from_slice(&config.ecu_address.to_be_bytes());
                    payload.extend_from_slice(&pdu);
                    debug!("TX {}", hex::encode(&pdu));
                    match write_message(&mut wr, PayloadType::DiagnosticMessage, &payload).await {
                        Err(e) => { let _ = done.send(Err(e.into())); }
                        Ok(()) => {
                            pending = Some((done, tokio::time::Instant::now() + config.timeout));
                        }
                    }
                }
            },
            _ = until(ack_deadline) => {
                if let Some((done, _)) = pending.take() {
                    let _ = done.send(Err(crate::Error::Timeout));
                }
            }
            msg = msg_rx.recv() => {
                let (payload_type, payload) = match msg {
                    Some(Ok(m)) => m,
                    None => return,
                    Some(Err(e)) => {
                        if let Some((done, _)) = pending.take() {
                            let _ = done.send(Err(e.clone().into()));
                        }
                        debug!("DoIP socket closed: {e}");
                        return;
                    }
                };
                match PayloadType::from_repr(payload_type) {
                    Some(PayloadType::DiagnosticMessage) => {
                        // An answer proves the request landed, so it settles a
                        // still-pending send: entities that skip the mandated
                        // 0x8002 would otherwise stall every send until timeout.
                        if let Some((done, _)) = pending.take() {
                            let _ = done.send(Ok(()));
                        }
                        if payload.len() > 4 {
                            debug!("RX {}", hex::encode(&payload[4..]));
                            let _ = pdu_tx.send(payload[4..].to_vec());
                        }
                    }
                    Some(PayloadType::DiagnosticAck) => {
                        let code = payload.get(4).copied().unwrap_or(ACK_OK);
                        if let Some((done, _)) = pending.take() {
                            let _ = done.send(if code == ACK_OK {
                                Ok(())
                            } else {
                                Err(Error::MessageNack(code, diagnostic_nack_reason(code)).into())
                            });
                        }
                    }
                    Some(PayloadType::DiagnosticNack) => {
                        let code = payload.get(4).copied().unwrap_or(0xff);
                        if let Some((done, _)) = pending.take() {
                            let _ = done.send(Err(
                                Error::MessageNack(code, diagnostic_nack_reason(code)).into()
                            ));
                        }
                    }
                    Some(PayloadType::AliveCheckRequest) => {
                        let reply = config.tester_address.to_be_bytes();
                        if write_message(&mut wr, PayloadType::AliveCheckResponse, &reply)
                            .await
                            .is_err()
                        {
                            return;
                        }
                    }
                    Some(PayloadType::GenericNack) => {
                        let code = payload.first().copied().unwrap_or(0xff);
                        if let Some((done, _)) = pending.take() {
                            let _ = done.send(Err(
                                Error::HeaderNack(code, header_nack_reason(code)).into()
                            ));
                        }
                    }
                    _ => debug!("DoIP: ignoring payload type 0x{payload_type:04x}"),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests;
