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

use std::net::SocketAddr;
use std::time::Duration;

use async_stream::stream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{broadcast, mpsc, oneshot};
use tracing::debug;

use crate::{Result, Stream, TransportLayer};

use constants::{
    diagnostic_nack_reason, header_nack_reason, routing_activation_reason, ACK_OK, HEADER_LEN,
    MAX_PAYLOAD, ROUTING_ACTIVATION_SUCCESS,
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
        }
    }
}

/// One entity's answer to a vehicle identification request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VehicleAnnouncement {
    pub source: SocketAddr,
    pub vin: String,
    pub logical_address: u16,
    pub eid: [u8; 6],
    pub gid: [u8; 6],
    pub further_action: u8,
}

// ── Message framing ─────────────────────────────────────────────────────────

fn encode(payload_type: PayloadType, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_LEN + payload.len());
    out.push(PROTOCOL_VERSION);
    out.push(!PROTOCOL_VERSION);
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

fn parse_announcement(source: SocketAddr, payload: &[u8]) -> Option<VehicleAnnouncement> {
    if payload.len() < 32 {
        return None;
    }
    Some(VehicleAnnouncement {
        source,
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

/// Broadcast a vehicle identification request and collect answers until
/// `timeout` elapses. Entities are deduplicated by source IP.
pub async fn discover(timeout: Duration) -> Result<Vec<VehicleAnnouncement>> {
    let socket = UdpSocket::bind(("0.0.0.0", 0)).await.map_err(Error::from)?;
    socket.set_broadcast(true).map_err(Error::from)?;
    let request = encode(PayloadType::VehicleIdRequest, &[]);
    socket
        .send_to(&request, ("255.255.255.255", PORT))
        .await
        .map_err(Error::from)?;

    let mut found: Vec<VehicleAnnouncement> = Vec::new();
    let deadline = tokio::time::Instant::now() + timeout;
    let mut buf = [0u8; 1024];
    while let Ok(Ok((n, source))) =
        tokio::time::timeout_at(deadline, socket.recv_from(&mut buf)).await
    {
        let Ok((payload_type, payload)) = decode(&buf[..n]) else {
            continue;
        };
        if PayloadType::from_repr(payload_type) != Some(PayloadType::VehicleAnnouncement) {
            continue;
        }
        if let Some(a) = parse_announcement(source, payload) {
            if !found.iter().any(|f| f.source.ip() == a.source.ip()) {
                debug!("DoIP entity {} at {}", a.vin, a.source);
                found.push(a);
            }
        }
    }
    Ok(found)
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
        let connect = TcpStream::connect((config.host.as_str(), config.port));
        let stream = tokio::time::timeout(timeout, connect)
            .await
            .map_err(|_| crate::Error::Timeout)?
            .map_err(Error::from)?;
        stream.set_nodelay(true).map_err(Error::from)?;
        let (mut rd, mut wr) = stream.into_split();

        write_message(
            &mut wr,
            PayloadType::RoutingActivationRequest,
            &encode_routing_activation(&config),
        )
        .await?;
        let entity_address = match tokio::time::timeout(timeout, await_routing_activation(&mut rd))
            .await
        {
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
        let task = tokio::spawn(socket_task(rd, wr, config, cmd_rx, pdu_tx.clone(), shutdown_rx));

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
