//! Volkswagen Transport Protocol 2.0 (TP 2.0).
//!
//! VAG's CAN transport for KWP2000/UDS diagnostics on pre-/early-UDS vehicles.
//! A broadcast setup exchange negotiates a dynamic point-to-point channel; the
//! channel then carries arbitrary-length application PDUs with its own
//! sequencing, block-windowed flow control, and a periodic channel test that
//! keeps it open. [`Tp20Transport`] implements [`TransportLayer`], so
//! `UDSClient` drives a TP2.0 ECU unchanged — VW's "KWP2000 on CAN (TP2.0)" is
//! the UDS-compatible service set over this transport.
//!
//! A message's payload is `[len_hi, len_lo, pdu…]` split into 7-byte chunks,
//! one per data frame. See [`constants`] for the frame opcodes.

mod constants;
mod error;

pub use constants::{ChannelType, FrameType, OPCODE_MASK, SEQUENCE_MASK};
pub use error::Error;

use async_stream::stream;
use tokio::sync::{broadcast, mpsc, oneshot};
use tracing::debug;

use crate::can::{AsyncCanAdapter, Frame, Identifier};
use crate::{Result, Stream, StreamExt, Timeout, TransportLayer};

/// Channel-setup request id (tester → ECU) for the standard VAG powertrain CAN.
const DEFAULT_SETUP_ID: u32 = 0x200;
/// CAN id we request the ECU transmit from (MCD `PhysRespIdCon`).
const DEFAULT_ECU_TX_ID: u32 = 0x300;
/// Interval between channel-test keepalives.
const KEEPALIVE_MS: u64 = 500;
/// Per-frame response / ACK timeout.
const DEFAULT_TIMEOUT_MS: u64 = 2000;
/// Maximum application PDU bytes per data frame (after the 1-byte header).
const FRAME_DATA_LEN: usize = 7;

/// Standard VAG logical (destination) addresses.
pub mod address {
    pub const ENGINE: u8 = 0x01;
    pub const TRANSMISSION: u8 = 0x02;
    pub const ABS_BRAKES: u8 = 0x03;
    pub const AIRBAG: u8 = 0x15;
    pub const STEERING: u8 = 0x16;
    pub const INSTRUMENTS: u8 = 0x17;
    pub const CENTRAL_ELECTRICS: u8 = 0x09;
    pub const CENTRAL_CONVENIENCE: u8 = 0x46;
    pub const GATEWAY: u8 = 0x19;
}

/// Configuration passed to the [`Tp20Transport`].
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Tp20Config {
    pub bus: u8,
    /// Channel-setup request id (tester → ECU). Standard VAG powertrain: `0x200`.
    pub setup_id: u32,
    /// ECU logical address; the setup response arrives on `setup_id + dest`.
    pub dest: u8,
    /// Application type — `0x01` = KWP2000/diagnostics.
    pub app_type: u8,
    /// CAN id we request the ECU transmit from. `0` lets the ECU assign it.
    pub ecu_tx_id: u32,
    /// Per-frame response / ACK timeout.
    pub timeout: std::time::Duration,
}

impl Tp20Config {
    /// Standard VAG powertrain-CAN config for an ECU at logical address `dest`.
    pub fn new(dest: u8) -> Self {
        Self {
            bus: 0,
            setup_id: DEFAULT_SETUP_ID,
            dest,
            app_type: 0x01,
            ecu_tx_id: DEFAULT_ECU_TX_ID,
            timeout: std::time::Duration::from_millis(DEFAULT_TIMEOUT_MS),
        }
    }
}

/// Decode a TP2.0 timing byte to a duration: bits 7-6 select the base
/// (0.1/1/10/100 ms), bits 5-0 are the multiplier.
fn decode_timing(b: u8) -> std::time::Duration {
    let mult = u64::from(b & 0x3f);
    let base_ns = match b >> 6 {
        0 => 100_000,
        1 => 1_000_000,
        2 => 10_000_000,
        _ => 100_000_000,
    };
    std::time::Duration::from_nanos(mult * base_ns)
}

/// Build the setup request: `[dest, C0, RX(ECU-listens)=invalid,
/// TX(ECU-transmits)=ecu_tx_id, app]`. The RX field is left invalid so the ECU
/// assigns the id we transmit on.
fn encode_setup_request(c: &Tp20Config) -> [u8; 7] {
    [
        c.dest,
        ChannelType::SetupRequest as u8,
        0x00,
        0x10,
        (c.ecu_tx_id & 0xff) as u8,
        ((c.ecu_tx_id >> 8) & 0x0f) as u8,
        c.app_type,
    ]
}

/// Parse a `0xD0` setup response into `(tester_tx_id, tester_rx_id)`.
///
/// Frame: `[dest, D0, rx_lo, rx_pre|valid, tx_lo, tx_pre|valid, app]`. The RX
/// field is the id the ECU listens on (= our TX); the TX field is the id the
/// ECU transmits from (= our RX). A non-zero high nibble of a prefix byte marks
/// the id invalid. Each id is `(prefix & 0x0f) << 8 | id_byte`.
fn parse_setup_response(data: &[u8]) -> std::result::Result<(u32, u32), Error> {
    if data.len() < 6 {
        return Err(Error::MalformedFrame);
    }
    if data[1] != ChannelType::SetupResponse as u8 {
        return Err(Error::SetupRejected(data[1]));
    }
    if data[3] >> 4 != 0 || data[5] >> 4 != 0 {
        return Err(Error::InvalidChannelId);
    }
    let tester_tx = (u32::from(data[3] & 0x0f) << 8) | u32::from(data[2]);
    let tester_rx = (u32::from(data[5] & 0x0f) << 8) | u32::from(data[4]);
    Ok((tester_tx, tester_rx))
}

/// One outgoing data frame and whether the sender must await an ACK after it.
struct OutFrame {
    bytes: Vec<u8>,
    await_ack: bool,
}

/// Segment an application PDU into TP2.0 data frames: prefix the 2-byte length,
/// chunk into 7 payload bytes per frame, assign sequence numbers, and mark
/// block-boundary and final frames as awaiting an ACK. Returns the frames and
/// the next sequence number to use.
fn segment(pdu: &[u8], block_size: u8, start_seq: u8) -> (Vec<OutFrame>, u8) {
    let mut payload = Vec::with_capacity(pdu.len() + 2);
    payload.extend_from_slice(&(pdu.len() as u16).to_be_bytes());
    payload.extend_from_slice(pdu);

    let chunks: Vec<&[u8]> = payload.chunks(FRAME_DATA_LEN).collect();
    let last = chunks.len() - 1;
    let mut seq = start_seq & SEQUENCE_MASK;
    let mut since_ack: u8 = 0;
    let mut frames = Vec::with_capacity(chunks.len());
    for (i, chunk) in chunks.iter().enumerate() {
        let is_last = i == last;
        // `since_ack` only advances when windowing is active, so it can never
        // exceed `block_size` (and never overflows when `block_size == 0`).
        let at_boundary = block_size != 0 && {
            since_ack += 1;
            since_ack >= block_size
        };
        let await_ack = is_last || at_boundary;
        let frame_type = if is_last {
            FrameType::DataAckLast
        } else if await_ack {
            FrameType::DataAckMore
        } else {
            FrameType::DataMore
        };
        let mut bytes = Vec::with_capacity(1 + chunk.len());
        bytes.push(frame_type as u8 | seq);
        bytes.extend_from_slice(chunk);
        frames.push(OutFrame { bytes, await_ack });
        seq = (seq + 1) & SEQUENCE_MASK;
        if await_ack {
            since_ack = 0;
        }
    }
    (frames, seq)
}

/// Outcome of feeding one received frame to a [`Reassembler`].
struct RxOutcome {
    /// Send an `ACK ready` echoing this next-expected sequence, if `Some`.
    ack_seq: Option<u8>,
    /// A fully reassembled application PDU, if this frame completed one.
    pdu: Option<Vec<u8>>,
}

/// Reassembles inbound TP2.0 data frames into application PDUs. Length-driven:
/// the message's first two payload bytes are its total length.
#[derive(Default)]
struct Reassembler {
    buf: Vec<u8>,
    expected: Option<usize>,
}

impl Reassembler {
    fn push(&mut self, frame: &[u8]) -> RxOutcome {
        let mut out = RxOutcome { ack_seq: None, pdu: None };
        let Some(&b0) = frame.first() else { return out };
        let frame_type = match FrameType::from_repr(b0 & OPCODE_MASK) {
            Some(ft) => ft,
            None => return out, // channel-management frame — not our concern here
        };
        let seq = b0 & SEQUENCE_MASK;
        match frame_type {
            FrameType::DataAckMore | FrameType::DataAckLast => {
                self.buf.extend_from_slice(&frame[1..]);
                out.ack_seq = Some((seq + 1) & SEQUENCE_MASK);
            }
            FrameType::DataMore | FrameType::DataLast => self.buf.extend_from_slice(&frame[1..]),
            FrameType::AckWait | FrameType::AckReady => return out,
        }
        if self.expected.is_none() && self.buf.len() >= 2 {
            self.expected = Some(usize::from(u16::from_be_bytes([self.buf[0], self.buf[1]])));
        }
        if let Some(len) = self.expected {
            if self.buf.len() >= 2 + len {
                out.pdu = Some(self.buf[2..2 + len].to_vec());
                self.buf.clear();
                self.expected = None;
            }
        }
        out
    }
}

enum Cmd {
    Send(Vec<u8>, oneshot::Sender<Result<()>>),
}

/// A live VW TP2.0 channel. A background task owns the CAN adapter and runs the
/// channel state machine; [`TransportLayer::send`]/`recv` exchange whole PDUs.
pub struct Tp20Transport {
    cmd_tx: mpsc::Sender<Cmd>,
    pdu_tx: broadcast::Sender<Vec<u8>>,
    shutdown: Option<oneshot::Sender<()>>,
    _task: tokio::task::JoinHandle<()>,
    timeout: std::time::Duration,
}

impl Tp20Transport {
    /// Open a channel: run setup + parameter negotiation, then spawn the
    /// channel task. Consumes the adapter, which the task owns for the
    /// channel's lifetime.
    pub async fn open(adapter: AsyncCanAdapter, config: Tp20Config) -> Result<Self> {
        let (cmd_tx, cmd_rx) = mpsc::channel(8);
        let (pdu_tx, _) = broadcast::channel(64);
        let (ready_tx, ready_rx) = oneshot::channel();
        let (shutdown_tx, shutdown_rx) = oneshot::channel();

        let task = tokio::spawn(channel_task(
            adapter,
            config,
            ready_tx,
            cmd_rx,
            pdu_tx.clone(),
            shutdown_rx,
        ));

        match ready_rx.await {
            Ok(Ok(())) => Ok(Self {
                cmd_tx,
                pdu_tx,
                shutdown: Some(shutdown_tx),
                _task: task,
                timeout: config.timeout,
            }),
            Ok(Err(e)) => Err(e),
            Err(_) => Err(crate::Error::Disconnected),
        }
    }
}

impl Drop for Tp20Transport {
    fn drop(&mut self) {
        // Signal the task to send a disconnect and release the adapter. The
        // task is detached (not aborted) so the `0xA8` actually goes out.
        if let Some(s) = self.shutdown.take() {
            let _ = s.send(());
        }
    }
}

impl TransportLayer for Tp20Transport {
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

async fn send_raw(adapter: &AsyncCanAdapter, bus: u8, id: u32, data: &[u8]) {
    match Frame::new(bus, Identifier::from(id), data) {
        Ok(frame) => adapter.send(&frame).await,
        Err(e) => tracing::error!("Failed to build TP2.0 frame: {:?}", e),
    }
}

/// Setup + params handshake, then the channel loop. Reports readiness on
/// `ready`; on handshake failure it reports the error and returns.
async fn channel_task(
    adapter: AsyncCanAdapter,
    config: Tp20Config,
    ready: oneshot::Sender<Result<()>>,
    mut cmd_rx: mpsc::Receiver<Cmd>,
    pdu_tx: broadcast::Sender<Vec<u8>>,
    mut shutdown: oneshot::Receiver<()>,
) {
    let (tx_id, rx_id, block_size, t3) = match handshake(&adapter, &config).await {
        Ok(v) => v,
        Err(e) => {
            let _ = ready.send(Err(e));
            return;
        }
    };
    let _ = ready.send(Ok(()));

    let data_rx = adapter.recv_filter(move |frame| u32::from(frame.id) == rx_id && !frame.loopback);
    tokio::pin!(data_rx);

    let mut tx_seq: u8 = 0;
    let mut reasm = Reassembler::default();

    let mut keepalive = tokio::time::interval(std::time::Duration::from_millis(KEEPALIVE_MS));
    keepalive.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            _ = &mut shutdown => {
                send_raw(&adapter, config.bus, tx_id, &[ChannelType::Disconnect as u8]).await;
                return;
            }
            cmd = cmd_rx.recv() => match cmd {
                None => {
                    send_raw(&adapter, config.bus, tx_id, &[ChannelType::Disconnect as u8]).await;
                    return;
                }
                Some(Cmd::Send(pdu, done)) => {
                    let r = transmit(&adapter, &config, tx_id, rx_id, block_size, t3, &mut tx_seq, &pdu).await;
                    let _ = done.send(r);
                }
            },
            frame = data_rx.next() => {
                let Some(frame) = frame else { return };
                let outcome = reasm.push(&frame.data);
                if let Some(ack_seq) = outcome.ack_seq {
                    send_raw(&adapter, config.bus, tx_id, &[FrameType::AckReady as u8 | ack_seq]).await;
                }
                if let Some(pdu) = outcome.pdu {
                    debug!("RX {}", hex::encode(&pdu));
                    let _ = pdu_tx.send(pdu);
                }
            }
            _ = keepalive.tick() => {
                send_raw(&adapter, config.bus, tx_id, &[ChannelType::ChannelTest as u8]).await;
            }
        }
    }
}

/// Returns `(tester_tx_id, tester_rx_id, block_size, interframe_delay)`.
async fn handshake(
    adapter: &AsyncCanAdapter,
    config: &Tp20Config,
) -> Result<(u32, u32, u8, std::time::Duration)> {
    // Subscribe before sending so the response can't be missed.
    let setup_resp_id = config.setup_id + u32::from(config.dest);
    let setup = adapter
        .recv_filter(move |frame| u32::from(frame.id) == setup_resp_id && !frame.loopback)
        .timeout(config.timeout);
    tokio::pin!(setup);

    send_raw(adapter, config.bus, config.setup_id, &encode_setup_request(config)).await;
    let resp = setup.next().await.unwrap()?;
    let (tx_id, rx_id) = parse_setup_response(&resp.data)?;
    debug!("channel set up, tx {:03x} rx {:03x}", tx_id, rx_id);

    // Parameter negotiation runs on the negotiated ids. We request BS 15 / T1
    // 100 ms / T3 5 ms; the ECU's response governs how fast we may send to it.
    let params = adapter
        .recv_filter(move |frame| u32::from(frame.id) == rx_id && !frame.loopback)
        .timeout(config.timeout);
    tokio::pin!(params);
    send_raw(adapter, config.bus, tx_id, &[ChannelType::ParamsRequest as u8, 0x0f, 0x8a, 0xff, 0x32, 0xff]).await;

    let resp = loop {
        let frame = params.next().await.unwrap()?;
        if frame.data.first() == Some(&(ChannelType::ParamsResponse as u8)) {
            break frame;
        }
    };
    if resp.data.len() < 6 {
        return Err(Error::MalformedFrame.into());
    }
    let block_size = resp.data[1];
    let t3 = decode_timing(resp.data[4]);
    debug!("params negotiated, block_size {} t3 {:?}", block_size, t3);
    Ok((tx_id, rx_id, block_size, t3))
}

/// Transmit one application PDU, honouring block-size flow control: await an
/// `ACK ready` after every block-boundary frame and the final frame.
#[allow(clippy::too_many_arguments)]
async fn transmit(
    adapter: &AsyncCanAdapter,
    config: &Tp20Config,
    tx_id: u32,
    rx_id: u32,
    block_size: u8,
    t3: std::time::Duration,
    tx_seq: &mut u8,
    pdu: &[u8],
) -> Result<()> {
    debug!("TX {}", hex::encode(pdu));

    // Own ACK subscription so block ACKs are read even while the channel loop
    // is parked in this call.
    let acks = adapter
        .recv_filter(move |frame| {
            u32::from(frame.id) == rx_id
                && !frame.loopback
                && matches!(
                    frame.data.first().map(|b| FrameType::from_repr(b & OPCODE_MASK)),
                    Some(Some(FrameType::AckReady | FrameType::AckWait))
                )
        })
        .timeout(config.timeout);
    tokio::pin!(acks);

    let (frames, next_seq) = segment(pdu, block_size, *tx_seq);
    for frame in &frames {
        send_raw(adapter, config.bus, tx_id, &frame.bytes).await;
        if frame.await_ack {
            let expected = (frame.bytes[0] + 1) & SEQUENCE_MASK;
            receive_ack(&mut acks, expected).await?;
        } else if !t3.is_zero() {
            tokio::time::sleep(t3).await;
        }
    }
    *tx_seq = next_seq;
    Ok(())
}

/// Await an `ACK ready` carrying `expected_seq`; a `Wait` ACK keeps listening.
async fn receive_ack(
    stream: &mut std::pin::Pin<&mut Timeout<impl Stream<Item = Frame>>>,
    expected_seq: u8,
) -> Result<()> {
    loop {
        let frame = stream.next().await.unwrap()?;
        let Some(&b0) = frame.data.first() else { continue };
        match FrameType::from_repr(b0 & OPCODE_MASK) {
            Some(FrameType::AckWait) => continue,
            Some(FrameType::AckReady) => {
                let got = b0 & SEQUENCE_MASK;
                if got == expected_seq {
                    return Ok(());
                }
                return Err(Error::BadAck { got, expected: expected_seq }.into());
            }
            _ => continue,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn timing_byte_decodes_against_known_values() {
        assert_eq!(decode_timing(0x8a), Duration::from_millis(100)); // base 10ms × 10
        assert_eq!(decode_timing(0x32), Duration::from_millis(5)); // base 0.1ms × 50
        assert_eq!(decode_timing(0x4a), Duration::from_millis(10)); // base 1ms × 10
        assert_eq!(decode_timing(0x00), Duration::ZERO);
    }

    #[test]
    fn setup_request_matches_vag_template() {
        let req = encode_setup_request(&Tp20Config::new(address::ENGINE));
        assert_eq!(req, [0x01, 0xc0, 0x00, 0x10, 0x00, 0x03, 0x01]);
    }

    #[test]
    fn setup_response_parses_negotiated_ids() {
        // ECU-listens-on 0x740 (our TX), ECU-transmits-from 0x300 (our RX).
        let resp = [0x01, 0xd0, 0x40, 0x07, 0x00, 0x03, 0x01];
        assert_eq!(parse_setup_response(&resp).unwrap(), (0x740, 0x300));
    }

    #[test]
    fn setup_response_rejects_bad_opcode_and_invalid_id() {
        assert_eq!(
            parse_setup_response(&[0x01, 0xd6, 0, 0, 0, 0, 0]),
            Err(Error::SetupRejected(0xd6))
        );
        assert_eq!(
            parse_setup_response(&[0x01, 0xd0, 0x00, 0x17, 0x00, 0x03, 0x01]),
            Err(Error::InvalidChannelId)
        );
    }

    #[test]
    fn segment_single_frame_request() {
        // UDS ReadDataByIdentifier 0xF190 → fits one frame, awaiting ACK, last.
        let (frames, next) = segment(&[0x22, 0xf1, 0x90], 0x0f, 0);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].bytes, [0x10, 0x00, 0x03, 0x22, 0xf1, 0x90]);
        assert!(frames[0].await_ack);
        assert_eq!(next, 1);
    }

    #[test]
    fn segment_multi_frame_block_windowing_and_wrap() {
        // 30-byte PDU → 32-byte payload → 5 frames (7,7,7,7,4); block size 2.
        let pdu: Vec<u8> = (0..30).collect();
        let (frames, next) = segment(&pdu, 2, 0x0e);
        let opcodes: Vec<u8> = frames.iter().map(|f| f.bytes[0] & OPCODE_MASK).collect();
        let seqs: Vec<u8> = frames.iter().map(|f| f.bytes[0] & SEQUENCE_MASK).collect();
        assert_eq!(seqs, [0x0e, 0x0f, 0x00, 0x01, 0x02]); // wraps F→0
        assert_eq!(opcodes, [
            FrameType::DataMore as u8,
            FrameType::DataAckMore as u8, // block boundary
            FrameType::DataMore as u8,
            FrameType::DataAckMore as u8, // block boundary
            FrameType::DataAckLast as u8, // final
        ]);
        let acks: Vec<bool> = frames.iter().map(|f| f.await_ack).collect();
        assert_eq!(acks, [false, true, false, true, true]);
        assert_eq!(next, 0x03);
    }

    #[test]
    fn reassembler_single_frame_with_ack() {
        let mut r = Reassembler::default();
        // last-frame opcode, seq 5, len 3, payload 62 F1 90.
        let out = r.push(&[0x15, 0x00, 0x03, 0x62, 0xf1, 0x90]);
        assert_eq!(out.ack_seq, Some(6)); // seq + 1
        assert_eq!(out.pdu.as_deref(), Some(&[0x62, 0xf1, 0x90][..]));
    }

    #[test]
    fn segment_reassemble_roundtrip() {
        // Round-trip a range of PDU sizes and block sizes through segmentation
        // + reassembly; the reassembled PDU must equal the input.
        for len in [1usize, 5, 6, 7, 8, 14, 100, 255, 4095] {
            let pdu: Vec<u8> = (0..len).map(|i| (i * 7 % 251) as u8).collect();
            for bs in [0u8, 1, 2, 8, 15] {
                let (frames, _) = segment(&pdu, bs, 0);
                let mut r = Reassembler::default();
                let mut got = None;
                for f in &frames {
                    if let Some(p) = r.push(&f.bytes).pdu {
                        got = Some(p);
                    }
                }
                assert_eq!(got.as_deref(), Some(&pdu[..]), "len={len} bs={bs}");
            }
        }
    }
}
