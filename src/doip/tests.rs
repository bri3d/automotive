use super::*;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use tokio::net::TcpListener;

use crate::StreamExt;

/// Minimal DoIP entity: activates routing, then answers each diagnostic
/// message with an ACK followed by `responses.next()`.
async fn spawn_entity(responses: Vec<Vec<u8>>, ack_code: u8, activation_code: u8) -> String {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let (mut rd, mut wr) = stream.into_split();
        let mut responses = responses.into_iter();
        loop {
            let Ok((payload_type, payload)) = read_message(&mut rd).await else {
                return;
            };
            match PayloadType::from_repr(payload_type) {
                Some(PayloadType::RoutingActivationRequest) => {
                    let mut p = payload[0..2].to_vec();
                    p.extend_from_slice(&0x3828u16.to_be_bytes());
                    p.push(activation_code);
                    p.extend_from_slice(&[0u8; 4]);
                    write_message(&mut wr, PayloadType::RoutingActivationResponse, &p)
                        .await
                        .unwrap();
                }
                Some(PayloadType::DiagnosticMessage) => {
                    let mut ack = payload[0..4].to_vec();
                    ack.swap(0, 2);
                    ack.swap(1, 3);
                    ack.push(ack_code);
                    let kind = if ack_code == ACK_OK {
                        PayloadType::DiagnosticAck
                    } else {
                        PayloadType::DiagnosticNack
                    };
                    write_message(&mut wr, kind, &ack).await.unwrap();
                    if let Some(body) = responses.next() {
                        let mut p = ack[0..4].to_vec();
                        p.extend_from_slice(&body);
                        write_message(&mut wr, PayloadType::DiagnosticMessage, &p)
                            .await
                            .unwrap();
                    }
                }
                _ => {}
            }
        }
    });
    addr.to_string()
}

fn config(host: &str) -> DoIpConfig {
    let (ip, port) = host.rsplit_once(':').unwrap();
    DoIpConfig {
        port: port.parse().unwrap(),
        timeout: Duration::from_millis(500),
        ..DoIpConfig::new(ip, 0x3076)
    }
}

#[test]
fn header_round_trips() {
    let msg = encode(
        PayloadType::DiagnosticMessage,
        &[0x0e, 0x80, 0x30, 0x76, 0x3e, 0x00],
    );
    assert_eq!(&msg[0..4], &[0x02, 0xfd, 0x80, 0x01]);
    assert_eq!(&msg[4..8], &6u32.to_be_bytes());
    let (payload_type, payload) = decode(&msg).unwrap();
    assert_eq!(
        PayloadType::from_repr(payload_type),
        Some(PayloadType::DiagnosticMessage)
    );
    assert_eq!(payload, &[0x0e, 0x80, 0x30, 0x76, 0x3e, 0x00]);
}

#[test]
fn a_bad_inverse_version_is_rejected() {
    let mut msg = encode(PayloadType::DiagnosticMessage, &[]);
    msg[1] = 0x00;
    assert!(matches!(decode(&msg), Err(Error::BadVersion(0x02, 0x00))));
}

#[test]
fn a_vehicle_id_request_uses_the_wildcard_version() {
    let msg = encode(PayloadType::VehicleIdRequest, &[]);
    assert_eq!(&msg[0..4], &[0xff, 0x00, 0x00, 0x01]);
    assert_eq!(&msg[4..8], &0u32.to_be_bytes());
}

#[test]
fn a_truncated_payload_is_rejected() {
    let mut msg = encode(PayloadType::DiagnosticMessage, &[1, 2, 3, 4]);
    msg.truncate(HEADER_LEN + 2);
    assert!(matches!(decode(&msg), Err(Error::MalformedMessage)));
}

#[test]
fn a_refused_routing_activation_names_its_reason() {
    let payload = [0x0e, 0x80, 0x38, 0x28, 0x06, 0, 0, 0, 0];
    let Err(Error::RoutingActivationRefused(code, reason)) = parse_routing_activation(&payload)
    else {
        panic!("0x06 must not read as success");
    };
    assert_eq!(code, 0x06);
    assert!(reason.contains("routing activation type"), "{reason}");
}

#[test]
fn an_announcement_parses() {
    let mut payload = b"WVWZZZ3CZJE000001".to_vec();
    payload.extend_from_slice(&0x3828u16.to_be_bytes());
    payload.extend_from_slice(&[0xaa; 6]);
    payload.extend_from_slice(&[0xbb; 6]);
    payload.push(0x00);
    let source = "169.254.1.2:13400".parse().unwrap();
    let local = Some(IpAddr::V4(Ipv4Addr::new(169, 254, 108, 35)));
    let a = parse_announcement(source, local, &payload).unwrap();
    assert_eq!(a.vin, "WVWZZZ3CZJE000001");
    assert_eq!(a.logical_address, 0x3828);
    assert_eq!(a.eid, [0xaa; 6]);
    assert_eq!(a.gid, [0xbb; 6]);
    // The NIC that heard it is what a later connect must bind.
    assert_eq!(a.local, local);
}

#[tokio::test]
async fn a_request_gets_its_response() {
    let host = spawn_entity(
        vec![vec![0x62, 0xf1, 0x9e, 0x41]],
        ACK_OK,
        ROUTING_ACTIVATION_SUCCESS,
    )
    .await;
    let transport = DoIpTransport::open(config(&host)).await.unwrap();
    assert_eq!(transport.entity_address(), 0x3828);

    let mut stream = transport.recv();
    transport.send(&[0x22, 0xf1, 0x9e]).await.unwrap();
    let response = stream.next().await.unwrap().unwrap();
    assert_eq!(response, vec![0x62, 0xf1, 0x9e, 0x41]);
    drop(stream);
    transport.shutdown().await;
}

/// Back-to-back exchanges: proves the stream stays framed across sends. A
/// `read_exact` polled directly in the dispatch `select!` would be dropped
/// mid-header by the next command and desync here.
#[tokio::test]
async fn the_stream_stays_framed_across_exchanges() {
    let replies: Vec<Vec<u8>> = (0..8u8).map(|i| vec![0x62, 0xf1, 0x9e, i]).collect();
    let host = spawn_entity(replies.clone(), ACK_OK, ROUTING_ACTIVATION_SUCCESS).await;
    let transport = DoIpTransport::open(config(&host)).await.unwrap();

    let mut stream = transport.recv();
    for expected in &replies {
        transport.send(&[0x22, 0xf1, 0x9e]).await.unwrap();
        assert_eq!(&stream.next().await.unwrap().unwrap(), expected);
    }
}

/// An entity that answers without the mandated `0x8002` must not stall the
/// send until its timeout — the answer itself proves the request landed.
#[tokio::test]
async fn an_answer_settles_a_send_the_entity_never_acknowledged() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let (mut rd, mut wr) = stream.into_split();
        loop {
            let Ok((payload_type, payload)) = read_message(&mut rd).await else {
                return;
            };
            let mut p = payload[0..2].to_vec();
            match PayloadType::from_repr(payload_type) {
                Some(PayloadType::RoutingActivationRequest) => {
                    p.extend_from_slice(&0x3828u16.to_be_bytes());
                    p.push(ROUTING_ACTIVATION_SUCCESS);
                    p.extend_from_slice(&[0u8; 4]);
                    write_message(&mut wr, PayloadType::RoutingActivationResponse, &p)
                        .await
                        .unwrap();
                }
                // Answer straight away, with no acknowledgement at all.
                Some(PayloadType::DiagnosticMessage) => {
                    let mut r = vec![payload[2], payload[3], payload[0], payload[1]];
                    r.extend_from_slice(&[0x62, 0xf1, 0x9e, 0x41]);
                    write_message(&mut wr, PayloadType::DiagnosticMessage, &r)
                        .await
                        .unwrap();
                }
                _ => {}
            }
        }
    });

    let transport = DoIpTransport::open(config(&addr.to_string()))
        .await
        .unwrap();
    let mut stream = transport.recv();
    let started = tokio::time::Instant::now();
    transport.send(&[0x22, 0xf1, 0x9e]).await.unwrap();
    assert_eq!(
        stream.next().await.unwrap().unwrap(),
        vec![0x62, 0xf1, 0x9e, 0x41]
    );
    assert!(
        started.elapsed() < Duration::from_millis(400),
        "send waited for a missing ACK"
    );
}

#[tokio::test]
async fn a_refused_activation_fails_the_open() {
    let host = spawn_entity(vec![], ACK_OK, 0x00).await;
    let Err(e) = DoIpTransport::open(config(&host)).await else {
        panic!("an unknown source address must not activate");
    };
    assert!(e.to_string().contains("unknown source address"), "{e}");
}

#[tokio::test]
async fn a_nacked_message_fails_the_send() {
    let host = spawn_entity(vec![], 0x03, ROUTING_ACTIVATION_SUCCESS).await;
    let transport = DoIpTransport::open(config(&host)).await.unwrap();
    let Err(e) = transport.send(&[0x22, 0xf1, 0x9e]).await else {
        panic!("a 0x8003 negative acknowledgement must fail the send");
    };
    assert!(e.to_string().contains("unknown target address"), "{e}");
}

/// An entity that never acknowledges must time the send out rather than hang.
#[tokio::test]
async fn a_silent_entity_times_the_send_out() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let (mut rd, mut wr) = stream.into_split();
        let (_, payload) = read_message(&mut rd).await.unwrap();
        let mut p = payload[0..2].to_vec();
        p.extend_from_slice(&0x3828u16.to_be_bytes());
        p.push(ROUTING_ACTIVATION_SUCCESS);
        p.extend_from_slice(&[0u8; 4]);
        write_message(&mut wr, PayloadType::RoutingActivationResponse, &p)
            .await
            .unwrap();
        std::future::pending::<()>().await;
    });

    let transport = DoIpTransport::open(config(&addr.to_string()))
        .await
        .unwrap();
    assert!(matches!(
        transport.send(&[0x3e, 0x00]).await,
        Err(crate::Error::Timeout)
    ));
}

#[test]
fn directed_broadcast_of_a_link_local_nic() {
    assert_eq!(
        directed_broadcast(
            Ipv4Addr::new(169, 254, 108, 35),
            Ipv4Addr::new(255, 255, 0, 0)
        ),
        Ipv4Addr::new(169, 254, 255, 255)
    );
    assert_eq!(
        directed_broadcast(
            Ipv4Addr::new(192, 168, 1, 133),
            Ipv4Addr::new(255, 255, 255, 0)
        ),
        Ipv4Addr::new(192, 168, 1, 255)
    );
}

/// Discovery must search every interface, not just the one the routing table
/// prefers, and never the loopback.
#[test]
fn discovery_binds_every_non_loopback_interface() {
    for iface in discovery_interfaces() {
        assert!(!iface.bind.is_loopback());
        assert!(iface.destinations.iter().all(|d| d.port() == PORT));
        // Each NIC gets its own directed broadcast plus the limited one.
        assert!(iface
            .destinations
            .iter()
            .any(|d| *d.ip() == Ipv4Addr::BROADCAST));
        let directed = *iface.destinations[0].ip();
        assert_eq!(
            u32::from(directed) & u32::from(iface.bind),
            u32::from(iface.bind)
        );
    }
}

/// The per-socket loop must keep asking until the deadline — one lost datagram
/// cannot be the difference between finding the car and not — and must stamp
/// each answer with the interface it came back on.
#[tokio::test]
async fn discovery_retries_and_records_the_local_interface() {
    let entity = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let SocketAddr::V4(entity_addr) = entity.local_addr().unwrap() else {
        panic!("a v4 bind yields a v4 address");
    };

    let mut announcement = b"WVWZZZ3CZJE000001".to_vec();
    announcement.extend_from_slice(&0x3828u16.to_be_bytes());
    announcement.extend_from_slice(&[0xaa; 6]);
    announcement.extend_from_slice(&[0xbb; 6]);
    announcement.push(0x00);
    let reply = encode(PayloadType::VehicleAnnouncement, &announcement);
    let request = encode(PayloadType::VehicleIdRequest, &[]);

    let seen = Arc::new(AtomicUsize::new(0));
    let counter = seen.clone();
    let expected = request.clone();
    tokio::spawn(async move {
        let mut buf = [0u8; 64];
        while let Ok((n, from)) = entity.recv_from(&mut buf).await {
            assert_eq!(buf[..n], expected[..]);
            counter.fetch_add(1, Ordering::SeqCst);
            entity.send_to(&reply, from).await.unwrap();
        }
    });

    let local = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let (tx, mut rx) = mpsc::channel(8);
    let deadline = tokio::time::Instant::now() + DISCOVERY_RETRY * 2 + Duration::from_millis(200);
    let task = tokio::spawn(discovery_task(
        socket,
        Some(local),
        vec![entity_addr],
        request,
        deadline,
        tx,
    ));

    let a = rx.recv().await.unwrap();
    assert_eq!(a.vin, "WVWZZZ3CZJE000001");
    assert_eq!(a.local, Some(local));
    task.await.unwrap().unwrap();
    assert!(
        seen.load(Ordering::SeqCst) >= 3,
        "the request must be repeated while waiting"
    );
}

/// A source-bound connect must still reach the entity.
#[tokio::test]
async fn a_bound_local_address_connects() {
    let host = spawn_entity(vec![], ACK_OK, ROUTING_ACTIVATION_SUCCESS).await;
    let config = DoIpConfig {
        local_address: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        ..config(&host)
    };
    DoIpTransport::open(config).await.unwrap().shutdown().await;
}
