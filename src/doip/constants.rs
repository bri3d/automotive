use strum_macros::FromRepr;

/// ISO 13400-2:2012 protocol version.
pub const PROTOCOL_VERSION: u8 = 0x02;
/// Version for vehicle identification requests, sent before the entity's own
/// version is known (ISO 13400-2 Table 12). Strict entities ignore anything else.
pub const VEHICLE_ID_VERSION: u8 = 0xff;
/// Registered DoIP port, TCP (diagnostics) and UDP (discovery).
pub const PORT: u16 = 13400;

pub const HEADER_LEN: usize = 8;
/// Upper bound on an accepted payload, guarding against a bogus length field.
pub const MAX_PAYLOAD: usize = 8 * 1024 * 1024;

/// Default tester logical address for VAG (`CP_DoIPLogicalTesterAddress`).
pub const DEFAULT_TESTER_ADDRESS: u16 = 0x0e80;
/// Routing activation type 0 — default, non-OEM-specific.
pub const ACTIVATION_TYPE_DEFAULT: u8 = 0x00;

pub const ROUTING_ACTIVATION_SUCCESS: u8 = 0x10;
pub const ACK_OK: u8 = 0x00;

#[derive(Debug, PartialEq, Eq, Copy, Clone, FromRepr)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u16)]
pub enum PayloadType {
    GenericNack = 0x0000,
    VehicleIdRequest = 0x0001,
    VehicleIdRequestEid = 0x0002,
    VehicleIdRequestVin = 0x0003,
    VehicleAnnouncement = 0x0004,
    RoutingActivationRequest = 0x0005,
    RoutingActivationResponse = 0x0006,
    AliveCheckRequest = 0x0007,
    AliveCheckResponse = 0x0008,
    EntityStatusRequest = 0x4001,
    EntityStatusResponse = 0x4002,
    PowerModeRequest = 0x4003,
    PowerModeResponse = 0x4004,
    DiagnosticMessage = 0x8001,
    DiagnosticAck = 0x8002,
    DiagnosticNack = 0x8003,
}

pub fn header_nack_reason(code: u8) -> &'static str {
    match code {
        0x00 => "incorrect pattern format",
        0x01 => "unknown payload type",
        0x02 => "message too large",
        0x03 => "out of memory",
        0x04 => "invalid payload length",
        _ => "unknown",
    }
}

pub fn routing_activation_reason(code: u8) -> &'static str {
    match code {
        0x00 => "unknown source address",
        0x01 => "all TCP sockets registered and active",
        0x02 => "source address differs from the one already activated",
        0x03 => "source address already registered on another socket",
        0x04 => "missing authentication",
        0x05 => "rejected confirmation",
        0x06 => "unsupported routing activation type",
        0x07 => "requires encrypted link (TLS)",
        0x10 => "success",
        0x11 => "success, confirmation required",
        _ => "unknown",
    }
}

pub fn diagnostic_nack_reason(code: u8) -> &'static str {
    match code {
        0x02 => "invalid source address",
        0x03 => "unknown target address",
        0x04 => "diagnostic message too large",
        0x05 => "out of memory",
        0x06 => "target unreachable",
        0x07 => "unknown network",
        0x08 => "transport protocol error",
        _ => "unknown",
    }
}
