use strum_macros::FromRepr;

/// Mask for a data/ACK frame's opcode (high nibble of byte 0).
pub static OPCODE_MASK: u8 = 0xf0;
/// Mask for a data/ACK frame's sequence number (low nibble of byte 0).
pub static SEQUENCE_MASK: u8 = 0x0f;

/// Data-transfer and ACK opcodes, in the high nibble of a frame's first byte.
#[derive(Debug, PartialEq, Copy, Clone, FromRepr)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum FrameType {
    /// Data, awaiting ACK, more frames follow (block boundary).
    DataAckMore = 0x00,
    /// Data, awaiting ACK, final frame of the message.
    DataAckLast = 0x10,
    /// Data, no ACK, more frames follow.
    DataMore = 0x20,
    /// Data, no ACK, final frame of the message.
    DataLast = 0x30,
    /// ACK, not ready for the next block.
    AckWait = 0x90,
    /// ACK, ready for the next block.
    AckReady = 0xb0,
}

/// Channel-management opcodes (the whole first byte).
#[derive(Debug, PartialEq, Copy, Clone, FromRepr)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum ChannelType {
    /// Setup request, to `0x200` (broadcast setup id).
    SetupRequest = 0xc0,
    /// Positive setup response, on `0x200 + dest`.
    SetupResponse = 0xd0,
    /// Channel-parameters request.
    ParamsRequest = 0xa0,
    /// Channel-parameters response.
    ParamsResponse = 0xa1,
    /// Channel test (keepalive).
    ChannelTest = 0xa3,
    /// Disconnect.
    Disconnect = 0xa8,
}
