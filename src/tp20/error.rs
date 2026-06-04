//! Error types for the VW TP2.0 protocol.

use thiserror::Error;

#[derive(Error, Debug, PartialEq, Clone)]
pub enum Error {
    #[error("Setup Rejected")]
    SetupRejected(u8),
    #[error("Invalid Channel Identifier")]
    InvalidChannelId,
    #[error("Malformed Frame")]
    MalformedFrame,
    #[error("Unexpected ACK")]
    BadAck { got: u8, expected: u8 },
    #[error("Disconnected")]
    Disconnected,
}
