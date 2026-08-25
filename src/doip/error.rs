//! Error types for DoIP (ISO 13400-2).

use thiserror::Error;

#[derive(Error, Debug, Clone)]
pub enum Error {
    #[error("routing activation refused: 0x{0:02x} ({1})")]
    RoutingActivationRefused(u8, &'static str),
    #[error("diagnostic message rejected: 0x{0:02x} ({1})")]
    MessageNack(u8, &'static str),
    #[error("DoIP header rejected: 0x{0:02x} ({1})")]
    HeaderNack(u8, &'static str),
    #[error("malformed DoIP message")]
    MalformedMessage,
    #[error("bad DoIP protocol version: 0x{0:02x}/0x{1:02x}")]
    BadVersion(u8, u8),
    #[error("DoIP payload of {0} bytes exceeds the {1} byte limit")]
    PayloadTooLarge(usize, usize),
    #[error("no DoIP entity responded")]
    NoEntity,
    #[error("DoIP I/O error: {0}")]
    Io(std::sync::Arc<std::io::Error>),
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Io(std::sync::Arc::new(e))
    }
}
