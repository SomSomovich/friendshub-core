use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("no local identity is configured")]
    NoIdentity,

    #[error("database: {0}")]
    Database(String),

    #[error("signal protocol: {0}")]
    Signal(String),

    #[error("invalid data: {0}")]
    Invalid(String),
}

impl From<sqlx::Error> for CryptoError {
    fn from(e: sqlx::Error) -> Self {
        CryptoError::Database(e.to_string())
    }
}

impl From<libsignal_protocol::SignalProtocolError> for CryptoError {
    fn from(e: libsignal_protocol::SignalProtocolError) -> Self {
        CryptoError::Signal(e.to_string())
    }
}

impl From<CryptoError> for crate::error::Error {
    fn from(e: CryptoError) -> Self {
        crate::error::Error::Internal(format!("crypto: {e}"))
    }
}

pub type CryptoResult<T> = std::result::Result<T, CryptoError>;
