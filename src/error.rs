use serde::Serialize;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("configuration: {0}")]
    Config(String),

    #[error("database: {0}")]
    Database(String),

    #[error("actor is not running")]
    ActorClosed,

    #[error("failed to spawn actor thread: {0}")]
    SpawnThread(String),

    #[error("runtime build failed: {0}")]
    RuntimeBuild(String),

    #[error("unknown method 0x{0:08x}")]
    UnknownMethod(u32),

    #[error("invalid payload: {0}")]
    InvalidPayload(String),

    #[error("not implemented")]
    NotImplemented,

    #[error("not authenticated")]
    NotAuthenticated,

    #[error("network: {0}")]
    Network(String),

    #[error("server returned {status}: {body}")]
    Server { status: u16, body: String },

    #[error("internal: {0}")]
    Internal(String),
}

impl Error {
    pub fn code(&self) -> &'static str {
        match self {
            Error::Config(_) => "config",
            Error::Database(_) => "database",
            Error::ActorClosed => "actor_closed",
            Error::SpawnThread(_) => "spawn_thread",
            Error::RuntimeBuild(_) => "runtime_build",
            Error::UnknownMethod(_) => "unknown_method",
            Error::InvalidPayload(_) => "invalid_payload",
            Error::NotImplemented => "not_implemented",
            Error::NotAuthenticated => "not_authenticated",
            Error::Network(_) => "network",
            Error::Server { .. } => "server",
            Error::Internal(_) => "internal",
        }
    }

    pub fn to_json(&self) -> String {
        #[derive(Serialize)]
        struct Body<'a> {
            code: &'a str,
            message: String,
        }
        let body = Body { code: self.code(), message: self.to_string() };
        serde_json::to_string(&body).unwrap_or_else(|_| {
            "{\"code\":\"internal\",\"message\":\"serialization failed\"}".to_string()
        })
    }
}

impl From<sqlx::Error> for Error {
    fn from(e: sqlx::Error) -> Self {
        Error::Database(e.to_string())
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::InvalidPayload(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, Error>;
