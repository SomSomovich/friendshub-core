#[cfg(feature = "native")]
pub mod http;
pub mod protobuf;
#[cfg(feature = "native")]
pub mod ws;

#[cfg(feature = "native")]
pub use http::HttpClient;
#[cfg(feature = "native")]
pub use ws::WsClient;
