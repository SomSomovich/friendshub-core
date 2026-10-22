use std::time::Duration;

use reqwest::Method;
use reqwest::header::{ACCEPT, CONTENT_TYPE, LOCATION};
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::config::Config;
use crate::error::{Error, Result};
use crate::transport::protobuf::{self, Protocol};

const PROTOBUF_MEDIA_TYPE: &str = "application/x-protobuf";

/// Upper bound on a server-requested wait, in seconds. A misconfigured or
/// hostile server sending `retry-after: 999999` must not park a call for
/// hours; past this the caller gets the 429 back and decides.
const MAX_RETRY_AFTER_SECS: u64 = 30;

#[derive(Clone)]
pub struct HttpClient {
    base: String,
    client: reqwest::Client,
    no_redirect_client: reqwest::Client,
}

impl HttpClient {
    pub fn new(cfg: &Config) -> Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent(concat!("friendshub-core/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| Error::Network(e.to_string()))?;
        let no_redirect_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent(concat!("friendshub-core/", env!("CARGO_PKG_VERSION")))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| Error::Network(e.to_string()))?;

        Ok(Self {
            base: cfg.api_base.trim_end_matches('/').to_string(),
            client,
            no_redirect_client,
        })
    }

    pub async fn get<R: DeserializeOwned>(&self, path: &str, bearer: Option<&str>) -> Result<R> {
        self.send::<(), R>(Method::GET, path, None, bearer).await
    }

    pub async fn post<B: Serialize, R: DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
        bearer: Option<&str>,
    ) -> Result<R> {
        self.send::<B, R>(Method::POST, path, Some(body), bearer)
            .await
    }

    /// Sends a mutation without retrying HTTP 429, matching APIs where the
    /// web client deliberately surfaces rate limiting to the caller.
    pub async fn post_no_rate_limit_retry<B: Serialize, R: DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
        bearer: Option<&str>,
    ) -> Result<R> {
        self.send_with_retry::<B, R>(Method::POST, path, Some(body), bearer, false)
            .await
    }

    pub async fn put<B: Serialize, R: DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
        bearer: Option<&str>,
    ) -> Result<R> {
        self.send::<B, R>(Method::PUT, path, Some(body), bearer)
            .await
    }

    pub async fn patch<B: Serialize, R: DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
        bearer: Option<&str>,
    ) -> Result<R> {
        self.send::<B, R>(Method::PATCH, path, Some(body), bearer)
            .await
    }

    pub async fn delete<R: DeserializeOwned>(&self, path: &str, bearer: Option<&str>) -> Result<R> {
        self.send::<(), R>(Method::DELETE, path, None, bearer).await
    }

    /// Sends DELETE without retrying HTTP 429.
    pub async fn delete_no_rate_limit_retry<R: DeserializeOwned>(
        &self,
        path: &str,
        bearer: Option<&str>,
    ) -> Result<R> {
        self.send_with_retry::<(), R>(Method::DELETE, path, None, bearer, false)
            .await
    }

    /// Sends a DELETE request with a typed body.
    ///
    /// A small number of first-party REST endpoints define DELETE bodies. This
    /// intentionally uses the same route lookup, protobuf encoding, response
    /// decoding, error handling, and rate-limit retry policy as other verbs.
    pub async fn delete_with_body<B: Serialize, R: DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
        bearer: Option<&str>,
    ) -> Result<R> {
        self.send::<B, R>(Method::DELETE, path, Some(body), bearer)
            .await
    }

    /// Sends a body-bearing DELETE without retrying HTTP 429.
    pub async fn delete_with_body_no_rate_limit_retry<B: Serialize, R: DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
        bearer: Option<&str>,
    ) -> Result<R> {
        self.send_with_retry::<B, R>(Method::DELETE, path, Some(body), bearer, false)
            .await
    }

    pub async fn post_void<B: Serialize>(
        &self,
        path: &str,
        body: &B,
        bearer: Option<&str>,
    ) -> Result<()> {
        let _: serde_json::Value = self
            .send::<B, serde_json::Value>(Method::POST, path, Some(body), bearer)
            .await?;
        Ok(())
    }

    pub async fn post_raw<R: DeserializeOwned>(
        &self,
        path: &str,
        data: Vec<u8>,
        content_type: &str,
        bearer: Option<&str>,
    ) -> Result<R> {
        let url = format!("{}{}", self.base, path);
        let protocol = protobuf::protocol_for(Method::POST.as_str(), path)?;
        let mut req = self.client.post(&url);
        if let Protocol::Protobuf(route) = protocol {
            if !protobuf::request_is_raw(route) {
                return Err(Error::InvalidPayload(
                    "this REST route does not accept a raw request body".into(),
                ));
            }
            req = req
                .header(ACCEPT, PROTOBUF_MEDIA_TYPE)
                .header(CONTENT_TYPE, content_type)
                .body(data);
        } else if matches!(protocol, Protocol::Json) {
            req = req.header(CONTENT_TYPE, content_type).body(data);
        } else {
            return Err(Error::InvalidPayload(
                "this REST route is a raw response, not a raw upload".into(),
            ));
        }
        if let Some(t) = bearer {
            req = req.bearer_auth(t);
        }
        let resp = req
            .send()
            .await
            .map_err(|e| Error::Network(e.to_string()))?;
        let status = resp.status();
        if !status.is_success() {
            let body = match protocol {
                Protocol::Protobuf(_) | Protocol::RawProtobufErrors => {
                    let bytes = resp.bytes().await.unwrap_or_default();
                    protobuf::decode_http_error_body(protocol, &bytes)
                }
                Protocol::Json => resp.text().await.unwrap_or_default(),
            };
            return Err(Error::Server {
                status: status.as_u16(),
                body,
            });
        }
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| Error::Network(e.to_string()))?;
        let bytes = match protocol {
            Protocol::Protobuf(route) => protobuf::decode_response_body(route, &bytes)?,
            Protocol::Json | Protocol::RawProtobufErrors => bytes.to_vec(),
        };
        if bytes.is_empty() {
            return serde_json::from_slice(b"null")
                .map_err(|e| Error::InvalidPayload(e.to_string()));
        }
        serde_json::from_slice(&bytes).map_err(|e| Error::InvalidPayload(e.to_string()))
    }

    pub async fn put_absolute(&self, url: &str, data: Vec<u8>) -> Result<()> {
        let resp = self
            .client
            .put(url)
            .header(CONTENT_TYPE, "application/octet-stream")
            .body(data)
            .send()
            .await
            .map_err(|e| Error::Network(e.to_string()))?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(Error::Server { status, body });
        }
        Ok(())
    }

    pub async fn get_absolute(&self, url: &str) -> Result<Vec<u8>> {
        let resp = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|e| Error::Network(e.to_string()))?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(Error::Server { status, body });
        }
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| Error::Network(e.to_string()))?;
        Ok(bytes.to_vec())
    }

    pub async fn get_absolute_relative(&self, path: &str) -> Result<Vec<u8>> {
        let url = format!("{}{}", self.base, path);
        let protobuf_errors = matches!(
            protobuf::protocol_for("GET", path)?,
            Protocol::RawProtobufErrors
        );
        if protobuf_errors {
            self.get_avatar_relative(&url).await
        } else {
            self.get_absolute(&url).await
        }
    }

    async fn get_avatar_relative(&self, url: &str) -> Result<Vec<u8>> {
        let response = self
            .no_redirect_client
            .get(url)
            .header(ACCEPT, PROTOBUF_MEDIA_TYPE)
            .send()
            .await
            .map_err(|e| Error::Network(e.to_string()))?;
        let status = response.status();
        let location = response
            .headers()
            .get(LOCATION)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);

        match protobuf::classify_avatar_initial_response(status.as_u16(), location.is_some()) {
            protobuf::AvatarInitialResponse::RawBytes => response
                .bytes()
                .await
                .map(|bytes| bytes.to_vec())
                .map_err(|e| Error::Network(e.to_string())),
            protobuf::AvatarInitialResponse::ApiProtobufError => {
                let body = response.bytes().await.unwrap_or_default();
                Err(Error::Server {
                    status: status.as_u16(),
                    body: protobuf::decode_error_body(&body),
                })
            }
            protobuf::AvatarInitialResponse::FollowStorageRedirect => {
                let location = location.expect("redirect classification requires Location");
                let target = url::Url::parse(url)
                    .and_then(|base| base.join(&location))
                    .map_err(|e| Error::Network(format!("invalid avatar redirect: {e}")))?;
                // The regular client keeps its existing redirect policy here;
                // any object-store response is returned with its original body.
                self.get_absolute(target.as_str()).await
            }
            protobuf::AvatarInitialResponse::RawRedirectError => {
                let body = response.bytes().await.unwrap_or_default();
                Err(Error::Server {
                    status: status.as_u16(),
                    body: String::from_utf8_lossy(&body).into_owned(),
                })
            }
        }
    }

    /// Sends a request, retrying once when the server answers 429.
    ///
    /// The wait is taken from `Retry-After` (seconds) and clamped to
    /// `MAX_RETRY_AFTER_SECS`. One retry: more would mask a server that is
    /// persistently refusing the caller, and the caller is the right place to
    /// decide whether to keep trying.
    async fn send<B: Serialize, R: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        body: Option<&B>,
        bearer: Option<&str>,
    ) -> Result<R> {
        self.send_with_retry(method, path, body, bearer, true).await
    }

    async fn send_with_retry<B: Serialize, R: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        body: Option<&B>,
        bearer: Option<&str>,
        retry_on_rate_limit: bool,
    ) -> Result<R> {
        let url = format!("{}{}", self.base, path);
        let protocol = protobuf::protocol_for(method.as_str(), path)?;
        let encoded_body = match protocol {
            Protocol::Json => None,
            Protocol::Protobuf(route) => {
                if protobuf::request_is_raw(route) {
                    return Err(Error::InvalidPayload(
                        "this REST route requires a raw request body".into(),
                    ));
                }
                if protobuf::request_requires_protobuf(route) {
                    let value = match body {
                        Some(body) => serde_json::to_value(body)
                            .map_err(|error| Error::InvalidPayload(error.to_string()))?,
                        None => serde_json::Value::Object(serde_json::Map::new()),
                    };
                    protobuf::encode_request_body(route, value)?
                } else {
                    None
                }
            }
            Protocol::RawProtobufErrors => {
                return Err(Error::InvalidPayload(
                    "raw avatar responses must use get_absolute_relative".into(),
                ));
            }
        };
        let mut attempt: u32 = 0;

        loop {
            let mut req = self.client.request(method.clone(), &url);
            if let Some(token) = bearer {
                req = req.bearer_auth(token);
            }
            match protocol {
                Protocol::Json => {
                    if let Some(body) = body {
                        req = req.json(body);
                    }
                }
                Protocol::Protobuf(route) => {
                    req = req.header(ACCEPT, PROTOBUF_MEDIA_TYPE);
                    if protobuf::request_requires_protobuf(route) {
                        req = req
                            .header(CONTENT_TYPE, PROTOBUF_MEDIA_TYPE)
                            .body(encoded_body.clone().unwrap_or_default());
                    }
                }
                Protocol::RawProtobufErrors => unreachable!("raw response was rejected above"),
            }

            let resp = req
                .send()
                .await
                .map_err(|e| Error::Network(e.to_string()))?;
            let status = resp.status();

            if retry_on_rate_limit && status.as_u16() == 429 && attempt == 0 {
                let wait = resp
                    .headers()
                    .get("retry-after")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or(5)
                    .min(MAX_RETRY_AFTER_SECS);
                tracing::info!(wait_secs = wait, path, "rate limited; retrying once");
                tokio::time::sleep(Duration::from_secs(wait)).await;
                attempt += 1;
                continue;
            }

            if !status.is_success() {
                let body = match protocol {
                    Protocol::Protobuf(_) | Protocol::RawProtobufErrors => {
                        let bytes = resp.bytes().await.unwrap_or_default();
                        protobuf::decode_http_error_body(protocol, &bytes)
                    }
                    Protocol::Json => resp.text().await.unwrap_or_default(),
                };
                return Err(Error::Server {
                    status: status.as_u16(),
                    body,
                });
            }

            let bytes = resp
                .bytes()
                .await
                .map_err(|e| Error::Network(e.to_string()))?;
            let bytes = match protocol {
                Protocol::Protobuf(route) => protobuf::decode_response_body(route, &bytes)?,
                Protocol::Json if bytes.is_empty() => b"null".to_vec(),
                Protocol::Json => bytes.to_vec(),
                Protocol::RawProtobufErrors => unreachable!("raw response was rejected above"),
            };
            return serde_json::from_slice(&bytes)
                .map_err(|e| Error::InvalidPayload(e.to_string()));
        }
    }
}

#[cfg(test)]
mod delete_with_body_tests {
    use super::*;
    use prost::Message;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn delete_with_body_encodes_registered_protobuf_request() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut chunk = [0_u8; 2048];
            let total_len = loop {
                let read = stream.read(&mut chunk).await.unwrap();
                assert_ne!(read, 0, "client closed before sending complete request");
                request.extend_from_slice(&chunk[..read]);
                if let Some(header_end) = request.windows(4).position(|w| w == b"\r\n\r\n") {
                    let header_end = header_end + 4;
                    let headers = String::from_utf8_lossy(&request[..header_end]);
                    let content_length = headers
                        .lines()
                        .find_map(|line| {
                            let (name, value) = line.split_once(':')?;
                            name.eq_ignore_ascii_case("content-length")
                                .then(|| value.trim().parse::<usize>().unwrap())
                        })
                        .unwrap_or(0);
                    let total_len = header_end + content_length;
                    if request.len() >= total_len {
                        break total_len;
                    }
                }
            };
            let response =
                b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            stream.write_all(response).await.unwrap();
            request.truncate(total_len);
            request
        });

        let config = Config {
            db_path: "/tmp/profile-extras-http-test.sqlite".into(),
            api_base: format!("http://{address}"),
            ws_url: format!("ws://{address}"),
            discovery: Default::default(),
            log_level: "error".into(),
            log_format: "text".into(),
        };
        let client = HttpClient::new(&config).unwrap();
        let body = serde_json::json!({"endpoint": "https://push.example.test/subscription/1"});
        let response: serde_json::Value = client
            .delete_with_body("/api/v1/push/subscribe", &body, Some("test-token"))
            .await
            .unwrap();
        assert_eq!(response, serde_json::Value::Null);

        let request = server.await.unwrap();
        let header_end = request.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
        let headers = String::from_utf8_lossy(&request[..header_end]);
        assert!(headers.starts_with("DELETE /api/v1/push/subscribe HTTP/1.1\r\n"));
        assert!(
            headers
                .to_ascii_lowercase()
                .contains("content-type: application/x-protobuf")
        );
        assert!(
            headers
                .to_ascii_lowercase()
                .contains("authorization: bearer test-token")
        );
        let decoded =
            crate::proto::rest::identity::UnsubscribeRequest::decode(&request[header_end..])
                .unwrap();
        assert_eq!(
            decoded.endpoint.as_deref(),
            Some("https://push.example.test/subscription/1")
        );
    }
}
