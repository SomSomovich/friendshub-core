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
/// hostile server sending `retry-after: 999999` must not park a call for hours.
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
            base: normalize_api_base(&cfg.api_base),
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
        if let Protocol::Protobuf(route) = protocol {
            if !protobuf::request_is_raw(route) {
                return Err(Error::InvalidPayload(
                    "this REST route does not accept a raw request body".into(),
                ));
            }
        } else if !matches!(protocol, Protocol::Json) {
            return Err(Error::InvalidPayload(
                "this REST route is a raw response, not a raw upload".into(),
            ));
        }
        let mut attempt = 0;
        loop {
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
                    .body(data.clone());
            } else if matches!(protocol, Protocol::Json) {
                req = req.header(CONTENT_TYPE, content_type).body(data.clone());
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

            if status.as_u16() == 429 && attempt == 0 {
                if let Some(wait) = rate_limit_wait(resp.headers().get("retry-after")) {
                    tracing::info!(
                        wait_ms = wait.as_millis(),
                        path,
                        "rate limited; retrying raw upload once"
                    );
                    tokio::time::sleep(wait).await;
                    attempt += 1;
                    continue;
                }
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
                Protocol::Json | Protocol::RawProtobufErrors => bytes.to_vec(),
            };
            if bytes.is_empty() {
                return serde_json::from_slice(b"null")
                    .map_err(|e| Error::InvalidPayload(e.to_string()));
            }
            return serde_json::from_slice(&bytes)
                .map_err(|e| Error::InvalidPayload(e.to_string()));
        }
    }

    pub async fn put_absolute(&self, url: &str, data: Vec<u8>) -> Result<()> {
        let mut attempt = 0;
        loop {
            let resp = self
                .client
                .put(url)
                .header(CONTENT_TYPE, "application/octet-stream")
                .body(data.clone())
                .send()
                .await
                .map_err(|e| Error::Network(e.to_string()))?;
            if resp.status().as_u16() == 429 && attempt == 0 {
                if let Some(wait) = rate_limit_wait(resp.headers().get("retry-after")) {
                    tracing::info!(
                        wait_ms = wait.as_millis(),
                        "rate limited; retrying presigned upload once"
                    );
                    tokio::time::sleep(wait).await;
                    attempt += 1;
                    continue;
                }
            }
            if !resp.status().is_success() {
                let status = resp.status().as_u16();
                let body = resp.text().await.unwrap_or_default();
                return Err(Error::Server { status, body });
            }
            return Ok(());
        }
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
                if let Some(wait) = rate_limit_wait(resp.headers().get("retry-after")) {
                    tracing::info!(
                        wait_ms = wait.as_millis(),
                        path,
                        "rate limited; retrying once"
                    );
                    tokio::time::sleep(wait).await;
                    attempt += 1;
                    continue;
                }
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

fn rate_limit_wait(header: Option<&reqwest::header::HeaderValue>) -> Option<Duration> {
    let seconds = header?.to_str().ok()?.trim().parse::<f64>().ok()?;
    if !seconds.is_finite() || seconds < 0.0 {
        return None;
    }
    let milliseconds = (seconds * 1_000.0)
        .ceil()
        .min(MAX_RETRY_AFTER_SECS as f64 * 1_000.0) as u64;
    Some(Duration::from_millis(milliseconds))
}

fn normalize_api_base(api_base: &str) -> String {
    let trimmed = api_base.trim_end_matches('/');
    trimmed
        .strip_suffix("/api/v1")
        .unwrap_or(trimmed)
        .to_owned()
}

#[cfg(test)]
mod route_codec_tests {
    use super::*;
    use prost::Message;

    #[test]
    fn delete_with_body_uses_registered_protobuf_request_and_empty_response() {
        let Protocol::Protobuf(route) =
            protobuf::protocol_for("DELETE", "/api/v1/push/subscribe").unwrap()
        else {
            panic!("push unsubscribe must use protobuf");
        };
        assert!(protobuf::request_requires_protobuf(route));
        let encoded = protobuf::encode_request_body(
            route,
            serde_json::json!({"endpoint": "https://push.example.test/subscription/1"}),
        )
        .unwrap()
        .unwrap();
        let decoded =
            crate::proto::rest::identity::UnsubscribeRequest::decode(encoded.as_slice()).unwrap();
        assert_eq!(
            decoded.endpoint.as_deref(),
            Some("https://push.example.test/subscription/1")
        );
        assert_eq!(protobuf::decode_response_body(route, &[]).unwrap(), b"null");
    }

    #[test]
    fn profile_fields_protobuf_encoding_preserves_label_and_value_verbatim() {
        let Protocol::Protobuf(route) =
            protobuf::protocol_for("PUT", "/api/v1/profile/fields").unwrap()
        else {
            panic!("profile fields must use protobuf");
        };
        let encoded = protobuf::encode_request_body(
            route,
            serde_json::json!({
                "fields": [{"label": "  GitHub  ", "value": "  @someone  "}]
            }),
        )
        .unwrap()
        .unwrap();
        let decoded =
            crate::proto::rest::identity::SetProfileFieldsRequest::decode(encoded.as_slice())
                .unwrap();
        let field = &decoded.fields.unwrap().items[0];
        assert_eq!(field.label.as_deref(), Some("  GitHub  "));
        assert_eq!(field.value.as_deref(), Some("  @someone  "));
    }

    #[test]
    fn api_base_normalization_keeps_bot_api_on_the_origin() {
        assert_eq!(
            normalize_api_base("https://api.example.test/api/v1/"),
            "https://api.example.test"
        );
        assert_eq!(
            normalize_api_base("https://api.example.test/custom/"),
            "https://api.example.test/custom"
        );
    }

    #[test]
    fn rate_limit_retry_requires_a_valid_header_and_clamps_the_wait() {
        use reqwest::header::HeaderValue;

        assert_eq!(
            rate_limit_wait(Some(&HeaderValue::from_static("0.25"))),
            Some(Duration::from_millis(250))
        );
        assert_eq!(
            rate_limit_wait(Some(&HeaderValue::from_static("999"))),
            Some(Duration::from_secs(MAX_RETRY_AFTER_SECS))
        );
        assert_eq!(
            rate_limit_wait(Some(&HeaderValue::from_static("invalid"))),
            None
        );
        assert_eq!(rate_limit_wait(None), None);
    }
}
