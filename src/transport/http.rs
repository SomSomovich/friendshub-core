use std::time::Duration;

use reqwest::header::CONTENT_TYPE;
use reqwest::Method;
use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::config::Config;
use crate::error::{Error, Result};

/// Upper bound on a server-requested wait, in seconds. A misconfigured or
/// hostile server sending `retry-after: 999999` must not park a call for
/// hours; past this the caller gets the 429 back and decides.
const MAX_RETRY_AFTER_SECS: u64 = 30;

#[derive(Clone)]
pub struct HttpClient {
    base: String,
    client: reqwest::Client,
}

impl HttpClient {
    pub fn new(cfg: &Config) -> Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent(concat!("friendshub-core/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| Error::Network(e.to_string()))?;

        Ok(Self { base: cfg.api_base.trim_end_matches('/').to_string(), client })
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
        self.send::<B, R>(Method::POST, path, Some(body), bearer).await
    }

    pub async fn put<B: Serialize, R: DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
        bearer: Option<&str>,
) -> Result<R> {
        self.send::<B, R>(Method::PUT, path, Some(body), bearer).await
    }

    pub async fn patch<B: Serialize, R: DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
        bearer: Option<&str>,
) -> Result<R> {
        self.send::<B, R>(Method::PATCH, path, Some(body), bearer).await
    }

    pub async fn delete<R: DeserializeOwned>(&self, path: &str, bearer: Option<&str>) -> Result<R> {
        self.send::<(), R>(Method::DELETE, path, None, bearer).await
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
        let mut req = self
            .client
            .post(&url)
            .header(CONTENT_TYPE, content_type)
            .body(data);
        if let Some(t) = bearer {
            req = req.bearer_auth(t);
        }
        let resp = req.send().await.map_err(|e| Error::Network(e.to_string()))?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(Error::Server { status: status.as_u16(), body });
        }
        let bytes = resp.bytes().await.map_err(|e| Error::Network(e.to_string()))?;
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
        let bytes = resp.bytes().await.map_err(|e| Error::Network(e.to_string()))?;
        Ok(bytes.to_vec())
    }

    pub async fn get_absolute_relative(&self, path: &str) -> Result<Vec<u8>> {
        let url = format!("{}{}", self.base, path);
        self.get_absolute(&url).await
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
        let url = format!("{}{}", self.base, path);
        let mut attempt: u32 = 0;

        loop {
            let mut req = self.client.request(method.clone(), &url);
            if let Some(token) = bearer {
                req = req.bearer_auth(token);
            }
            if let Some(b) = body {
                req = req.json(b);
            }

            let resp = req.send().await.map_err(|e| Error::Network(e.to_string()))?;
            let status = resp.status();

            if status.as_u16() == 429 && attempt == 0 {
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
                let body = resp.text().await.unwrap_or_default();
                return Err(Error::Server { status: status.as_u16(), body });
            }

            let bytes = resp.bytes().await.map_err(|e| Error::Network(e.to_string()))?;
            if bytes.is_empty() {
                return serde_json::from_slice(b"null")
                    .map_err(|e| Error::InvalidPayload(e.to_string()));
            }
            return serde_json::from_slice(&bytes)
                .map_err(|e| Error::InvalidPayload(e.to_string()));
        }
    }
}
