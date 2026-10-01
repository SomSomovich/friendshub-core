use std::time::Duration;

use reqwest::header::CONTENT_TYPE;
use reqwest::Method;
use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::config::Config;
use crate::error::{Error, Result};

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

    /// POSTs raw bytes with an explicit Content-Type. Used for avatar upload.
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

    /// PUTs bytes to an absolute URL (presigned S3) with no auth.
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

    /// GETs bytes from an absolute URL (presigned S3) with no auth.
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

    /// GETs raw bytes from the configured API base with no authentication.
    /// Used for public resources such as other accounts' avatars.
    pub async fn get_absolute_relative(&self, path: &str) -> Result<Vec<u8>> {
        let url = format!("{}{}", self.base, path);
        self.get_absolute(&url).await
    }

    async fn send<B: Serialize, R: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        body: Option<&B>,
        bearer: Option<&str>,
) -> Result<R> {
        let url = format!("{}{}", self.base, path);
        let mut req = self.client.request(method, &url);

        if let Some(token) = bearer {
            req = req.bearer_auth(token);
        }
        if let Some(b) = body {
            req = req.json(b);
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
}
