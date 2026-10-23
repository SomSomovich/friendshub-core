//! Bot-token REST API support.
//!
//! Bot long polling runs on its own library-owned thread and Tokio runtime, so
//! an intentionally long request never parks the account actor. Callback data
//! is owned Rust data; callers may retain it after a callback returns without
//! allocating or freeing any library buffers.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::thread::{self, JoinHandle, ThreadId};
use std::time::Duration;

use reqwest::header::ACCEPT;
use serde::{Deserialize, Serialize};
use tokio::sync::oneshot;
use url::Url;

use crate::client::{Client, method_ids};
use crate::error::{Error, Result};
use crate::runtime::ActorState;

const MAX_CALLBACK_TEXT_CHARS: usize = 200;

/// Options for bot-token long polling. Bounds match the bot REST API.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BotUpdatesOptions {
    /// Last successfully handled update ID. Negative values are normalized to
    /// zero, matching the backend's `offset >= 0` rule.
    pub offset: i64,
    /// Number of updates to request; clamped to 1..=500.
    pub limit: u32,
    /// Long-poll timeout in seconds; clamped to 0..=60.
    pub timeout_seconds: u32,
}

impl Default for BotUpdatesOptions {
    fn default() -> Self {
        Self {
            offset: 0,
            limit: 100,
            timeout_seconds: 60,
        }
    }
}

/// Data for a bot `message` or `edited_message` update.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct BotMessageUpdateData {
    pub message_id: String,
    pub bot_id: String,
    pub account_id: String,
    pub text: String,
    pub reply_to_message_id: Option<String>,
    pub created_at: i64,
}

/// A `message` update delivered to [`BotUpdateHandler::on_message`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BotMessageUpdate {
    pub update_id: i64,
    pub data: BotMessageUpdateData,
    pub created_at: Option<i64>,
}

/// An `edited_message` update delivered to
/// [`BotUpdateHandler::on_edited_message`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BotEditedMessageUpdate {
    pub update_id: i64,
    pub data: BotMessageUpdateData,
    pub created_at: Option<i64>,
}

/// Data for a bot `callback_query` update.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct BotCallbackQueryUpdateData {
    pub callback_query_id: String,
    pub message_id: String,
    pub account_id: String,
    pub data: String,
    pub created_at: i64,
}

/// A `callback_query` update delivered to
/// [`BotUpdateHandler::on_callback_query`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BotCallbackQueryUpdate {
    pub update_id: i64,
    pub data: BotCallbackQueryUpdateData,
    pub created_at: Option<i64>,
}

/// An error raised by the bot REST API, response decoder, or update callback.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BotApiError {
    /// HTTP status when the error came from an HTTP response.
    pub status: Option<u16>,
    /// Backend error code when one was present in its JSON response.
    pub code: Option<String>,
    /// Human-readable error message.
    pub message: String,
}

impl BotApiError {
    fn local(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status: None,
            code: Some(code.to_owned()),
            message: message.into(),
        }
    }
}

/// Per-type callbacks for bot updates.
///
/// Each callback receives an owned DTO and runs on the long-poll worker, never
/// on the account actor. Return `Ok(())` only after the update is durably
/// handled: the offset advances only after that return. Returning an error
/// reports it through `on_error` and stops this subscription without advancing
/// that update. Callback panics are caught and treated as callback errors.
pub trait BotUpdateHandler: Send + Sync + 'static {
    fn on_message(&self, update: BotMessageUpdate) -> Result<()>;
    fn on_edited_message(&self, update: BotEditedMessageUpdate) -> Result<()>;
    fn on_callback_query(&self, update: BotCallbackQueryUpdate) -> Result<()>;
    fn on_error(&self, error: BotApiError);
    fn on_offset(&self, last_handled_update_id: i64);
}

/// A running bot update subscription.
///
/// Dropping this value cancels the outstanding HTTP request and joins the
/// worker. Cancellation is prompt while the worker is polling the network; a
/// synchronous user callback already in progress must return before the worker
/// can finish. A callback may retain its owned DTO independently of this
/// subscription's lifetime.
pub struct BotUpdatesSubscription {
    cancel: Option<oneshot::Sender<()>>,
    worker: Option<JoinHandle<()>>,
    worker_id: ThreadId,
}

impl BotUpdatesSubscription {
    /// Cancels polling and waits for the worker to finish. Repeated calls are
    /// harmless. This method does not block the actor.
    pub fn cancel(&mut self) -> Result<()> {
        if let Some(cancel) = self.cancel.take() {
            let _ = cancel.send(());
        }
        self.join_worker()
    }

    fn join_worker(&mut self) -> Result<()> {
        if thread::current().id() == self.worker_id {
            // A callback can indirectly drop its own subscription. Detaching
            // here avoids self-join; the cancellation signal was already sent.
            self.worker.take();
            return Ok(());
        }
        if let Some(worker) = self.worker.take() {
            worker
                .join()
                .map_err(|_| Error::Internal("bot update worker panicked".into()))?;
        }
        Ok(())
    }
}

impl Drop for BotUpdatesSubscription {
    fn drop(&mut self) {
        if let Some(cancel) = self.cancel.take() {
            let _ = cancel.send(());
        }
        let _ = self.join_worker();
    }
}

/// Request body for the bot-token `answerCallbackQuery` endpoint.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct AnswerBotCallbackQueryInput {
    pub callback_query_id: String,
    pub account_id: String,
    pub message_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub show_alert: Option<bool>,
}

impl Client {
    /// Starts long polling with the bot token on a library-owned worker.
    ///
    /// `token` is copied into that worker and the caller can discard its input
    /// string after this call. Update DTOs passed to callbacks are Rust-owned
    /// values, so the callback may keep them without separately managing a
    /// native buffer.
    pub fn subscribe_bot_updates(
        &self,
        token: impl Into<String>,
        options: BotUpdatesOptions,
        handler: Arc<dyn BotUpdateHandler>,
    ) -> Result<BotUpdatesSubscription> {
        let token = token.into();
        validate_token(&token)?;

        // VERSION exposes the resolved discovery URL. This short actor call
        // obtains the same base the regular HTTP client is using; all long-poll
        // traffic then happens off-actor.
        let version: serde_json::Value =
            self.call_json(method_ids::VERSION, &serde_json::json!({}))?;
        let api_base = version
            .get("api_base")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| Error::Internal("version response has no api_base".into()))?;
        let endpoint = bot_api_url(api_base)?;

        let options = BotUpdatesOptions {
            offset: options.offset.max(0),
            limit: options.limit.clamp(1, 500),
            timeout_seconds: options.timeout_seconds.min(60),
        };
        let request_timeout = Duration::from_secs(u64::from(options.timeout_seconds) + 5);
        let client = reqwest::Client::builder()
            .timeout(request_timeout)
            .user_agent(concat!("friendshub-core/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|error| Error::Network(format!("bot API client: {error}")))?;

        let (cancel_tx, cancel_rx) = oneshot::channel();
        let worker_handler = handler;
        let worker_endpoint = endpoint;
        let worker = thread::Builder::new()
            .name("friendshub-bot-updates".into())
            .spawn(move || {
                let runtime = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(runtime) => runtime,
                    Err(error) => {
                        notify_error(
                            &worker_handler,
                            BotApiError::local("runtime_build", error.to_string()),
                        );
                        return;
                    }
                };
                runtime.block_on(poll_updates(
                    client,
                    worker_endpoint,
                    token,
                    options,
                    worker_handler,
                    cancel_rx,
                ));
            })
            .map_err(|error| Error::SpawnThread(error.to_string()))?;
        let worker_id = worker.thread().id();

        Ok(BotUpdatesSubscription {
            cancel: Some(cancel_tx),
            worker: Some(worker),
            worker_id,
        })
    }

    /// Answers a bot callback query using the bot-token REST API.
    pub fn answer_bot_callback_query(
        &self,
        token: impl AsRef<str>,
        input: AnswerBotCallbackQueryInput,
    ) -> Result<()> {
        let request = AnswerCallbackDispatch {
            token: token.as_ref().to_owned(),
            input,
        };
        let _: () = self.call_json(method_ids::BOT_ANSWER_CALLBACK_QUERY, &request)?;
        Ok(())
    }
}

#[derive(Serialize)]
struct AnswerCallbackDispatch {
    token: String,
    #[serde(flatten)]
    input: AnswerBotCallbackQueryInput,
}

#[derive(Deserialize)]
struct RawBotUpdate {
    update_id: i64,
    update_type: String,
    data: serde_json::Value,
    #[serde(default)]
    created_at: Option<i64>,
}

#[derive(Deserialize)]
struct BotUpdatesResponse {
    updates: Vec<RawBotUpdate>,
}

async fn poll_updates(
    client: reqwest::Client,
    endpoint: Url,
    token: String,
    options: BotUpdatesOptions,
    handler: Arc<dyn BotUpdateHandler>,
    mut cancel: oneshot::Receiver<()>,
) {
    let mut offset = options.offset;
    loop {
        let response = tokio::select! {
            biased;
            _ = &mut cancel => return,
            result = get_updates(&client, &endpoint, &token, offset, options) => match result {
                Ok(response) => response,
                Err(error) => {
                    notify_error(&handler, error);
                    return;
                }
            },
        };

        for raw_update in response.updates {
            let update_id = raw_update.update_id;
            let callback_result = match invoke_update(&handler, raw_update) {
                Ok(result) => result,
                Err(error) => {
                    notify_error(&handler, error);
                    return;
                }
            };
            if let Err(error) = callback_result {
                notify_error(
                    &handler,
                    BotApiError::local("callback_error", error.to_string()),
                );
                return;
            }

            offset = offset.max(update_id);
            if let Err(message) = invoke_offset(&handler, offset) {
                notify_error(&handler, BotApiError::local("callback_panic", message));
                return;
            }
        }
    }
}

async fn get_updates(
    client: &reqwest::Client,
    endpoint: &Url,
    token: &str,
    offset: i64,
    options: BotUpdatesOptions,
) -> std::result::Result<BotUpdatesResponse, BotApiError> {
    for attempt in 0..=1 {
        let response = client
            .get(endpoint.clone())
            .bearer_auth(token)
            .header(ACCEPT, "application/json")
            .query(&[
                ("offset", offset),
                ("limit", i64::from(options.limit)),
                ("timeout", i64::from(options.timeout_seconds)),
            ])
            .send()
            .await
            .map_err(|error| BotApiError::local("network", error.to_string()))?;

        if response.status().as_u16() == 429 && attempt == 0 {
            // Match the native shared HTTP policy: retry once, with a bounded
            // Retry-After delay. The outer cancellation select drops this
            // future during the wait when the subscription is cancelled.
            let wait = response
                .headers()
                .get("retry-after")
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse::<u64>().ok())
                .unwrap_or(5)
                .min(30);
            drop(response);
            tokio::time::sleep(Duration::from_secs(wait)).await;
            continue;
        }

        let status = response.status();
        let body = response
            .bytes()
            .await
            .map_err(|error| BotApiError::local("network", error.to_string()))?;
        if !status.is_success() {
            return Err(http_error(status.as_u16(), &body));
        }
        return serde_json::from_slice(&body)
            .map_err(|error| BotApiError::local("invalid_payload", error.to_string()));
    }
    Err(BotApiError::local(
        "rate_limited",
        "bot updates request remained rate limited after one retry",
    ))
}

fn invoke_update(
    handler: &Arc<dyn BotUpdateHandler>,
    update: RawBotUpdate,
) -> std::result::Result<Result<()>, BotApiError> {
    match update.update_type.as_str() {
        "message" => {
            let data = serde_json::from_value(update.data).map_err(|error| {
                BotApiError::local(
                    "invalid_payload",
                    format!("invalid message update payload: {error}"),
                )
            })?;
            let update = BotMessageUpdate {
                update_id: update.update_id,
                data,
                created_at: update.created_at,
            };
            catch_unwind(AssertUnwindSafe(|| handler.on_message(update)))
                .map_err(|_| BotApiError::local("callback_panic", "on_message callback panicked"))
        }
        "edited_message" => {
            let data = serde_json::from_value(update.data).map_err(|error| {
                BotApiError::local(
                    "invalid_payload",
                    format!("invalid edited_message update payload: {error}"),
                )
            })?;
            let update = BotEditedMessageUpdate {
                update_id: update.update_id,
                data,
                created_at: update.created_at,
            };
            catch_unwind(AssertUnwindSafe(|| handler.on_edited_message(update))).map_err(|_| {
                BotApiError::local("callback_panic", "on_edited_message callback panicked")
            })
        }
        "callback_query" => {
            let data = serde_json::from_value(update.data).map_err(|error| {
                BotApiError::local(
                    "invalid_payload",
                    format!("invalid callback_query update payload: {error}"),
                )
            })?;
            let update = BotCallbackQueryUpdate {
                update_id: update.update_id,
                data,
                created_at: update.created_at,
            };
            catch_unwind(AssertUnwindSafe(|| handler.on_callback_query(update))).map_err(|_| {
                BotApiError::local("callback_panic", "on_callback_query callback panicked")
            })
        }
        other => Err(BotApiError::local(
            "invalid_payload",
            format!("unsupported bot update type: {other}"),
        )),
    }
}

fn invoke_offset(
    handler: &Arc<dyn BotUpdateHandler>,
    offset: i64,
) -> std::result::Result<(), String> {
    catch_unwind(AssertUnwindSafe(|| handler.on_offset(offset)))
        .map_err(|_| "on_offset callback panicked".to_owned())
}

fn notify_error(handler: &Arc<dyn BotUpdateHandler>, error: BotApiError) {
    let _ = catch_unwind(AssertUnwindSafe(|| handler.on_error(error)));
}

fn http_error(status: u16, body: &[u8]) -> BotApiError {
    let parsed = serde_json::from_slice::<serde_json::Value>(body).ok();
    let code = parsed
        .as_ref()
        .and_then(|value| value.get("code"))
        .or_else(|| parsed.as_ref().and_then(|value| value.get("error")))
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned);
    let message = parsed
        .as_ref()
        .and_then(|value| value.get("message"))
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
        .unwrap_or_else(|| String::from_utf8_lossy(body).chars().take(1024).collect());
    BotApiError {
        status: Some(status),
        code,
        message,
    }
}

fn bot_api_url(api_base: &str) -> Result<Url> {
    let api_base = api_base.trim_end_matches('/');
    if api_base.is_empty() {
        return Err(Error::Config("api_base is empty".into()));
    }
    let root = api_base.strip_suffix("/api/v1").unwrap_or(api_base);
    let endpoint = format!("{root}/api/bot/v1/getUpdates");
    let url = Url::parse(&endpoint)
        .map_err(|error| Error::Config(format!("invalid bot API base URL: {error}")))?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(Error::Config("api_base is not a valid HTTP(S) URL".into()));
    }
    Ok(url)
}

fn validate_token(token: &str) -> Result<()> {
    if token.trim().is_empty()
        || token.trim() != token
        || token.chars().any(char::is_whitespace)
        || token.chars().any(char::is_control)
    {
        return Err(Error::InvalidPayload(
            "bot token must be non-empty and contain no control characters".into(),
        ));
    }
    Ok(())
}

async fn answer_callback_query(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    #[derive(Deserialize)]
    struct DispatchRequest {
        token: String,
        #[serde(flatten)]
        input: AnswerBotCallbackQueryInputOwned,
    }

    #[derive(Deserialize)]
    struct AnswerBotCallbackQueryInputOwned {
        callback_query_id: String,
        account_id: String,
        message_id: String,
        #[serde(default)]
        text: Option<String>,
        #[serde(default)]
        show_alert: Option<bool>,
    }

    let request: DispatchRequest = serde_json::from_slice(&payload)?;
    validate_token(&request.token)?;
    validate_required_identifier(&request.input.callback_query_id, "callback_query_id")?;
    validate_required_identifier(&request.input.account_id, "account_id")?;
    validate_required_identifier(&request.input.message_id, "message_id")?;
    if request
        .input
        .text
        .as_deref()
        .is_some_and(|text| text.chars().count() > MAX_CALLBACK_TEXT_CHARS)
    {
        return Err(Error::InvalidPayload(format!(
            "text must be at most {MAX_CALLBACK_TEXT_CHARS} characters"
        )));
    }

    #[derive(Serialize)]
    struct WireRequest<'a> {
        callback_query_id: &'a str,
        account_id: &'a str,
        message_id: &'a str,
        #[serde(skip_serializing_if = "Option::is_none")]
        text: Option<&'a str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        show_alert: Option<bool>,
    }

    let body = WireRequest {
        callback_query_id: &request.input.callback_query_id,
        account_id: &request.input.account_id,
        message_id: &request.input.message_id,
        text: request.input.text.as_deref(),
        show_alert: request.input.show_alert,
    };
    state
        .http
        .post_void(
            "/api/bot/v1/answerCallbackQuery",
            &body,
            Some(&request.token),
        )
        .await?;
    Ok(b"null".to_vec())
}

fn validate_required_identifier(value: &str, field: &str) -> Result<()> {
    if value.trim().is_empty()
        || value.trim() != value
        || value.chars().count() > 128
        || value.chars().any(char::is_control)
    {
        return Err(Error::InvalidPayload(format!(
            "{field} must be a non-empty identifier without control characters"
        )));
    }
    Ok(())
}

pub(crate) async fn dispatch_answer_callback_query(
    state: &Arc<ActorState>,
    payload: Vec<u8>,
) -> Result<Vec<u8>> {
    answer_callback_query(state, payload).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bot_api_url_replaces_frontend_api_v1_suffix() {
        let url = bot_api_url("https://api.example.test/api/v1/").unwrap();
        assert_eq!(
            url.as_str(),
            "https://api.example.test/api/bot/v1/getUpdates"
        );
    }

    #[test]
    fn bot_api_url_appends_bot_prefix_to_native_origin() {
        let url = bot_api_url("http://127.0.0.1:8080").unwrap();
        assert_eq!(url.as_str(), "http://127.0.0.1:8080/api/bot/v1/getUpdates");
    }

    #[test]
    fn bot_api_url_rejects_non_http_and_query_components() {
        assert!(bot_api_url("file:///tmp/api").is_err());
        assert!(bot_api_url("https://api.example.test?x=1").is_err());
    }

    #[test]
    fn options_match_backend_limits() {
        let options = BotUpdatesOptions {
            offset: -9,
            limit: 700,
            timeout_seconds: 90,
        };
        assert_eq!(options.offset.max(0), 0);
        assert_eq!(options.limit.clamp(1, 500), 500);
        assert_eq!(options.timeout_seconds.min(60), 60);
    }

    #[test]
    fn answer_body_omits_unspecified_optional_fields() {
        let input = AnswerBotCallbackQueryInput {
            callback_query_id: "callback".into(),
            account_id: "account".into(),
            message_id: "message".into(),
            text: None,
            show_alert: None,
        };
        let value = serde_json::to_value(input).unwrap();
        assert_eq!(
            value,
            serde_json::json!({
                "callback_query_id": "callback",
                "account_id": "account",
                "message_id": "message"
            })
        );
    }
}
