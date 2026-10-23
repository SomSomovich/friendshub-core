use friendshub_core::error::Error as CoreError;
use friendshub_core::transport::protobuf::{
    RestProtocol, finish_rest_response, format_rest_error_body, prepare_rest_request,
};
use js_sys::{ArrayBuffer, Date, Error as JsError, Reflect, Uint8Array};
use serde_json::Value;
use std::cell::Cell;
use std::rc::Rc;
use url::Url;
use wasm_bindgen::JsCast;
use wasm_bindgen::closure::Closure;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use web_sys::{
    AbortController, AbortSignal, Event, Headers, Request, RequestInit, Response, Window,
};

mod api;
mod calls;
mod push;
pub mod signal;
mod webrtc;
pub use api::BrowserApi;
pub use calls::BrowserCallManager;
pub use push::BrowserPushClient;
pub use signal::*;
pub use webrtc::BrowserRtcManager;

const DEFAULT_TIMEOUT_MS: u32 = 30_000;
const MAX_TIMEOUT_MS: u32 = 2_147_483_647;
/// Browser-side HTTP client. Rust owns the request policy and protobuf codec;
/// Fetch and browser-owned request bodies remain in the browser runtime.
#[wasm_bindgen]
pub struct BrowserRestClient {
    origin: String,
    api_base: String,
    device_number: Option<u32>,
    timeout_ms: u32,
}

#[wasm_bindgen]
impl BrowserRestClient {
    #[wasm_bindgen(constructor)]
    pub fn new(api_base: String) -> Result<BrowserRestClient, JsValue> {
        let normalized = normalize_api_base(&api_base).map_err(|error| error.into_js())?;
        Ok(Self {
            origin: normalized.origin,
            api_base: normalized.api_base,
            device_number: None,
            timeout_ms: DEFAULT_TIMEOUT_MS,
        })
    }

    /// Sets the session's `X-Device-Number`. Pass null/undefined to omit it,
    /// which is required for endpoints such as login before device creation.
    pub fn set_device_number(&mut self, device_number: Option<u32>) {
        self.device_number = device_number;
    }

    /// Sets Fetch's total deadline, including response body download.
    pub fn set_timeout_ms(&mut self, timeout_ms: u32) -> Result<(), JsValue> {
        if timeout_ms == 0 || timeout_ms > MAX_TIMEOUT_MS {
            return Err(RestError::new(
                "invalid_request",
                0,
                "timeout_ms must be between 1 and 2147483647".into(),
                String::new(),
            )
            .into_js());
        }
        self.timeout_ms = timeout_ms;
        Ok(())
    }

    /// Sends a JSON/protobuf/bodyless REST request.
    ///
    /// `path` accepts the full `/api/v1/...` routes used by the web client,
    /// `/health`, bot JSON routes, or an absolute HTTP(S) URL for storage.
    /// `response_type` is `"json"` (default) or `"bytes"`.
    pub async fn request(
        &self,
        method: String,
        path: String,
        body: Option<JsValue>,
        bearer: Option<String>,
        signal: Option<AbortSignal>,
        response_type: Option<String>,
    ) -> Result<JsValue, JsValue> {
        self.request_with_options_inner(
            method,
            path,
            body,
            bearer,
            signal,
            response_type,
            Vec::new(),
            true,
        )
        .await
    }

    /// Sends a raw browser `BodyInit` to a route registered as a raw upload.
    /// Passing a Blob lets Fetch stream browser-owned file data without first
    /// copying the entire file into Rust's linear memory.
    pub async fn request_raw(
        &self,
        method: String,
        path: String,
        raw_body: JsValue,
        content_type: Option<String>,
        bearer: Option<String>,
        signal: Option<AbortSignal>,
        response_type: Option<String>,
    ) -> Result<JsValue, JsValue> {
        let method = validate_method(&method).map_err(|error| error.into_js())?;
        validate_response_type(response_type.as_deref()).map_err(|error| error.into_js())?;
        if raw_body.is_null() || raw_body.is_undefined() {
            return Err(RestError::new(
                "invalid_request",
                0,
                "raw request body must not be null or undefined".into(),
                String::new(),
            )
            .into_js());
        }
        let url = self.request_url(&path).map_err(|error| error.into_js())?;
        let attach_session_headers = should_attach_session_headers(&path);
        let codec_origin = self.codec_origin().unwrap_or_default();
        let codec_path = route_path_for_codec(&url, &codec_origin).map_err(|e| e.into_js())?;
        let inferred_content_type = if content_type.is_none() {
            raw_body
                .clone()
                .dyn_into::<web_sys::Blob>()
                .ok()
                .map(|blob| blob.type_())
                .filter(|value| !value.is_empty())
        } else {
            None
        };
        let effective_content_type = content_type
            .as_deref()
            .or(inferred_content_type.as_deref())
            .or(Some("application/octet-stream"));
        let prepared = prepare_rest_request(
            method,
            &codec_path,
            None,
            Some(Vec::new()),
            effective_content_type,
        )
        .map_err(request_core_error_to_js)?;
        let absolute_url = is_absolute_http_url(&path);
        if !matches!(prepared.protocol, RestProtocol::Protobuf) && !absolute_url {
            return Err(RestError::new(
                "invalid_request",
                0,
                "request_raw requires a route registered for raw upload or a non-protobuf JSON URL"
                    .into(),
                String::new(),
            )
            .into_js());
        }
        let prepared_content_type = prepared.content_type;
        let bearer = bearer.filter(|_| attach_session_headers);
        self.execute(
            method,
            &url,
            &codec_path,
            prepared.protocol,
            prepared.accept,
            prepared_content_type,
            Some(raw_body),
            bearer.as_deref(),
            signal,
            response_type.as_deref(),
            &[],
            attach_session_headers,
        )
        .await
    }
}

impl BrowserRestClient {
    /// Sends a REST request with operation-specific headers and device-header
    /// policy. Used by the typed API facade for WEB endpoints that set
    /// `Idempotency-Key` or deliberately omit `X-Device-Number`.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn request_with_options(
        &self,
        method: String,
        path: String,
        body: Option<JsValue>,
        bearer: Option<String>,
        signal: Option<AbortSignal>,
        response_type: Option<String>,
        extra_headers: Vec<(String, String)>,
        include_device_number: bool,
    ) -> Result<JsValue, JsValue> {
        self.request_with_options_inner(
            method,
            path,
            body,
            bearer,
            signal,
            response_type,
            extra_headers,
            include_device_number,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn request_with_options_inner(
        &self,
        method: String,
        path: String,
        body: Option<JsValue>,
        bearer: Option<String>,
        signal: Option<AbortSignal>,
        response_type: Option<String>,
        extra_headers: Vec<(String, String)>,
        include_device_number: bool,
    ) -> Result<JsValue, JsValue> {
        let method = validate_method(&method).map_err(|error| error.into_js())?;
        validate_response_type(response_type.as_deref()).map_err(|error| error.into_js())?;
        let url = self.request_url(&path).map_err(|error| error.into_js())?;
        let attach_session_headers = should_attach_session_headers(&path);
        let codec_origin = self.codec_origin().unwrap_or_default();
        let codec_path = route_path_for_codec(&url, &codec_origin).map_err(|e| e.into_js())?;
        let body = body
            .filter(|value| !value.is_undefined())
            .map(js_value_to_json)
            .transpose()
            .map_err(|error: RestError| {
                RestError::new(
                    "invalid_payload",
                    0,
                    format!("request body is not JSON-compatible: {}", error.message),
                    String::new(),
                )
                .into_js()
            })?;
        let prepared = prepare_rest_request(method, &codec_path, body, None, None)
            .map_err(request_core_error_to_js)?;
        let bearer = bearer.filter(|_| attach_session_headers);
        let extra_headers = if attach_session_headers {
            extra_headers
        } else {
            Vec::new()
        };
        self.execute(
            method,
            &url,
            &codec_path,
            prepared.protocol,
            prepared.accept,
            prepared.content_type,
            prepared.body.map(bytes_to_js_body),
            bearer.as_deref(),
            signal,
            response_type.as_deref(),
            &extra_headers,
            include_device_number && attach_session_headers,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn execute(
        &self,
        method: &'static str,
        url: &str,
        codec_path: &str,
        protocol: RestProtocol,
        accept: Option<&'static str>,
        content_type: Option<String>,
        body: Option<JsValue>,
        bearer: Option<&str>,
        external_signal: Option<AbortSignal>,
        response_type: Option<&str>,
        extra_headers: &[(String, String)],
        include_device_number: bool,
    ) -> Result<JsValue, JsValue> {
        let window = web_sys::window().ok_or_else(|| {
            RestError::new(
                "runtime",
                0,
                "browser window is unavailable".into(),
                String::new(),
            )
            .into_js()
        })?;
        let headers = Headers::new()
            .map_err(|error| js_runtime_error("failed to create request headers", error))?;
        if let Some(value) = accept {
            headers
                .set("Accept", value)
                .map_err(|error| js_runtime_error("invalid Accept header", error))?;
        }
        if let Some(value) = content_type.as_deref() {
            headers
                .set("Content-Type", value)
                .map_err(|error| js_runtime_error("invalid Content-Type header", error))?;
        }
        for (name, value) in extra_headers {
            headers
                .set(name, value)
                .map_err(|error| js_runtime_error("invalid request header", error))?;
        }
        if let Some(token) = bearer {
            if url_matches_api_origin(url, &self.origin, &window) {
                headers
                    .set("Authorization", &format!("Bearer {token}"))
                    .map_err(|error| js_runtime_error("invalid Authorization header", error))?;
            }
        }
        if include_device_number {
            if let Some(device_number) = self
                .device_number
                .filter(|_| url_matches_api_origin(url, &self.origin, &window))
            {
                headers
                    .set("X-Device-Number", &device_number.to_string())
                    .map_err(|error| js_runtime_error("invalid device number header", error))?;
            }
        }

        let controller = AbortController::new().map_err(|error| {
            js_runtime_error("failed to create request abort controller", error)
        })?;
        let timeout_fired = Rc::new(Cell::new(false));
        let timeout_flag = Rc::clone(&timeout_fired);
        let timeout_controller = controller.clone();
        let timeout_callback = Closure::wrap(Box::new(move || {
            timeout_flag.set(true);
            timeout_controller.abort();
        }) as Box<dyn FnMut()>);
        let timeout_handle = window
            .set_timeout_with_callback_and_timeout_and_arguments_0(
                timeout_callback.as_ref().unchecked_ref(),
                self.timeout_ms as i32,
            )
            .map_err(|error| js_runtime_error("failed to install request timeout", error))?;

        let mut external_abort_callback: Option<Closure<dyn FnMut(Event)>> = None;
        if let Some(signal) = external_signal.as_ref() {
            if signal.aborted() {
                controller.abort();
            } else {
                let external_controller = controller.clone();
                let callback = Closure::wrap(Box::new(move |_event: Event| {
                    external_controller.abort();
                }) as Box<dyn FnMut(Event)>);
                if let Err(error) = signal
                    .add_event_listener_with_callback("abort", callback.as_ref().unchecked_ref())
                {
                    window.clear_timeout_with_handle(timeout_handle);
                    return Err(js_runtime_error("failed to attach AbortSignal", error));
                }
                external_abort_callback = Some(callback);
            }
        }

        let request_result = async {
            let init = RequestInit::new();
            init.set_method(method);
            init.set_headers_headers(&headers);
            init.set_signal(Some(&controller.signal()));
            if let Some(body) = body.as_ref() {
                init.set_body(body);
            }
            let request = Request::new_with_str_and_init(url, &init)
                .map_err(|error| js_runtime_error("invalid Fetch request", error))?;
            let response = JsFuture::from(window.fetch_with_request(&request))
                .await
                .map_err(|error| {
                    let code = if timeout_fired.get() {
                        "timeout"
                    } else {
                        "network"
                    };
                    RestError::new(
                        code,
                        0,
                        format!("{method} {url} failed: {}", describe_js_error(&error)),
                        String::new(),
                    )
                    .into_js()
                })?
                .dyn_into::<Response>()
                .map_err(|_| {
                    RestError::new(
                        "network",
                        0,
                        "Fetch returned a non-Response value".into(),
                        String::new(),
                    )
                    .into_js()
                })?;
            let status = response.status();
            let status_text = response.status_text();
            let retry_after = response.headers().get("Retry-After").ok().flatten();
            let bytes = JsFuture::from(response.array_buffer().map_err(|error| {
                RestError::new(
                    "network",
                    0,
                    format!(
                        "failed to read {method} {url} response: {}",
                        describe_js_error(&error)
                    ),
                    String::new(),
                )
                .into_js()
            })?)
            .await
            .map_err(|error| {
                let code = if timeout_fired.get() {
                    "timeout"
                } else {
                    "network"
                };
                RestError::new(
                    code,
                    0,
                    format!(
                        "failed to read {method} {url} response: {}",
                        describe_js_error(&error)
                    ),
                    String::new(),
                )
                .into_js()
            })?
            .dyn_into::<ArrayBuffer>()
            .map_err(|_| {
                RestError::new(
                    "network",
                    0,
                    "Fetch response body was not an ArrayBuffer".into(),
                    String::new(),
                )
                .into_js()
            })?;
            Ok::<_, JsValue>((status, status_text, retry_after, bytes))
        }
        .await;

        window.clear_timeout_with_handle(timeout_handle);
        drop(timeout_callback);
        if let (Some(signal), Some(callback)) = (external_signal.as_ref(), external_abort_callback)
        {
            let _ = signal
                .remove_event_listener_with_callback("abort", callback.as_ref().unchecked_ref());
            drop(callback);
        }

        let (status, status_text, retry_after, response_buffer) = request_result?;
        if (200..300).contains(&status)
            && (response_type == Some("bytes")
                || matches!(protocol, RestProtocol::RawProtobufErrors))
        {
            return Ok(Uint8Array::new(&response_buffer).into());
        }
        let bytes = Uint8Array::new(&response_buffer).to_vec();
        if !(200..300).contains(&status) {
            let decoded = match finish_rest_response(method, codec_path, status, &bytes) {
                Err(CoreError::Server { status, body }) => (status, body),
                Err(_) | Ok(_) => (status, format_rest_error_body(method, codec_path, &bytes)),
            };
            let fallback_message = if status_text.is_empty() {
                format!("HTTP {status}")
            } else {
                status_text
            };
            let retry_after_ms = retry_after
                .as_deref()
                .and_then(|value| parse_retry_after_ms(value, Date::now()));
            return Err(
                http_error(decoded.0, decoded.1, Some(fallback_message), retry_after_ms).into_js(),
            );
        }

        let decoded = finish_rest_response(method, codec_path, status, &bytes)
            .map_err(response_core_error_to_js)?;
        if decoded.is_empty() {
            return Ok(JsValue::NULL);
        }
        let mut value: Value = serde_json::from_slice(&decoded).map_err(|error| {
            RestError::new(
                "invalid_payload",
                status,
                format!("response JSON decode failed: {error}"),
                String::from_utf8_lossy(&decoded).into_owned(),
            )
            .into_js()
        })?;
        if matches!(protocol, RestProtocol::Protobuf) {
            value = protobuf_json_to_web_camel_case(value);
        }
        json_to_js_value(&value).map_err(|error| {
            RestError::new("invalid_payload", status, error.message, String::new()).into_js()
        })
    }

    fn request_url(&self, path: &str) -> Result<String, RestError> {
        if path.trim().is_empty() {
            return Err(RestError::new(
                "invalid_request",
                0,
                "request path is empty".into(),
                String::new(),
            ));
        }
        if path.starts_with("//") {
            return Err(RestError::new(
                "invalid_request",
                0,
                "protocol-relative request URLs are not allowed".into(),
                String::new(),
            ));
        }
        if has_absolute_url_scheme(path) {
            let parsed = Url::parse(path).map_err(|error| {
                RestError::new(
                    "invalid_request",
                    0,
                    format!("invalid absolute request URL: {error}"),
                    String::new(),
                )
            })?;
            if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none() {
                return Err(RestError::new(
                    "invalid_request",
                    0,
                    "absolute request URL must use HTTP(S)".into(),
                    String::new(),
                ));
            }
            if parsed.fragment().is_some() {
                return Err(RestError::new(
                    "invalid_request",
                    0,
                    "request URLs must not contain fragments".into(),
                    String::new(),
                ));
            }
            return Ok(parsed.to_string());
        }
        if path.contains('#') {
            return Err(RestError::new(
                "invalid_request",
                0,
                "request paths must not contain URL fragments".into(),
                String::new(),
            ));
        }
        let path = if path.starts_with('/') {
            path.to_owned()
        } else {
            format!("/{path}")
        };
        if path == "/health" {
            return Ok(format!("{}{path}", self.origin));
        }
        if path.starts_with("/api/") {
            return Ok(format!("{}{path}", self.origin));
        }
        Ok(format!("{}{path}", self.api_base))
    }

    fn codec_origin(&self) -> Option<String> {
        if !self.origin.is_empty() {
            return Some(self.origin.clone());
        }
        web_sys::window()?.location().origin().ok()
    }
}

struct NormalizedBase {
    origin: String,
    api_base: String,
}

fn normalize_api_base(api_base: &str) -> Result<NormalizedBase, RestError> {
    let base = api_base.trim().trim_end_matches('/');
    if base.is_empty() {
        return Ok(NormalizedBase {
            origin: String::new(),
            api_base: "/api/v1".into(),
        });
    }
    if base.starts_with('/') {
        let path = base.trim_end_matches('/');
        if path.is_empty() || path == "/api/v1" {
            return Ok(NormalizedBase {
                origin: String::new(),
                api_base: "/api/v1".into(),
            });
        }
        return Err(RestError::new(
            "invalid_request",
            0,
            "relative API base must be /api/v1".into(),
            String::new(),
        ));
    }
    let mut parsed = Url::parse(base).map_err(|error| {
        RestError::new(
            "invalid_request",
            0,
            format!("API base must be an origin or end in /api/v1: {error}"),
            String::new(),
        )
    })?;
    if !matches!(parsed.scheme(), "http" | "https")
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || !matches!(parsed.path(), "/" | "/api/v1")
    {
        return Err(RestError::new(
            "invalid_request",
            0,
            "API base must be an HTTP(S) origin or that origin followed by /api/v1".into(),
            String::new(),
        ));
    }
    let origin = parsed.origin().ascii_serialization();
    parsed.set_path("/api/v1");
    parsed.set_query(None);
    parsed.set_fragment(None);
    Ok(NormalizedBase {
        origin,
        api_base: parsed.to_string().trim_end_matches('/').to_owned(),
    })
}

fn route_path_for_codec(url: &str, origin: &str) -> Result<String, RestError> {
    let absolute = if url.starts_with('/') {
        format!("https://friendshub.invalid{url}")
    } else {
        url.to_owned()
    };
    let parsed = Url::parse(&absolute).map_err(|error| {
        RestError::new(
            "invalid_request",
            0,
            format!("unable to determine REST route path: {error}"),
            String::new(),
        )
    })?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(RestError::new(
            "invalid_request",
            0,
            "request URL must use HTTP(S)".into(),
            String::new(),
        ));
    }
    if !origin.is_empty() && parsed.origin().ascii_serialization() != origin {
        return Ok(url.to_owned());
    }
    Ok(format!(
        "{}{}",
        parsed.path(),
        parsed.query().map(|q| format!("?{q}")).unwrap_or_default()
    ))
}

fn is_absolute_http_url(value: &str) -> bool {
    has_absolute_url_scheme(value)
        && Url::parse(value).is_ok_and(|url| matches!(url.scheme(), "http" | "https"))
}

/// Absolute URLs may be presigned storage capabilities. They never receive
/// FriendsHub session credentials, even if storage shares the API origin.
fn should_attach_session_headers(path: &str) -> bool {
    !is_absolute_http_url(path)
}

fn has_absolute_url_scheme(value: &str) -> bool {
    let Some((scheme, _)) = value.split_once("://") else {
        return false;
    };
    let mut characters = scheme.chars();
    characters
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic())
        && characters.all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '+' | '.' | '-')
        })
}

fn url_matches_api_origin(url: &str, origin: &str, window: &Window) -> bool {
    let page_origin = if origin.is_empty() {
        window.location().origin().ok()
    } else {
        None
    };
    is_same_origin_request(url, origin, page_origin.as_deref())
}

fn is_same_origin_request(url: &str, api_origin: &str, page_origin: Option<&str>) -> bool {
    if url.starts_with('/') {
        return true;
    }
    let Ok(parsed) = Url::parse(url) else {
        return false;
    };
    let expected_origin = if api_origin.is_empty() {
        page_origin.unwrap_or_default()
    } else {
        api_origin
    };
    !expected_origin.is_empty() && parsed.origin().ascii_serialization() == expected_origin
}

fn validate_method(method: &str) -> Result<&'static str, RestError> {
    match method {
        "GET" => Ok("GET"),
        "HEAD" => Ok("HEAD"),
        "POST" => Ok("POST"),
        "PUT" => Ok("PUT"),
        "PATCH" => Ok("PATCH"),
        "DELETE" => Ok("DELETE"),
        _ => Err(RestError::new(
            "invalid_request",
            0,
            format!("unsupported HTTP method: {method}"),
            String::new(),
        )),
    }
}

fn validate_response_type(response_type: Option<&str>) -> Result<(), RestError> {
    match response_type {
        None | Some("json") | Some("bytes") => Ok(()),
        Some(other) => Err(RestError::new(
            "invalid_request",
            0,
            format!("unsupported response_type: {other}"),
            String::new(),
        )),
    }
}

fn bytes_to_js_body(bytes: Vec<u8>) -> JsValue {
    Uint8Array::from(bytes.as_slice()).into()
}

fn js_value_to_json(value: JsValue) -> Result<Value, RestError> {
    let json = js_sys::JSON::stringify(&value)
        .map_err(|error| {
            RestError::new(
                "invalid_payload",
                0,
                format!(
                    "request body is not JSON-compatible: {}",
                    describe_js_error(&error)
                ),
                String::new(),
            )
        })?
        .as_string()
        .ok_or_else(|| {
            RestError::new(
                "invalid_payload",
                0,
                "request body is not JSON-compatible".into(),
                String::new(),
            )
        })?;
    serde_json::from_str(&json).map_err(|error| {
        RestError::new(
            "invalid_payload",
            0,
            format!("request body is not JSON-compatible: {error}"),
            String::new(),
        )
    })
}

fn json_to_js_value(value: &Value) -> Result<JsValue, RestError> {
    let json = serde_json::to_string(value).map_err(|error| {
        RestError::new(
            "invalid_payload",
            0,
            format!("response conversion failed: {error}"),
            String::new(),
        )
    })?;
    js_sys::JSON::parse(&json).map_err(|error| {
        RestError::new(
            "invalid_payload",
            0,
            format!("response conversion failed: {}", describe_js_error(&error)),
            String::new(),
        )
    })
}

/// Native REST DTOs retain Rust's snake_case JSON keys after the shared
/// protobuf decoder. The browser API follows the WEB client's camelCase
/// contract, so only protobuf route results cross this key conversion.
fn protobuf_json_to_web_camel_case(value: Value) -> Value {
    match value {
        Value::Object(object) => Value::Object(
            object
                .into_iter()
                .map(|(key, value)| {
                    (
                        snake_case_to_camel_case(&key),
                        protobuf_json_to_web_camel_case(value),
                    )
                })
                .collect(),
        ),
        Value::Array(values) => Value::Array(
            values
                .into_iter()
                .map(protobuf_json_to_web_camel_case)
                .collect(),
        ),
        other => other,
    }
}

fn snake_case_to_camel_case(key: &str) -> String {
    let mut result = String::with_capacity(key.len());
    let mut uppercase_next = false;
    for character in key.chars() {
        if character == '_' {
            uppercase_next = true;
        } else if uppercase_next {
            result.extend(character.to_uppercase());
            uppercase_next = false;
        } else {
            result.push(character);
        }
    }
    result
}

fn request_core_error_to_js(error: CoreError) -> JsValue {
    match error {
        CoreError::Server { status, body } => RestError::new(
            "server",
            status,
            format!("server returned HTTP {status}"),
            body,
        )
        .into_js(),
        CoreError::InvalidPayload(message) => {
            RestError::new("invalid_request", 0, message, String::new()).into_js()
        }
        CoreError::Network(message) => {
            RestError::new("network", 0, message, String::new()).into_js()
        }
        other => RestError::new("core", 0, other.to_string(), String::new()).into_js(),
    }
}

fn response_core_error_to_js(error: CoreError) -> JsValue {
    match error {
        CoreError::Server { status, body } => http_error(status, body, None, None).into_js(),
        CoreError::InvalidPayload(message) => {
            RestError::new("invalid_response", 0, message, String::new()).into_js()
        }
        CoreError::Network(message) => {
            RestError::new("network", 0, message, String::new()).into_js()
        }
        other => RestError::new("core", 0, other.to_string(), String::new()).into_js(),
    }
}

fn http_error(
    status: u16,
    body: String,
    fallback_message: Option<String>,
    retry_after_ms: Option<f64>,
) -> RestError {
    let mut error = RestError::new(
        "http_error",
        status,
        fallback_message.unwrap_or_else(|| format!("HTTP {status}")),
        body.clone(),
    );
    error.retry_after_ms = retry_after_ms;
    error.retry_after_seconds = retry_after_ms.map(|milliseconds| (milliseconds / 1000.0).ceil());
    if body.is_empty() {
        return error;
    }
    match serde_json::from_str::<Value>(&body) {
        Ok(Value::Object(object)) => {
            if let Some(code) = object.get("error").and_then(Value::as_str) {
                error.code = code.to_owned();
            }
            if let Some(message) = object.get("message").and_then(Value::as_str) {
                error.message = message.to_owned();
            }
            let contains_error_code = object.contains_key("error");
            error.details = object
                .get("details")
                .cloned()
                .or_else(|| (!contains_error_code).then_some(Value::Object(object)));
        }
        Ok(_) => {}
        Err(_) => {
            error.details = Some(Value::String(body.chars().take(500).collect()));
        }
    }
    error
}

fn parse_retry_after_ms(value: &str, now_ms: f64) -> Option<f64> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    if let Ok(seconds) = value.parse::<f64>() {
        return (seconds.is_finite() && seconds >= 0.0).then(|| (seconds * 1000.0).ceil());
    }
    let date_ms = Date::parse(value);
    date_ms.is_finite().then(|| (date_ms - now_ms).max(0.0))
}

fn js_runtime_error(context: &str, cause: JsValue) -> JsValue {
    RestError::new(
        "runtime",
        0,
        format!("{context}: {}", describe_js_error(&cause)),
        String::new(),
    )
    .into_js()
}

fn describe_js_error(error: &JsValue) -> String {
    if let Some(message) = error.as_string() {
        return message;
    }
    Reflect::get(error, &JsValue::from_str("message"))
        .ok()
        .and_then(|message| message.as_string())
        .filter(|message| !message.is_empty())
        .unwrap_or_else(|| format!("{error:?}"))
}

#[derive(Debug)]
struct RestError {
    code: String,
    status: u16,
    message: String,
    body: String,
    details: Option<Value>,
    retry_after_ms: Option<f64>,
    retry_after_seconds: Option<f64>,
}

impl RestError {
    fn new(code: impl Into<String>, status: u16, message: String, body: String) -> Self {
        Self {
            code: code.into(),
            status,
            message,
            body,
            details: None,
            retry_after_ms: None,
            retry_after_seconds: None,
        }
    }

    fn into_js(self) -> JsValue {
        let error = JsError::new(&self.message);
        let object = error.as_ref();
        let _ = Reflect::set(
            object,
            &JsValue::from_str("name"),
            &JsValue::from_str("ApiError"),
        );
        let _ = Reflect::set(
            object,
            &JsValue::from_str("code"),
            &JsValue::from_str(&self.code),
        );
        let _ = Reflect::set(
            object,
            &JsValue::from_str("status"),
            &JsValue::from_f64(self.status as f64),
        );
        let _ = Reflect::set(
            object,
            &JsValue::from_str("body"),
            &JsValue::from_str(&self.body),
        );
        let details = self
            .details
            .as_ref()
            .and_then(|details| json_to_js_value(details).ok())
            .unwrap_or(JsValue::NULL);
        let _ = Reflect::set(object, &JsValue::from_str("details"), &details);
        let _ = Reflect::set(
            object,
            &JsValue::from_str("isTransportFailure"),
            &JsValue::from_bool(self.status == 0),
        );
        let retry_after_ms = self
            .retry_after_ms
            .map(JsValue::from_f64)
            .unwrap_or(JsValue::NULL);
        let retry_after_seconds = self
            .retry_after_seconds
            .map(JsValue::from_f64)
            .unwrap_or(JsValue::NULL);
        let _ = Reflect::set(object, &JsValue::from_str("retryAfterMs"), &retry_after_ms);
        let _ = Reflect::set(
            object,
            &JsValue::from_str("retryAfterSeconds"),
            &retry_after_seconds,
        );
        error.into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_base_accepts_origin_or_api_v1_url() {
        let origin = normalize_api_base("https://api.example.test").unwrap();
        assert_eq!(origin.origin, "https://api.example.test");
        assert_eq!(origin.api_base, "https://api.example.test/api/v1");

        let api = normalize_api_base("https://api.example.test/api/v1/").unwrap();
        assert_eq!(api.origin, "https://api.example.test");
        assert_eq!(api.api_base, "https://api.example.test/api/v1");
    }

    #[test]
    fn relative_api_base_supports_same_origin_dev_proxy() {
        let base = normalize_api_base("/api/v1/").unwrap();
        assert_eq!(base.origin, "");
        assert_eq!(base.api_base, "/api/v1");
    }

    #[test]
    fn api_base_rejects_other_paths_credentials_and_non_http_schemes() {
        for invalid in [
            "https://api.example.test/proxy",
            "https://user:secret@api.example.test",
            "ftp://api.example.test",
            "https://api.example.test/api/v1?x=1",
        ] {
            assert!(normalize_api_base(invalid).is_err(), "accepted {invalid}");
        }
    }

    #[test]
    fn absolute_and_api_paths_keep_their_route_and_health_is_root_mounted() {
        let base = normalize_api_base("https://api.example.test/api/v1").unwrap();
        let client = BrowserRestClient {
            origin: base.origin,
            api_base: base.api_base,
            device_number: None,
            timeout_ms: DEFAULT_TIMEOUT_MS,
        };
        assert_eq!(
            client.request_url("/api/v1/register").unwrap(),
            "https://api.example.test/api/v1/register"
        );
        assert_eq!(
            client.request_url("/health").unwrap(),
            "https://api.example.test/health"
        );
        assert_eq!(
            client.request_url("/api/bot/v1/messages?offset=2").unwrap(),
            "https://api.example.test/api/bot/v1/messages?offset=2"
        );
        assert_eq!(
            client
                .request_url("https://storage.example.test/object")
                .unwrap(),
            "https://storage.example.test/object"
        );
    }

    #[test]
    fn same_origin_urls_and_relative_api_paths_are_stable() {
        let base = normalize_api_base("/api/v1").unwrap();
        let client = BrowserRestClient {
            origin: base.origin,
            api_base: base.api_base,
            device_number: None,
            timeout_ms: DEFAULT_TIMEOUT_MS,
        };
        assert_eq!(client.request_url("/api/v1/me").unwrap(), "/api/v1/me");
        assert_eq!(client.request_url("/health").unwrap(), "/health");
        assert_eq!(client.request_url("/contacts").unwrap(), "/api/v1/contacts");
    }

    #[test]
    fn request_path_validation_blocks_fragments_and_protocol_relative_urls() {
        let base = normalize_api_base("https://api.example.test").unwrap();
        let client = BrowserRestClient {
            origin: base.origin,
            api_base: base.api_base,
            device_number: None,
            timeout_ms: DEFAULT_TIMEOUT_MS,
        };
        assert!(client.request_url("//evil.example/x").is_err());
        assert!(client.request_url("/api/v1/me#fragment").is_err());
    }

    #[test]
    fn method_allowlist_matches_web_client_methods() {
        for method in ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"] {
            assert_eq!(validate_method(method).unwrap(), method);
        }
        assert!(validate_method("TRACE").is_err());
        assert!(validate_method("get").is_err());
    }

    #[test]
    fn codec_path_drops_origin_but_preserves_query() {
        assert_eq!(
            route_path_for_codec(
                "https://api.example.test/api/v1/contacts?q=alex",
                "https://api.example.test"
            )
            .unwrap(),
            "/api/v1/contacts?q=alex"
        );
    }

    #[test]
    fn codec_keeps_cross_origin_urls_outside_the_first_party_route_table() {
        assert_eq!(
            route_path_for_codec(
                "https://storage.example.test/api/v1/object?signature=x",
                "https://api.example.test"
            )
            .unwrap(),
            "https://storage.example.test/api/v1/object?signature=x"
        );
        let storage_path = route_path_for_codec(
            "https://storage.example.test/api/v1/object?signature=x",
            "https://api.example.test",
        )
        .unwrap();
        let raw = prepare_rest_request(
            "PUT",
            &storage_path,
            None,
            Some(vec![1, 2, 3]),
            Some("application/octet-stream"),
        )
        .unwrap();
        assert_eq!(raw.protocol, RestProtocol::Json);
        assert_eq!(raw.body.as_deref(), Some(&[1, 2, 3][..]));
        assert!(is_absolute_http_url("HTTPS://storage.example.test/file"));
        assert!(!is_absolute_http_url("/api/v1/me"));
    }

    #[test]
    fn auth_policy_allows_api_and_same_page_urls_but_rejects_storage_origin() {
        let api_origin = "https://api.example.test";
        let page_origin = "https://web.example.test";

        assert!(is_same_origin_request(
            "https://api.example.test/api/v1/me",
            api_origin,
            None
        ));
        assert!(!is_same_origin_request(
            "https://storage.example.test/upload/api/v1/object",
            api_origin,
            None
        ));
        assert!(is_same_origin_request(
            "https://web.example.test/api/v1/me",
            "",
            Some(page_origin)
        ));
        assert!(!is_same_origin_request(
            "https://storage.example.test/upload",
            "",
            Some(page_origin)
        ));
        assert!(is_same_origin_request("/api/v1/me", "", Some(page_origin)));
    }

    #[test]
    fn absolute_presigned_urls_never_receive_session_headers() {
        assert!(!should_attach_session_headers(
            "https://api.example.test/storage/object?signature=x"
        ));
        assert!(!should_attach_session_headers(
            "https://storage.example.test/object?signature=x"
        ));
        assert!(should_attach_session_headers("/api/v1/attachments/init"));
    }

    #[test]
    fn http_error_matches_web_api_error_shape() {
        let error = http_error(
            429,
            r#"{"error":"rate_limited","message":"slow down","details":{"retry_after":3}}"#.into(),
            None,
            Some(2500.0),
        );
        assert_eq!(error.status, 429);
        assert_eq!(error.code, "rate_limited");
        assert_eq!(error.message, "slow down");
        assert_eq!(error.details, Some(serde_json::json!({"retry_after": 3})));
        assert_eq!(error.retry_after_ms, Some(2500.0));
        assert_eq!(error.retry_after_seconds, Some(3.0));

        let plain_text = http_error(502, "gateway unavailable".into(), None, None);
        assert_eq!(plain_text.code, "http_error");
        assert_eq!(
            plain_text.details,
            Some(Value::String("gateway unavailable".into()))
        );
    }

    #[test]
    fn numeric_retry_after_is_converted_to_milliseconds() {
        assert_eq!(parse_retry_after_ms("1.25", 10_000.0), Some(1250.0));
        assert_eq!(parse_retry_after_ms("0", 10_000.0), Some(0.0));
        assert_eq!(parse_retry_after_ms("-1", 10_000.0), None);
    }

    #[test]
    fn shared_route_codec_covers_protobuf_json_and_raw_uploads() {
        let protobuf = prepare_rest_request(
            "POST",
            "/api/v1/register",
            Some(serde_json::json!({"password": "secret"})),
            None,
            None,
        )
        .unwrap();
        assert_eq!(protobuf.protocol, RestProtocol::Protobuf);
        assert_eq!(protobuf.accept, Some("application/x-protobuf"));
        assert_eq!(
            protobuf.content_type.as_deref(),
            Some("application/x-protobuf")
        );
        assert!(protobuf.body.is_some());

        let json = prepare_rest_request(
            "POST",
            "/api/bot/v1/answerCallbackQuery",
            Some(serde_json::json!({"callback_query_id": "callback"})),
            None,
            None,
        )
        .unwrap();
        assert_eq!(json.protocol, RestProtocol::Json);
        assert_eq!(json.content_type.as_deref(), Some("application/json"));
        assert_eq!(
            serde_json::from_slice::<Value>(json.body.as_deref().unwrap()).unwrap(),
            serde_json::json!({"callback_query_id": "callback"})
        );

        let raw = prepare_rest_request(
            "POST",
            "/api/v1/avatars/me",
            None,
            Some(Vec::new()),
            Some("image/webp"),
        )
        .unwrap();
        assert_eq!(raw.protocol, RestProtocol::Protobuf);
        assert_eq!(raw.content_type.as_deref(), Some("image/webp"));
    }

    #[test]
    fn shared_response_codec_keeps_typed_http_error_status_and_body() {
        let body = br#"{"error":"rate_limited","message":"slow down"}"#;
        let error =
            finish_rest_response("POST", "/api/bot/v1/answerCallbackQuery", 429, body).unwrap_err();
        match error {
            CoreError::Server { status, body: text } => {
                assert_eq!(status, 429);
                assert_eq!(text, String::from_utf8_lossy(body));
            }
            other => panic!("expected typed HTTP server error, got {other:?}"),
        }
    }

    #[test]
    fn protobuf_rest_responses_follow_web_camel_case_recursively() {
        let input = serde_json::json!({
            "user_id": "account",
            "conversation": {
                "owner_account_id": "owner",
                "last_read_at": 42
            },
            "items": [{"device_number": 7}]
        });
        assert_eq!(
            protobuf_json_to_web_camel_case(input),
            serde_json::json!({
                "userId": "account",
                "conversation": {
                    "ownerAccountId": "owner",
                    "lastReadAt": 42
                },
                "items": [{"deviceNumber": 7}]
            })
        );
    }
}
