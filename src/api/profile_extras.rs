//! REST operations used by the web client's privacy, Discover, and account
//! security settings.
//!
//! Requests and responses remain JSON-shaped at the native callback boundary.
//! `ActorState::http` maps the first-party REST routes to their protobuf wire
//! messages.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use url::Url;
use url::form_urlencoded;

use crate::api::common::bearer;
use crate::error::{Error, Result};
use crate::runtime::ActorState;

// ---------------------------------------------------------------------------
// Profile privacy and contact policies
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrivacySettings {
    pub hide_profile: bool,
    pub hide_from_search: bool,
}

pub async fn get_privacy(state: &Arc<ActorState>, _payload: Vec<u8>) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let settings: PrivacySettings = state
        .http
        .get("/api/v1/profile/privacy", Some(&token))
        .await?;
    Ok(serde_json::to_vec(&settings)?)
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ToggleRequest {
    pub enabled: bool,
}

pub async fn set_profile_hidden(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    set_privacy_toggle(state, payload, "/api/v1/profile/privacy/hide-profile").await
}

pub async fn set_hidden_from_search(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    set_privacy_toggle(state, payload, "/api/v1/profile/privacy/hide-from-search").await
}

async fn set_privacy_toggle(
    state: &Arc<ActorState>,
    payload: Vec<u8>,
    path: &'static str,
) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let request: ToggleRequest = serde_json::from_slice(&payload)?;
    let _: serde_json::Value = state.http.put(path, &request, Some(&token)).await?;
    Ok(br#"{"updated":true}"#.to_vec())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProfileExceptionItem {
    pub account_id: String,
    pub created_at: i64,
}

pub async fn list_profile_exceptions(
    state: &Arc<ActorState>,
    _payload: Vec<u8>,
) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let rows: Vec<ProfileExceptionItem> = state
        .http
        .get("/api/v1/profile/privacy/profile-exceptions", Some(&token))
        .await?;
    Ok(serde_json::to_vec(&rows)?)
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AccountIdRequest {
    pub account_id: String,
}

pub async fn add_profile_exception(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let request: AccountIdRequest = serde_json::from_slice(&payload)?;
    validate_identifier(&request.account_id, "account_id")?;
    let _: serde_json::Value = state
        .http
        .post(
            "/api/v1/profile/privacy/profile-exceptions",
            &request,
            Some(&token),
        )
        .await?;
    Ok(br#"{"added":true}"#.to_vec())
}

pub async fn remove_profile_exception(
    state: &Arc<ActorState>,
    payload: Vec<u8>,
) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let request: AccountIdRequest = serde_json::from_slice(&payload)?;
    let id = path_segment(&request.account_id, "account_id")?;
    let path = format!("/api/v1/profile/privacy/profile-exceptions/{id}");
    let _: serde_json::Value = state.http.delete(&path, Some(&token)).await?;
    Ok(br#"{"removed":true}"#.to_vec())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProfileField {
    pub label: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProfileFieldsResponse {
    pub fields: Vec<ProfileField>,
}

pub async fn get_profile_fields(state: &Arc<ActorState>, _payload: Vec<u8>) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let response: ProfileFieldsResponse = state
        .http
        .get("/api/v1/profile/fields", Some(&token))
        .await?;
    Ok(serde_json::to_vec(&response)?)
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SetProfileFieldsRequest {
    pub fields: Vec<ProfileField>,
}

pub async fn set_profile_fields(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let request: SetProfileFieldsRequest = serde_json::from_slice(&payload)?;
    validate_profile_fields(&request.fields)?;
    let _: serde_json::Value = state
        .http
        .put("/api/v1/profile/fields", &request, Some(&token))
        .await?;
    Ok(br#"{"updated":true}"#.to_vec())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyResponse {
    pub policy: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PolicyRequest {
    pub policy: String,
}

pub async fn get_dm_policy(state: &Arc<ActorState>, _payload: Vec<u8>) -> Result<Vec<u8>> {
    get_policy(state, "/api/v1/profile/dm-policy").await
}

pub async fn set_dm_policy(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let request: PolicyRequest = serde_json::from_slice(&payload)?;
    if !matches!(request.policy.as_str(), "everyone" | "contacts_only") {
        return Err(invalid("policy must be 'everyone' or 'contacts_only'"));
    }
    set_policy(state, "/api/v1/profile/dm-policy", &request).await
}

pub async fn get_group_add_policy(state: &Arc<ActorState>, _payload: Vec<u8>) -> Result<Vec<u8>> {
    get_policy(state, "/api/v1/profile/group-add-policy").await
}

pub async fn set_group_add_policy(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let request: PolicyRequest = serde_json::from_slice(&payload)?;
    if !matches!(request.policy.as_str(), "everyone" | "nobody") {
        return Err(invalid("policy must be 'everyone' or 'nobody'"));
    }
    set_policy(state, "/api/v1/profile/group-add-policy", &request).await
}

async fn get_policy(state: &Arc<ActorState>, path: &'static str) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let response: PolicyResponse = state.http.get(path, Some(&token)).await?;
    Ok(serde_json::to_vec(&response)?)
}

async fn set_policy(
    state: &Arc<ActorState>,
    path: &'static str,
    request: &PolicyRequest,
) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let _: serde_json::Value = state.http.put(path, request, Some(&token)).await?;
    Ok(br#"{"updated":true}"#.to_vec())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GroupAddExceptionItem {
    pub account_id: String,
    pub created_at: i64,
}

pub async fn list_group_add_exceptions(
    state: &Arc<ActorState>,
    _payload: Vec<u8>,
) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let rows: Vec<GroupAddExceptionItem> = state
        .http
        .get("/api/v1/profile/group-add-exceptions", Some(&token))
        .await?;
    Ok(serde_json::to_vec(&rows)?)
}

pub async fn add_group_add_exception(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let request: AccountIdRequest = serde_json::from_slice(&payload)?;
    validate_identifier(&request.account_id, "account_id")?;
    let _: serde_json::Value = state
        .http
        .post(
            "/api/v1/profile/group-add-exceptions",
            &request,
            Some(&token),
        )
        .await?;
    Ok(br#"{"added":true}"#.to_vec())
}

pub async fn remove_group_add_exception(
    state: &Arc<ActorState>,
    payload: Vec<u8>,
) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let request: AccountIdRequest = serde_json::from_slice(&payload)?;
    let id = path_segment(&request.account_id, "account_id")?;
    let path = format!("/api/v1/profile/group-add-exceptions/{id}");
    let _: serde_json::Value = state.http.delete(&path, Some(&token)).await?;
    Ok(br#"{"removed":true}"#.to_vec())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AllowNudgesResponse {
    pub allow: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SetAllowNudgesRequest {
    pub allow: bool,
}

pub async fn get_allow_nudges(state: &Arc<ActorState>, _payload: Vec<u8>) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let response: AllowNudgesResponse = state
        .http
        .get("/api/v1/profile/allow-nudges", Some(&token))
        .await?;
    Ok(serde_json::to_vec(&response)?)
}

pub async fn set_allow_nudges(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let request: SetAllowNudgesRequest = serde_json::from_slice(&payload)?;
    let _: serde_json::Value = state
        .http
        .put("/api/v1/profile/allow-nudges", &request, Some(&token))
        .await?;
    Ok(br#"{"updated":true}"#.to_vec())
}

// ---------------------------------------------------------------------------
// Discover profile and directory
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DiscoverProfile {
    pub account_id: String,
    pub display_name: String,
    pub city: String,
    pub birth_year: i32,
    pub gender: String,
    pub looking_for: String,
    pub bio: Option<String>,
    pub interests: Vec<String>,
    pub is_listed: bool,
    pub updated_at: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SaveDiscoverProfileRequest {
    pub display_name: String,
    pub city: String,
    pub birth_year: i32,
    pub gender: String,
    pub looking_for: String,
    pub bio: Option<String>,
    pub interests: Vec<String>,
    pub is_listed: bool,
}

pub async fn get_discover_profile(state: &Arc<ActorState>, _payload: Vec<u8>) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let profile: DiscoverProfile = state
        .http
        .get("/api/v1/discover/profile", Some(&token))
        .await?;
    Ok(serde_json::to_vec(&profile)?)
}

pub async fn save_discover_profile(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let request: SaveDiscoverProfileRequest = serde_json::from_slice(&payload)?;
    let request = validate_discover_profile(request)?;
    let profile: DiscoverProfile = state
        .http
        .put("/api/v1/discover/profile", &request, Some(&token))
        .await?;
    Ok(serde_json::to_vec(&profile)?)
}

pub async fn hide_discover_profile(state: &Arc<ActorState>, _payload: Vec<u8>) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let _: serde_json::Value = state
        .http
        .delete("/api/v1/discover/profile", Some(&token))
        .await?;
    Ok(br#"{"hidden":true}"#.to_vec())
}

#[derive(Debug, Default, Deserialize)]
pub struct DiscoverFilters {
    pub city: Option<String>,
    pub gender: Option<String>,
    pub looking_for: Option<String>,
    pub min_age: Option<i32>,
    pub max_age: Option<i32>,
    pub interests: Option<Vec<String>>,
    pub query: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct DiscoverCursor {
    pub before: i64,
    pub before_account_id: String,
}

/// The callback payload follows the wrapper arguments: `{ filters, cursor,
/// limit }`. Missing filters/cursor/limit mean `{}`, no cursor, and 20.
#[derive(Debug, Deserialize)]
pub struct ListDiscoverProfilesRequest {
    #[serde(default)]
    pub filters: DiscoverFilters,
    pub cursor: Option<DiscoverCursor>,
    pub limit: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DiscoverCard {
    pub account_id: String,
    pub display_name: String,
    pub city: String,
    pub birth_year: i32,
    pub age: i32,
    pub gender: String,
    pub looking_for: String,
    pub bio: Option<String>,
    pub interests: Vec<String>,
    pub updated_at: i64,
}

pub async fn list_discover_profiles(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let request: ListDiscoverProfilesRequest = serde_json::from_slice(&payload)?;
    let query = discover_query(&request)?;
    let path = format!("/api/v1/discover?{query}");
    let cards: Vec<DiscoverCard> = state.http.get(&path, Some(&token)).await?;
    Ok(serde_json::to_vec(&cards)?)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DiscoverProfileDetails {
    pub account_id: String,
    pub display_name: String,
    pub city: String,
    pub birth_year: i32,
    pub age: i32,
    pub gender: String,
    pub looking_for: String,
    pub bio: Option<String>,
    pub interests: Vec<String>,
    pub updated_at: i64,
    pub avatar_url: Option<String>,
    pub fh_number: String,
}

pub async fn get_discover_profile_details(
    state: &Arc<ActorState>,
    payload: Vec<u8>,
) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let request: AccountIdRequest = serde_json::from_slice(&payload)?;
    let id = path_segment(&request.account_id, "account_id")?;
    let path = format!("/api/v1/discover/{id}");
    let profile: DiscoverProfileDetails = state.http.get(&path, Some(&token)).await?;
    Ok(serde_json::to_vec(&profile)?)
}

// ---------------------------------------------------------------------------
// Web Push and security events
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VapidResponse {
    pub public_key: String,
    pub subject: String,
}

/// VAPID configuration is public by contract; this call works before login.
pub async fn get_vapid(state: &Arc<ActorState>, _payload: Vec<u8>) -> Result<Vec<u8>> {
    let response: VapidResponse = state.http.get("/api/v1/push/vapid", None).await?;
    Ok(serde_json::to_vec(&response)?)
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SubscribePushRequest {
    pub subscription: PushSubscription,
    pub user_agent: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PushSubscription {
    pub endpoint: String,
    pub keys: PushSubscriptionKeys,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PushSubscriptionKeys {
    pub p256dh: String,
    pub auth: String,
}

pub async fn subscribe_push(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let request: SubscribePushRequest = serde_json::from_slice(&payload)?;
    validate_push_endpoint(&request.subscription.endpoint)?;
    validate_push_key(&request.subscription.keys.p256dh, "p256dh")?;
    validate_push_key(&request.subscription.keys.auth, "auth")?;
    validate_user_agent(request.user_agent.as_deref())?;
    let _: serde_json::Value = state
        .http
        .post("/api/v1/push/subscribe", &request, Some(&token))
        .await?;
    Ok(br#"{"subscribed":true}"#.to_vec())
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UnsubscribePushRequest {
    pub endpoint: String,
}

pub async fn unsubscribe_push(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let request: UnsubscribePushRequest = serde_json::from_slice(&payload)?;
    validate_push_endpoint(&request.endpoint)?;
    let _: serde_json::Value = state
        .http
        .delete_with_body("/api/v1/push/subscribe", &request, Some(&token))
        .await?;
    Ok(br#"{"unsubscribed":true}"#.to_vec())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecurityEventItem {
    pub id: String,
    pub event_type: String,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub metadata: Option<String>,
    pub created_at: i64,
}

pub async fn list_security_events(state: &Arc<ActorState>, _payload: Vec<u8>) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    // The web client requests 100 rows; the server contract allows 1..=200.
    let rows: Vec<SecurityEventItem> = state
        .http
        .get("/api/v1/security/events?limit=100", Some(&token))
        .await?;
    Ok(serde_json::to_vec(&rows)?)
}

// ---------------------------------------------------------------------------
// Validation and query construction
// ---------------------------------------------------------------------------

fn invalid(message: impl Into<String>) -> Error {
    Error::InvalidPayload(message.into())
}

fn validate_identifier(value: &str, field: &str) -> Result<()> {
    if value.is_empty() || value.len() > 128 || value.chars().any(char::is_control) {
        return Err(invalid(format!(
            "{field} must be a non-empty identifier of at most 128 characters"
        )));
    }
    Ok(())
}

fn path_segment(value: &str, field: &str) -> Result<String> {
    validate_identifier(value, field)?;
    // Mirrors encodeURIComponent at the web API boundary while ensuring
    // reserved characters cannot change the route's path structure.
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric()
            || matches!(
                byte,
                b'-' | b'_' | b'.' | b'!' | b'~' | b'*' | b'\'' | b'(' | b')'
            )
        {
            encoded.push(char::from(byte));
        } else {
            use std::fmt::Write as _;
            write!(&mut encoded, "%{byte:02X}").expect("writing to String cannot fail");
        }
    }
    Ok(encoded)
}

fn validate_profile_fields(fields: &[ProfileField]) -> Result<()> {
    if fields.len() > 10 {
        return Err(invalid("fields must contain at most 10 entries"));
    }
    for (index, field) in fields.iter().enumerate() {
        let label_len = field.label.chars().count();
        let value_len = field.value.chars().count();
        if field.label.trim().is_empty()
            || label_len > 64
            || field.value.trim().is_empty()
            || value_len > 128
        {
            return Err(invalid(format!(
                "fields[{index}] label and value must be non-empty and within their documented limits"
            )));
        }
    }
    Ok(())
}

fn validate_discover_profile(
    mut request: SaveDiscoverProfileRequest,
) -> Result<SaveDiscoverProfileRequest> {
    request.display_name = request.display_name.trim().to_owned();
    request.city = request.city.trim().to_owned();
    let name_len = request.display_name.chars().count();
    let city_len = request.city.chars().count();
    if name_len == 0 || name_len > 64 {
        return Err(invalid("display_name must contain 1..=64 characters"));
    }
    if city_len == 0 || city_len > 64 {
        return Err(invalid("city must contain 1..=64 characters"));
    }
    let max_birth_year = utc_year().saturating_sub(18);
    if !(1900..=max_birth_year).contains(&request.birth_year) {
        return Err(invalid(format!(
            "birth_year must be between 1900 and {max_birth_year}"
        )));
    }
    if !matches!(
        request.gender.as_str(),
        "male" | "female" | "other" | "unspecified"
    ) {
        return Err(invalid(
            "gender must be male, female, other, or unspecified",
        ));
    }
    if !matches!(
        request.looking_for.as_str(),
        "friendship" | "relationship" | "chat" | "all"
    ) {
        return Err(invalid(
            "looking_for must be friendship, relationship, chat, or all",
        ));
    }
    if let Some(bio) = request.bio.as_mut() {
        *bio = bio.trim().to_owned();
        if bio.chars().count() > 500 {
            return Err(invalid("bio must not exceed 500 characters"));
        }
        if bio.is_empty() {
            request.bio = None;
        }
    }
    if request.interests.len() > 10 {
        return Err(invalid("interests must contain at most 10 entries"));
    }
    let mut normalized_interests = std::collections::HashSet::new();
    for interest in &mut request.interests {
        *interest = interest.trim().to_owned();
        let length = interest.chars().count();
        if length == 0 || length > 32 {
            return Err(invalid("each interest must contain 1..=32 characters"));
        }
        if !normalized_interests.insert(interest.to_lowercase()) {
            return Err(invalid("interests must be unique, ignoring case"));
        }
    }
    Ok(request)
}

fn discover_query(request: &ListDiscoverProfilesRequest) -> Result<String> {
    let filters = &request.filters;
    let mut query = form_urlencoded::Serializer::new(String::new());
    if let Some(city) = filters.city.as_deref() {
        let city = city.trim();
        if city.chars().count() > 64 {
            return Err(invalid("city filter must not exceed 64 characters"));
        }
        if !city.is_empty() {
            query.append_pair("city", city);
        }
    }
    if let Some(gender) = filters.gender.as_deref() {
        let normalized = gender.trim();
        if !matches!(normalized, "male" | "female" | "other") {
            return Err(invalid("gender filter must be male, female, or other"));
        }
        query.append_pair("gender", gender);
    }
    if let Some(looking_for) = filters.looking_for.as_deref() {
        if !matches!(
            looking_for.trim(),
            "friendship" | "relationship" | "chat" | "all"
        ) {
            return Err(invalid("looking_for filter is invalid"));
        }
        query.append_pair("looking_for", looking_for);
    }
    if let Some(min_age) = filters.min_age {
        if min_age < 0 {
            return Err(invalid("min_age must be non-negative"));
        }
        query.append_pair("min_age", &min_age.to_string());
    }
    if let Some(max_age) = filters.max_age {
        if max_age < 0 {
            return Err(invalid("max_age must be non-negative"));
        }
        query.append_pair("max_age", &max_age.to_string());
    }
    if let (Some(min_age), Some(max_age)) = (filters.min_age, filters.max_age) {
        if min_age > max_age {
            return Err(invalid("min_age must not exceed max_age"));
        }
    }
    if let Some(interests) = filters.interests.as_ref() {
        let mut unique = std::collections::HashSet::new();
        let mut count = 0;
        let joined_interests = interests.join(",");
        for interest in joined_interests
            .split(',')
            .map(str::trim)
            .filter(|tag| !tag.is_empty())
        {
            if interest.chars().count() > 32 {
                return Err(invalid(
                    "each interest filter must be at most 32 characters",
                ));
            }
            if unique.insert(interest.to_lowercase()) {
                count += 1;
            }
            if count > 10 {
                return Err(invalid("interests filter may contain at most 10 tags"));
            }
        }
        if !interests.is_empty() {
            query.append_pair("interests", &interests.join(","));
        }
    }
    if let Some(search) = filters.query.as_deref() {
        let search = search.trim();
        let length = search.chars().count();
        if !search.is_empty() && !(3..=64).contains(&length) {
            return Err(invalid(
                "query must contain 3..=64 characters when provided",
            ));
        }
        if !search.is_empty() {
            query.append_pair("q", search);
        }
    }
    let limit = request.limit.unwrap_or(20);
    if !(1..=50).contains(&limit) {
        return Err(invalid("limit must be between 1 and 50"));
    }
    query.append_pair("limit", &limit.to_string());
    if let Some(cursor) = request.cursor.as_ref() {
        if cursor.before < 0 {
            return Err(invalid("cursor.before must be non-negative"));
        }
        validate_identifier(&cursor.before_account_id, "cursor.before_account_id")?;
        query.append_pair("before", &cursor.before.to_string());
        query.append_pair("before_account_id", &cursor.before_account_id);
    }
    Ok(query.finish())
}

fn validate_push_endpoint(endpoint: &str) -> Result<()> {
    let endpoint = endpoint.trim();
    if endpoint.is_empty() || endpoint.len() > 2048 {
        return Err(invalid("endpoint must be 1-2048 characters"));
    }
    let parsed =
        Url::parse(endpoint).map_err(|_| invalid("endpoint must be an absolute HTTPS URL"))?;
    if parsed.scheme() != "https"
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
    {
        return Err(invalid(
            "endpoint must be an absolute HTTPS URL without credentials",
        ));
    }
    Ok(())
}

fn validate_user_agent(user_agent: Option<&str>) -> Result<()> {
    if user_agent.is_some_and(|value| value.len() > 512) {
        return Err(invalid("user_agent must be at most 512 bytes"));
    }
    Ok(())
}

fn validate_push_key(value: &str, field: &str) -> Result<()> {
    if value.is_empty() || value.len() > 256 {
        return Err(invalid(format!(
            "subscription key {field} must be 1-256 bytes"
        )));
    }
    Ok(())
}

fn utc_year() -> i32 {
    let Ok(duration) = SystemTime::now().duration_since(UNIX_EPOCH) else {
        return 1970;
    };
    let days = (duration.as_secs() / 86_400) as i64;
    civil_year_from_days(days)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn path_segments_encode_reserved_characters_like_the_web_wrapper() {
        assert_eq!(
            path_segment("account/id with space", "account_id").unwrap(),
            "account%2Fid%20with%20space"
        );
        assert!(path_segment("", "account_id").is_err());
        assert!(path_segment("a\n/b", "account_id").is_err());
    }

    #[test]
    fn discover_query_matches_frontend_parameter_names_and_cursor_shape() {
        let request: ListDiscoverProfilesRequest = serde_json::from_value(json!({
            "filters": {
                "city": " Yekaterinburg ",
                "gender": "female",
                "looking_for": "friendship",
                "min_age": 20,
                "max_age": 35,
                "interests": ["music", "hiking"],
                "query": " Alice "
            },
            "cursor": {"before": 1792281600, "before_account_id": "last-account"},
            "limit": 20
        }))
        .unwrap();
        assert_eq!(
            discover_query(&request).unwrap(),
            "city=Yekaterinburg&gender=female&looking_for=friendship&min_age=20&max_age=35&interests=music%2Chiking&q=Alice&limit=20&before=1792281600&before_account_id=last-account"
        );
    }

    #[test]
    fn discover_query_rejects_invalid_filters_and_ranges() {
        let invalid_gender: ListDiscoverProfilesRequest =
            serde_json::from_value(json!({"filters": {"gender": "unspecified"}})).unwrap();
        assert!(discover_query(&invalid_gender).is_err());

        let reversed_ages: ListDiscoverProfilesRequest = serde_json::from_value(json!({
            "filters": {"min_age": 36, "max_age": 20}
        }))
        .unwrap();
        assert!(discover_query(&reversed_ages).is_err());
    }

    #[test]
    fn discover_profile_validation_enforces_frontend_limits_and_normalizes_optional_text() {
        let profile: SaveDiscoverProfileRequest = serde_json::from_value(json!({
            "display_name": " Alice ",
            "city": " Yekaterinburg ",
            "birth_year": 1995,
            "gender": "female",
            "looking_for": "friendship",
            "bio": "   ",
            "interests": [" Music ", "Hiking"],
            "is_listed": true
        }))
        .unwrap();
        let profile = validate_discover_profile(profile).unwrap();
        assert_eq!(profile.display_name, "Alice");
        assert_eq!(profile.city, "Yekaterinburg");
        assert_eq!(profile.bio, None);
        assert_eq!(profile.interests, ["Music", "Hiking"]);

        let duplicate: SaveDiscoverProfileRequest = serde_json::from_value(json!({
            "display_name": "Alice", "city": "Town", "birth_year": 1995,
            "gender": "female", "looking_for": "friendship", "bio": null,
            "interests": ["Music", "music"], "is_listed": true
        }))
        .unwrap();
        assert!(validate_discover_profile(duplicate).is_err());
    }

    #[test]
    fn profile_fields_validate_api_documented_limits_and_allow_clear() {
        assert!(validate_profile_fields(&[]).is_ok());
        assert!(
            validate_profile_fields(&[ProfileField {
                label: "Site".into(),
                value: "example.com".into(),
            }])
            .is_ok()
        );
        assert!(
            validate_profile_fields(&[ProfileField {
                label: " ".into(),
                value: "value".into(),
            }])
            .is_err()
        );
        assert!(
            validate_profile_fields(&vec![
                ProfileField {
                    label: "Site".into(),
                    value: "example.com".into(),
                };
                11
            ])
            .is_err()
        );
        assert!(
            validate_profile_fields(&[ProfileField {
                label: "x".repeat(65),
                value: "value".into(),
            }])
            .is_err()
        );
        assert!(
            validate_profile_fields(&[ProfileField {
                label: "label".into(),
                value: "x".repeat(129),
            }])
            .is_err()
        );
    }

    #[test]
    fn profile_field_validation_preserves_exact_values_for_the_wire_request() {
        let request = SetProfileFieldsRequest {
            fields: vec![ProfileField {
                label: "  GitHub  ".into(),
                value: "  @someone  ".into(),
            }],
        };
        validate_profile_fields(&request.fields).unwrap();
        assert_eq!(
            serde_json::to_value(request).unwrap(),
            json!({"fields": [{"label": "  GitHub  ", "value": "  @someone  "}]})
        );
    }

    #[test]
    fn push_endpoint_requires_https_and_rejects_credentials() {
        assert!(validate_push_endpoint("https://push.example.test/subscription/1").is_ok());
        assert!(validate_push_endpoint("http://push.example.test/subscription/1").is_err());
        assert!(validate_push_endpoint("https://user:pass@push.example.test/path").is_err());
        assert!(validate_push_endpoint(" https://push.example.test/subscription/1 ").is_ok());
        assert!(validate_push_endpoint("   ").is_err());
    }

    #[test]
    fn push_limits_match_backend_byte_constraints() {
        assert!(validate_push_key("k", "p256dh").is_ok());
        assert!(validate_push_key(&"k".repeat(256), "auth").is_ok());
        assert!(validate_push_key("", "auth").is_err());
        assert!(validate_push_key(&"k".repeat(257), "auth").is_err());
        assert!(validate_user_agent(Some(&"é".repeat(257))).is_err());
        assert!(validate_user_agent(Some(&"x".repeat(512))).is_ok());
    }

    #[test]
    fn discover_filter_interest_and_page_limits_match_backend() {
        let request: ListDiscoverProfilesRequest = serde_json::from_value(json!({
            "filters": {"interests": [" music ", "", "MUSIC", "hiking"]},
            "limit": 50
        }))
        .unwrap();
        assert_eq!(
            discover_query(&request).unwrap(),
            "interests=+music+%2C%2CMUSIC%2Chiking&limit=50"
        );

        let too_many: ListDiscoverProfilesRequest =
            serde_json::from_value(json!({"limit": 51})).unwrap();
        assert!(discover_query(&too_many).is_err());
    }

    #[test]
    fn utc_year_conversion_matches_unix_epoch_and_current_system_time() {
        assert_eq!(civil_year_from_days(0), 1970);
        let days = (SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            / 86_400) as i64;
        assert_eq!(utc_year(), civil_year_from_days(days));
    }
}

fn civil_year_from_days(days: i64) -> i32 {
    let shifted_days = days + 719_468;
    let era = shifted_days.div_euclid(146_097);
    let day_of_era = shifted_days - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    (year_of_era + era * 400 + i64::from(month <= 2)) as i32
}
