//! Protobuf codecs for the first-party `/api/v1` REST contract.
//!
//! Application modules keep their existing Serde DTOs and FFI JSON surface.
//! This module translates those values at the HTTP boundary and fails closed
//! when a first-party route has no codec entry.

use prost::Message;
use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Map, Value};

use crate::error::{Error, Result};
use crate::proto::rest::{chat, community, identity};

const API_PREFIX: &str = "/api/v1";
const PROTOBUF_MEDIA_TYPE: &str = "application/x-protobuf";

/// Wire protocol selected for a REST endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestProtocol {
    Json,
    Protobuf,
    RawProtobufErrors,
}

/// Encoded request ready to send over a platform-specific HTTP adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestRequest {
    pub protocol: RestProtocol,
    pub accept: Option<&'static str>,
    pub content_type: Option<String>,
    pub body: Option<Vec<u8>>,
}

type RequestEncoder = fn(Value) -> Result<Vec<u8>>;
type ResponseDecoder = fn(&[u8], ResponseShape) -> Result<Value>;

#[derive(Clone, Copy)]
enum RequestBody {
    None,
    Protobuf(RequestEncoder),
    Raw,
}

#[derive(Clone, Copy)]
enum ResponseShape {
    Object,
    Items,
}

#[derive(Clone, Copy)]
pub(super) struct RouteSpec {
    method: &'static str,
    path: &'static str,
    request: RequestBody,
    response: Option<(ResponseDecoder, ResponseShape)>,
}

macro_rules! object_route {
    ($method:literal, $path:literal, $request:ty => $response:ty) => {
        RouteSpec {
            method: $method,
            path: $path,
            request: RequestBody::Protobuf(encode_request::<$request>),
            response: Some((decode_response::<$response>, ResponseShape::Object)),
        }
    };
}

macro_rules! object_list_route {
    ($method:literal, $path:literal, $request:ty => $response:ty) => {
        RouteSpec {
            method: $method,
            path: $path,
            request: RequestBody::Protobuf(encode_request::<$request>),
            response: Some((decode_response::<$response>, ResponseShape::Items)),
        }
    };
}

macro_rules! get_object_route {
    ($path:literal => $response:ty) => {
        RouteSpec {
            method: "GET",
            path: $path,
            request: RequestBody::None,
            response: Some((decode_response::<$response>, ResponseShape::Object)),
        }
    };
}

macro_rules! bodyless_object_route {
    ($method:literal, $path:literal => $response:ty) => {
        RouteSpec {
            method: $method,
            path: $path,
            request: RequestBody::None,
            response: Some((decode_response::<$response>, ResponseShape::Object)),
        }
    };
}

macro_rules! get_list_route {
    ($path:literal => $response:ty) => {
        RouteSpec {
            method: "GET",
            path: $path,
            request: RequestBody::None,
            response: Some((decode_response::<$response>, ResponseShape::Items)),
        }
    };
}

macro_rules! bodyless_response_route {
    ($method:literal, $path:literal) => {
        RouteSpec {
            method: $method,
            path: $path,
            request: RequestBody::None,
            response: None,
        }
    };
}

macro_rules! request_only_route {
    ($method:literal, $path:literal, $request:ty) => {
        RouteSpec {
            method: $method,
            path: $path,
            request: RequestBody::Protobuf(encode_request::<$request>),
            response: None,
        }
    };
}

macro_rules! raw_request_route {
    ($method:literal, $path:literal => $response:ty) => {
        RouteSpec {
            method: $method,
            path: $path,
            request: RequestBody::Raw,
            response: Some((decode_response::<$response>, ResponseShape::Object)),
        }
    };
}

static HEALTH_ROUTE: RouteSpec = RouteSpec {
    method: "GET",
    path: "/health",
    request: RequestBody::None,
    response: Some((
        decode_response::<crate::proto::rest::HealthResponse>,
        ResponseShape::Object,
    )),
};

static ROUTES: &[RouteSpec] = &[
    // Authentication, sessions and account deletion.
    object_route!("POST", "/register", identity::RegisterRequest => identity::RegisterResponse),
    object_route!("POST", "/login", identity::LoginRequest => identity::LoginResponse),
    object_route!("POST", "/login/2fa", identity::Login2faRequest => identity::LoginResponse),
    bodyless_response_route!("POST", "/logout"),
    get_object_route!("/me" => identity::MeResponse),
    bodyless_object_route!("POST", "/2fa/enroll" => identity::EnrollResponse),
    object_route!("POST", "/2fa/enroll/verify", identity::EnrollVerifyRequest => identity::EnrollVerifyResponse),
    request_only_route!("POST", "/2fa/disable", identity::DisableRequest),
    bodyless_object_route!("POST", "/account/delete/initiate" => identity::InitiateResponse),
    request_only_route!("POST", "/account/delete/confirm", identity::ConfirmRequest),
    bodyless_response_route!("POST", "/account/delete/cancel"),
    get_object_route!("/account/delete/status" => identity::StatusResponse),
    get_list_route!("/sessions" => identity::SessionsResponse),
    bodyless_response_route!("DELETE", "/sessions/{id}"),
    bodyless_object_route!("POST", "/sessions/revoke-all" => identity::RevokeAllResponse),
    // Contacts and blocks.
    get_list_route!("/contacts" => identity::ContactsResponse),
    object_route!("POST", "/contacts", identity::AddContactRequest => identity::ContactItem),
    get_list_route!("/contacts/search" => identity::ContactsResponse),
    bodyless_response_route!("DELETE", "/contacts/{id}"),
    get_list_route!("/blocks" => identity::BlockedContactsResponse),
    bodyless_response_route!("POST", "/blocks/{id}"),
    bodyless_response_route!("DELETE", "/blocks/{id}"),
    // Profile and privacy.
    request_only_route!("PUT", "/profile/username", identity::UpdateUsernameRequest),
    request_only_route!("PUT", "/profile/status", identity::UpdateStatusRequest),
    bodyless_response_route!("DELETE", "/profile/status"),
    request_only_route!("PUT", "/profile/invisible", identity::InvisibleModeRequest),
    get_object_route!("/profile/invisible" => identity::InvisibleModeResponse),
    get_list_route!("/profile/presence-exceptions" => identity::PresenceExceptionsResponse),
    request_only_route!(
        "POST",
        "/profile/presence-exceptions",
        identity::PresenceExceptionRequest
    ),
    request_only_route!(
        "POST",
        "/profile/presence-exceptions/remove",
        identity::PresenceExceptionRequest
    ),
    get_object_route!("/accounts/{id}/profile" => identity::PublicProfile),
    get_object_route!("/accounts/{id}/presence" => identity::PresenceResponse),
    object_list_route!("POST", "/accounts/batch", identity::AccountsBatchRequest => identity::AccountsBatchResponse),
    get_object_route!("/profile/group-add-policy" => identity::GroupAddPolicyResponse),
    request_only_route!(
        "PUT",
        "/profile/group-add-policy",
        identity::GroupAddPolicyRequest
    ),
    get_list_route!("/profile/group-add-exceptions" => identity::GroupAddExceptionsResponse),
    request_only_route!(
        "POST",
        "/profile/group-add-exceptions",
        identity::GroupAddExceptionRequest
    ),
    bodyless_response_route!("DELETE", "/profile/group-add-exceptions/{account_id}"),
    get_object_route!("/profile/fields" => identity::ProfileFieldsResponse),
    request_only_route!("PUT", "/profile/fields", identity::SetProfileFieldsRequest),
    get_object_route!("/profile/dm-policy" => identity::DmPolicyResponse),
    request_only_route!("PUT", "/profile/dm-policy", identity::DmPolicyRequest),
    get_object_route!("/profile/allow-nudges" => identity::AllowNudgesResponse),
    request_only_route!(
        "PUT",
        "/profile/allow-nudges",
        identity::SetAllowNudgesRequest
    ),
    get_object_route!("/profile/privacy" => identity::PrivacySettingsResponse),
    request_only_route!(
        "PUT",
        "/profile/privacy/hide-profile",
        identity::ToggleRequest
    ),
    request_only_route!(
        "PUT",
        "/profile/privacy/hide-from-search",
        identity::ToggleRequest
    ),
    get_list_route!("/profile/privacy/profile-exceptions" => identity::ProfileExceptionsResponse),
    request_only_route!(
        "POST",
        "/profile/privacy/profile-exceptions",
        identity::ProfileExceptionRequest
    ),
    bodyless_response_route!("DELETE", "/profile/privacy/profile-exceptions/{account_id}"),
    get_object_route!("/handles/{handle}" => identity::HandleLookupResponse),
    get_object_route!("/handles/{handle}/available" => identity::HandleAvailabilityResponse),
    object_route!("POST", "/handles/batch", identity::BatchLookupRequest => identity::BatchLookupResponse),
    // Devices, prekeys and security events.
    get_list_route!("/devices" => identity::DevicesResponse),
    object_route!("POST", "/devices", identity::RegisterDeviceRequest => identity::DeviceItem),
    bodyless_response_route!("DELETE", "/devices/{id}"),
    get_list_route!("/accounts/{account_id}/devices" => identity::PublicDevicesResponse),
    object_route!("POST", "/devices/me/prekeys", identity::UploadPrekeysRequest => identity::UploadPrekeysResponse),
    get_object_route!("/devices/me/prekeys/status" => identity::PrekeyStatusResponse),
    get_object_route!("/accounts/{account_id}/devices/{device_number}/bundle" => identity::PrekeyBundleResponse),
    get_list_route!("/security/events" => identity::SecurityEventsResponse),
    // Push and WebRTC configuration.
    get_object_route!("/push/vapid" => identity::VapidResponse),
    request_only_route!("POST", "/push/subscribe", identity::SubscribeRequest),
    request_only_route!("DELETE", "/push/subscribe", identity::UnsubscribeRequest),
    get_object_route!("/webrtc/ice-servers" => community::IceServersResponse),
    // Conversations, saved messages, polls, read state, folders and calls.
    get_list_route!("/conversations" => chat::ConversationListResponse),
    object_route!("POST", "/conversations/direct", chat::CreateDirectRequest => chat::CreateDirectResponse),
    get_object_route!("/conversations/{id}" => chat::ConversationDetailResponse),
    bodyless_response_route!("POST", "/conversations/{id}/leave"),
    bodyless_response_route!("POST", "/conversations/{id}/archive"),
    bodyless_response_route!("DELETE", "/conversations/{id}/archive"),
    request_only_route!("POST", "/conversations/{id}/mute", chat::MuteRequest),
    bodyless_response_route!("DELETE", "/conversations/{id}/mute"),
    get_list_route!("/conversations/{id}/envelopes" => chat::EnvelopeHistoryResponse),
    request_only_route!(
        "PUT",
        "/conversations/{id}/notification-level",
        chat::NotificationLevelRequest
    ),
    get_object_route!("/saved" => chat::SavedConversationResponse),
    get_object_route!("/saved/messages" => chat::SavedHistoryResponse),
    request_only_route!("POST", "/conversations/{id}/pinned", chat::PinRequest),
    get_list_route!("/conversations/{id}/pinned" => chat::PinnedListResponse),
    bodyless_response_route!("DELETE", "/conversations/{id}/pinned/{message_id}"),
    request_only_route!("POST", "/conversations/{id}/read", chat::MarkReadRequest),
    get_list_route!("/conversations/{id}/reads" => chat::ReadStateListResponse),
    get_list_route!("/conversations/{id}/polls" => chat::PollListResponse),
    object_route!("POST", "/conversations/{id}/polls", chat::CreatePollRequest => chat::PollItem),
    get_object_route!("/polls/{id}" => chat::PollItem),
    object_route!("POST", "/polls/{id}/vote", chat::VoteRequest => chat::PollItem),
    bodyless_response_route!("POST", "/polls/{id}/stop"),
    request_only_route!("POST", "/polls/{id}/options", chat::AddPollOptionRequest),
    bodyless_response_route!("DELETE", "/polls/{id}/options/{option_id}"),
    bodyless_response_route!("DELETE", "/polls/{id}"),
    get_list_route!("/conversations/{id}/invites" => chat::InviteListResponse),
    object_route!("POST", "/conversations/{id}/invites", chat::InviteCreateRequest => chat::InviteItem),
    bodyless_response_route!("DELETE", "/invites/{id}"),
    bodyless_object_route!("POST", "/invites/join/{token}" => chat::JoinInviteResponse),
    get_list_route!("/folders" => chat::FolderListResponse),
    object_route!("POST", "/folders", chat::CreateFolderRequest => chat::FolderItem),
    request_only_route!("PATCH", "/folders/{id}", chat::UpdateFolderRequest),
    bodyless_response_route!("DELETE", "/folders/{id}"),
    request_only_route!("POST", "/folders/{id}/items", chat::AddFolderItemRequest),
    bodyless_response_route!("DELETE", "/folders/{id}/items/{conversation_id}"),
    get_list_route!("/scheduled" => chat::ScheduledListResponse),
    bodyless_response_route!("DELETE", "/scheduled/{id}"),
    object_route!("POST", "/calls", chat::RecordCallRequest => chat::CallRecordItem),
    get_list_route!("/calls" => chat::CallListResponse),
    bodyless_response_route!("POST", "/calls/clear"),
    bodyless_response_route!("DELETE", "/calls/{id}"),
    get_object_route!("/search" => chat::SearchResponse),
    // Groups.
    object_route!("POST", "/groups", community::CreateGroupRequest => community::GroupResponse),
    get_list_route!("/groups/public" => community::PublicGroupsResponse),
    bodyless_response_route!("POST", "/groups/{id}/join"),
    get_object_route!("/groups/by-handle/{handle}" => community::GroupByHandleResponse),
    get_object_route!("/groups/{id}" => community::GroupDetail),
    request_only_route!("PATCH", "/groups/{id}", community::UpdateGroupRequest),
    bodyless_response_route!("DELETE", "/groups/{id}"),
    get_list_route!("/groups/{id}/members" => community::GroupMembersResponse),
    request_only_route!(
        "POST",
        "/groups/{id}/members",
        community::AddGroupMemberRequest
    ),
    bodyless_response_route!("DELETE", "/groups/{id}/members/{account_id}"),
    request_only_route!(
        "PUT",
        "/groups/{id}/members/{account_id}/tag",
        community::SetGroupTagRequest
    ),
    bodyless_response_route!("DELETE", "/groups/{id}/members/{account_id}/tag"),
    get_list_route!("/groups/{id}/bans" => community::GroupBansResponse),
    request_only_route!(
        "POST",
        "/groups/{id}/bans",
        community::BanGroupMemberRequest
    ),
    bodyless_response_route!("DELETE", "/groups/{id}/bans/{account_id}"),
    request_only_route!(
        "POST",
        "/groups/{id}/members/role",
        community::SetGroupRoleRequest
    ),
    request_only_route!(
        "POST",
        "/groups/{id}/members/mute",
        community::MuteGroupMemberRequest
    ),
    object_route!("POST", "/groups/{id}/profile", community::SetGroupProfileRequest => community::GroupProfileResponse),
    request_only_route!(
        "POST",
        "/groups/{id}/owner",
        community::TransferGroupOwnerRequest
    ),
    // Channels and channel posts. Static paths precede their {id} siblings.
    object_route!("POST", "/channels", community::CreateChannelRequest => community::ChannelResponse),
    get_list_route!("/channels/public" => community::PublicChannelsResponse),
    get_object_route!("/channels/by-handle/{handle}" => community::ChannelByHandleResponse),
    get_object_route!("/channels/{id}" => community::ChannelDetail),
    bodyless_response_route!("DELETE", "/channels/{id}"),
    get_list_route!("/channels/{id}/members" => community::ChannelMembersResponse),
    request_only_route!(
        "POST",
        "/channels/{id}/members/role",
        community::SetChannelRoleRequest
    ),
    request_only_route!(
        "POST",
        "/channels/{id}/members/remove",
        community::RemoveChannelMemberRequest
    ),
    request_only_route!(
        "POST",
        "/channels/{id}/linked-group",
        community::SetLinkedGroupRequest
    ),
    request_only_route!(
        "POST",
        "/channels/{id}/public",
        community::SetChannelPublicRequest
    ),
    request_only_route!(
        "POST",
        "/channels/{id}/owner",
        community::TransferChannelOwnerRequest
    ),
    get_object_route!("/channels/{id}/analytics" => community::ChannelAnalyticsResponse),
    object_route!("POST", "/channels/{id}/profile", community::SetChannelProfileRequest => community::ChannelProfileResponse),
    request_only_route!(
        "POST",
        "/channels/{id}/bots",
        community::AddChannelBotRequest
    ),
    get_object_route!("/channels/{id}/can-publish" => community::CanPublishResponse),
    bodyless_response_route!("POST", "/channels/{id}/subscribe"),
    bodyless_response_route!("DELETE", "/channels/{id}/subscribe"),
    get_list_route!("/channels/{id}/posts" => community::ChannelPostsResponse),
    object_route!("POST", "/channels/{id}/posts", community::PublishChannelPostRequest => community::ChannelPost),
    bodyless_response_route!("POST", "/channel-posts/{post_id}/pin"),
    bodyless_response_route!("DELETE", "/channel-posts/{post_id}/pin"),
    get_list_route!("/channels/{id}/pinned" => community::ChannelPostsResponse),
    get_object_route!("/channel-posts/{post_id}" => community::ChannelPost),
    request_only_route!(
        "PATCH",
        "/channel-posts/{post_id}",
        community::EditChannelPostRequest
    ),
    bodyless_response_route!("DELETE", "/channel-posts/{post_id}"),
    get_list_route!("/channel-posts/{post_id}/reactions" => community::ChannelPostReactionsResponse),
    request_only_route!(
        "POST",
        "/channel-posts/{post_id}/reactions",
        community::SetChannelPostReactionRequest
    ),
    bodyless_response_route!("DELETE", "/channel-posts/{post_id}/reactions"),
    get_object_route!("/channel-posts/{post_id}/discussion" => community::ChannelPostDiscussion),
    // First-party bot management/conversations. The separate /api/bot/v1
    // bot API is intentionally outside this registry.
    bodyless_object_route!("POST", "/bots" => community::CreateBotResponse),
    get_list_route!("/bots" => community::BotsResponse),
    object_route!("POST", "/bots/{id}/profile", community::SetBotProfileRequest => community::BotProfileResponse),
    bodyless_object_route!("POST", "/bots/{id}/rotate-token" => community::RotateBotTokenResponse),
    bodyless_response_route!("DELETE", "/bots/{id}"),
    get_list_route!("/user/bots" => community::OwnedBotsResponse),
    get_object_route!("/bots/{id}/info" => community::BotPublicInfo),
    get_list_route!("/bots/{id}/messages" => community::BotMessagesResponse),
    object_route!("POST", "/bots/{id}/messages", community::SendToBotRequest => community::BotMessage),
    object_route!("POST", "/bots/{id}/callback", community::BotCallbackRequest => community::BotCallbackResponse),
    // Discover.
    get_object_route!("/discover/profile" => community::MyDiscoverProfile),
    object_route!("PUT", "/discover/profile", community::UpsertDiscoverProfileRequest => community::MyDiscoverProfile),
    bodyless_response_route!("DELETE", "/discover/profile"),
    get_list_route!("/discover" => community::DiscoverCardsResponse),
    get_object_route!("/discover/{account_id}" => community::DiscoverProfile),
    // Attachments metadata and presigned URL responses; raw attachment bytes
    // are transferred directly by the client to the object store.
    object_route!("POST", "/attachments/init", community::InitAttachmentRequest => community::InitAttachmentResponse),
    object_route!("POST", "/attachments/recommend", community::RecommendAttachmentRequest => community::RecommendAttachmentResponse),
    bodyless_response_route!("POST", "/attachments/{id}/finalize"),
    bodyless_response_route!("POST", "/attachments/{id}/claim"),
    bodyless_response_route!("POST", "/attachments/{id}/release"),
    get_object_route!("/attachments/{id}" => community::AttachmentDownloadResponse),
    // Avatar byte uploads keep their image/webp request bodies. Their JSON
    // success DTO is bridged to the typed protobuf response. Direct GETs and
    // redirects are deliberately not registered.
    object_route!("POST", "/avatars/me/uploads", identity::AvatarUploadInitRequest => identity::AvatarUploadInitResponse),
    bodyless_object_route!("POST", "/avatars/me/uploads/{id}/finalize" => identity::AvatarUrlResponse),
    raw_request_route!("POST", "/avatars/me" => identity::AvatarUrlResponse),
    bodyless_response_route!("DELETE", "/avatars/me"),
    raw_request_route!("POST", "/groups/{id}/avatar" => identity::AvatarUrlResponse),
    bodyless_response_route!("DELETE", "/groups/{id}/avatar"),
    raw_request_route!("POST", "/channels/{id}/avatar" => identity::AvatarUrlResponse),
    bodyless_response_route!("DELETE", "/channels/{id}/avatar"),
];

#[derive(Clone, Copy)]
pub(super) enum Protocol {
    Json,
    Protobuf(&'static RouteSpec),
    /// Public avatar bytes stay raw; only error envelopes use protobuf.
    RawProtobufErrors,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg(feature = "native")]
pub(super) enum AvatarInitialResponse {
    RawBytes,
    ApiProtobufError,
    FollowStorageRedirect,
    RawRedirectError,
}

#[cfg(feature = "native")]
pub(super) fn classify_avatar_initial_response(
    status: u16,
    has_location: bool,
) -> AvatarInitialResponse {
    match status {
        200..=299 => AvatarInitialResponse::RawBytes,
        300..=399 if has_location => AvatarInitialResponse::FollowStorageRedirect,
        300..=399 => AvatarInitialResponse::RawRedirectError,
        _ => AvatarInitialResponse::ApiProtobufError,
    }
}

pub(super) fn protocol_for(method: &str, path_and_query: &str) -> Result<Protocol> {
    let path = path_and_query
        .split_once('?')
        .map_or(path_and_query, |(path, _)| path);
    if method == "GET" && path == "/health" {
        return Ok(Protocol::Protobuf(&HEALTH_ROUTE));
    }
    let Some(local_path) = path
        .strip_prefix(API_PREFIX)
        .filter(|suffix| suffix.is_empty() || suffix.starts_with('/'))
    else {
        // The separate bot API and non-API endpoints retain their JSON/raw
        // contracts. Callers that use absolute storage URLs bypass this path.
        return Ok(Protocol::Json);
    };

    if matches!(method, "GET" | "HEAD")
        && (path_matches("/avatars/{account_id}", local_path)
            || path_matches("/conversations/{id}/avatar", local_path))
    {
        return Ok(Protocol::RawProtobufErrors);
    }

    ROUTES
        .iter()
        .find(|route| route.method == method && path_matches(route.path, local_path))
        .map(Protocol::Protobuf)
        .ok_or_else(|| {
            Error::InvalidPayload(format!(
                "no protobuf REST codec is registered for {method} {path}"
            ))
        })
}

/// Selects the same request encoding used by the native HTTP transport.
///
/// `json_body` is a structured request for JSON or protobuf endpoints;
/// `raw_body` is reserved for routes whose contract accepts file bytes. The
/// body arguments are mutually exclusive. `raw_content_type` is used only for
/// a raw upload and defaults to `application/octet-stream`.
pub fn prepare_rest_request(
    method: &str,
    path_and_query: &str,
    json_body: Option<Value>,
    raw_body: Option<Vec<u8>>,
    raw_content_type: Option<&str>,
) -> Result<RestRequest> {
    if json_body.is_some() && raw_body.is_some() {
        return Err(Error::InvalidPayload(
            "JSON and raw request bodies cannot be used together".into(),
        ));
    }

    let protocol = protocol_for(method, path_and_query)?;
    match protocol {
        Protocol::Json => {
            let (body, content_type) = if let Some(body) = raw_body {
                (
                    Some(body),
                    Some(
                        raw_content_type
                            .unwrap_or("application/octet-stream")
                            .to_owned(),
                    ),
                )
            } else if let Some(body) = json_body {
                (
                    Some(serde_json::to_vec(&body)?),
                    Some("application/json".into()),
                )
            } else {
                (None, None)
            };
            Ok(RestRequest {
                protocol: RestProtocol::Json,
                accept: None,
                content_type,
                body,
            })
        }
        Protocol::Protobuf(route) => match route.request {
            RequestBody::None => {
                if json_body.is_some() || raw_body.is_some() {
                    return Err(Error::InvalidPayload(
                        "this REST endpoint does not accept a request body".into(),
                    ));
                }
                Ok(RestRequest {
                    protocol: RestProtocol::Protobuf,
                    accept: Some(PROTOBUF_MEDIA_TYPE),
                    content_type: None,
                    body: None,
                })
            }
            RequestBody::Protobuf(encode) => {
                if raw_body.is_some() {
                    return Err(Error::InvalidPayload(
                        "this REST endpoint requires a structured protobuf request".into(),
                    ));
                }
                let value = json_body.unwrap_or_else(|| Value::Object(Map::new()));
                let body = encode(value)?;
                Ok(RestRequest {
                    protocol: RestProtocol::Protobuf,
                    accept: Some(PROTOBUF_MEDIA_TYPE),
                    content_type: Some(PROTOBUF_MEDIA_TYPE.into()),
                    body: Some(body),
                })
            }
            RequestBody::Raw => {
                if json_body.is_some() {
                    return Err(Error::InvalidPayload(
                        "this REST endpoint requires a raw request body".into(),
                    ));
                }
                let body = raw_body.ok_or_else(|| {
                    Error::InvalidPayload("this REST endpoint requires a raw request body".into())
                })?;
                Ok(RestRequest {
                    protocol: RestProtocol::Protobuf,
                    accept: Some(PROTOBUF_MEDIA_TYPE),
                    content_type: raw_content_type.map(str::to_owned),
                    body: Some(body),
                })
            }
        },
        Protocol::RawProtobufErrors => {
            if json_body.is_some() || raw_body.is_some() {
                return Err(Error::InvalidPayload(
                    "this REST endpoint does not accept a request body".into(),
                ));
            }
            Ok(RestRequest {
                protocol: RestProtocol::RawProtobufErrors,
                accept: Some(PROTOBUF_MEDIA_TYPE),
                content_type: None,
                body: None,
            })
        }
    }
}

/// Decodes a successful HTTP response using the endpoint's registered wire
/// contract. Raw media responses remain raw bytes; structured responses become
/// JSON bytes suitable for conversion by the platform binding.
pub fn finish_rest_response(
    method: &str,
    path_and_query: &str,
    status: u16,
    body: &[u8],
) -> Result<Vec<u8>> {
    let protocol = protocol_for(method, path_and_query)?;
    if !(200..300).contains(&status) {
        return Err(Error::Server {
            status,
            body: decode_http_error_body(protocol, body),
        });
    }

    match protocol {
        Protocol::Json if body.is_empty() => Ok(b"null".to_vec()),
        Protocol::Json | Protocol::RawProtobufErrors => Ok(body.to_vec()),
        Protocol::Protobuf(route) => decode_response_body(route, body),
    }
}

/// Converts an HTTP error body into the same text representation surfaced by
/// the native HTTP transport.
pub fn format_rest_error_body(method: &str, path_and_query: &str, body: &[u8]) -> String {
    match protocol_for(method, path_and_query) {
        Ok(protocol) => decode_http_error_body(protocol, body),
        Err(_) => String::from_utf8_lossy(body).into_owned(),
    }
}

#[cfg(feature = "native")]
pub(super) fn request_is_raw(route: &RouteSpec) -> bool {
    matches!(route.request, RequestBody::Raw)
}

#[cfg(feature = "native")]
pub(super) fn request_requires_protobuf(route: &RouteSpec) -> bool {
    matches!(route.request, RequestBody::Protobuf(_))
}

#[cfg(feature = "native")]
pub(super) fn encode_request_body(route: &RouteSpec, value: Value) -> Result<Option<Vec<u8>>> {
    match route.request {
        RequestBody::None => Ok(None),
        RequestBody::Raw => Err(Error::InvalidPayload(
            "this REST route requires a raw request body".into(),
        )),
        RequestBody::Protobuf(encode) => encode(value).map(Some),
    }
}

pub(super) fn decode_response_body(route: &RouteSpec, bytes: &[u8]) -> Result<Vec<u8>> {
    let Some((decode, shape)) = route.response else {
        return Ok(b"null".to_vec());
    };
    // An empty protobuf message is a valid encoding of a default response
    // (for example, an empty list wrapper). Bodyless routes are represented
    // explicitly by `response: None` above, so byte length cannot distinguish
    // those two cases.
    serde_json::to_vec(&decode(bytes, shape)?)
        .map_err(|error| Error::InvalidPayload(error.to_string()))
}

pub(super) fn decode_error_body(bytes: &[u8]) -> String {
    match crate::proto::rest::ErrorResponse::decode(bytes) {
        Ok(error) => {
            let mut value = serde_json::Map::new();
            value.insert("error".into(), Value::String(error.error));
            value.insert("message".into(), Value::String(error.message));
            if let Some(details) = error.details {
                let mut fields = Map::new();
                if let Some(v) = details.one_time_available {
                    fields.insert("one_time_available".into(), Value::from(v));
                }
                if let Some(v) = details.kyber_one_time_available {
                    fields.insert("kyber_one_time_available".into(), Value::from(v));
                }
                if let Some(v) = details.minimum_required {
                    fields.insert("minimum_required".into(), Value::from(v));
                }
                value.insert("details".into(), Value::Object(fields));
            }
            Value::Object(value).to_string()
        }
        Err(_) => String::from_utf8_lossy(bytes).into_owned(),
    }
}

pub(super) fn decode_http_error_body(protocol: Protocol, bytes: &[u8]) -> String {
    match protocol {
        Protocol::Protobuf(route) if route.path == "/health" => {
            match decode_response_body(route, bytes) {
                Ok(body) => String::from_utf8_lossy(&body).into_owned(),
                Err(_) => String::from_utf8_lossy(bytes).into_owned(),
            }
        }
        Protocol::Protobuf(_) | Protocol::RawProtobufErrors => decode_error_body(bytes),
        Protocol::Json => String::from_utf8_lossy(bytes).into_owned(),
    }
}

fn encode_request<M>(value: Value) -> Result<Vec<u8>>
where
    M: Message + Default + DeserializeOwned,
{
    let value = rewrite_json_keys(value, KeyDirection::ApiToProto);
    let value = wrap_list_fields(value);
    let message: M = serde_json::from_value(value).map_err(|error| {
        Error::InvalidPayload(format!("invalid protobuf REST request: {error}"))
    })?;
    Ok(message.encode_to_vec())
}

fn decode_response<M>(bytes: &[u8], shape: ResponseShape) -> Result<Value>
where
    M: Message + Default + Serialize,
{
    let message = M::decode(bytes).map_err(|error| {
        Error::InvalidPayload(format!("invalid protobuf REST response: {error}"))
    })?;
    let value =
        serde_json::to_value(message).map_err(|error| Error::InvalidPayload(error.to_string()))?;
    let value = rewrite_json_keys(value, KeyDirection::ProtoToApi);
    let value = normalize_prekey_public_key_aliases(value);
    let value = unwrap_items_wrappers(value);
    if matches!(shape, ResponseShape::Items) {
        return value
            .get("items")
            .cloned()
            .ok_or_else(|| Error::InvalidPayload("protobuf list response has no items".into()));
    }
    Ok(value)
}

#[derive(Clone, Copy)]
enum KeyDirection {
    ApiToProto,
    ProtoToApi,
}

fn rewrite_json_keys(value: Value, direction: KeyDirection) -> Value {
    match value {
        Value::Array(values) => Value::Array(
            values
                .into_iter()
                .map(|value| rewrite_json_keys(value, direction))
                .collect(),
        ),
        Value::Object(object) => {
            let mut mapped = Map::with_capacity(object.len());
            for (key, value) in object {
                let key = match direction {
                    KeyDirection::ApiToProto if key == "pub" => "publicKey".into(),
                    KeyDirection::ApiToProto => snake_to_camel(&key),
                    KeyDirection::ProtoToApi => camel_to_snake(&key),
                };
                mapped.insert(key, rewrite_json_keys(value, direction));
            }
            Value::Object(mapped)
        }
        other => other,
    }
}

fn normalize_prekey_public_key_aliases(value: Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(
            values
                .into_iter()
                .map(normalize_prekey_public_key_aliases)
                .collect(),
        ),
        Value::Object(object) => {
            let mut mapped = Map::with_capacity(object.len());
            for (key, value) in object {
                mapped.insert(key, normalize_prekey_public_key_aliases(value));
            }
            if mapped.contains_key("id") {
                if let Some(public_key) = mapped.remove("public_key") {
                    mapped.insert("pub".into(), public_key);
                }
            }
            Value::Object(mapped)
        }
        other => other,
    }
}

fn wrap_list_fields(value: Value) -> Value {
    const WRAPPED_FIELDS: &[&str] = &[
        "accountIds",
        "handles",
        "fields",
        "optionIds",
        "interests",
        "chunkSizes",
    ];
    match value {
        Value::Array(values) => Value::Array(values.into_iter().map(wrap_list_fields).collect()),
        Value::Object(object) => {
            let mut mapped = Map::with_capacity(object.len());
            for (key, value) in object {
                let value = wrap_list_fields(value);
                let value = if WRAPPED_FIELDS.contains(&key.as_str()) && value.is_array() {
                    let mut wrapper = Map::new();
                    wrapper.insert("items".into(), value);
                    Value::Object(wrapper)
                } else {
                    value
                };
                mapped.insert(key, value);
            }
            Value::Object(mapped)
        }
        other => other,
    }
}

fn unwrap_items_wrappers(value: Value) -> Value {
    match value {
        Value::Array(values) => {
            Value::Array(values.into_iter().map(unwrap_items_wrappers).collect())
        }
        Value::Object(object) => {
            let mut mapped = Map::with_capacity(object.len());
            for (key, value) in object {
                let value = unwrap_items_wrappers(value);
                let value = match value {
                    Value::Object(mut wrapper)
                        if wrapper.len() == 1 && wrapper.contains_key("items") =>
                    {
                        wrapper.remove("items").unwrap_or(Value::Null)
                    }
                    other => other,
                };
                mapped.insert(key, value);
            }
            Value::Object(mapped)
        }
        other => other,
    }
}

fn snake_to_camel(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    let mut uppercase_next = false;
    for character in value.chars() {
        if character == '_' {
            uppercase_next = true;
        } else if uppercase_next {
            output.extend(character.to_uppercase());
            uppercase_next = false;
        } else {
            output.push(character);
        }
    }
    output
}

fn camel_to_snake(value: &str) -> String {
    let mut output = String::with_capacity(value.len() + 4);
    for character in value.chars() {
        if character.is_ascii_uppercase() {
            output.push('_');
            output.push(character.to_ascii_lowercase());
        } else {
            output.push(character);
        }
    }
    output
}

fn path_matches(pattern: &str, path: &str) -> bool {
    let mut pattern_segments = pattern.split('/').filter(|part| !part.is_empty());
    let mut path_segments = path.split('/').filter(|part| !part.is_empty());
    loop {
        match (pattern_segments.next(), path_segments.next()) {
            (None, None) => return true,
            (Some(pattern), Some(value)) if pattern.starts_with('{') && pattern.ends_with('}') => {
                if value.is_empty() {
                    return false;
                }
            }
            (Some(pattern), Some(value)) if pattern == value => {}
            _ => return false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_request_uses_protobuf_codec() {
        let Protocol::Protobuf(route) = protocol_for("POST", "/api/v1/register").unwrap() else {
            panic!("register must use protobuf");
        };
        let encoded = encode_request_body(route, serde_json::json!({"password": "secret"}))
            .unwrap()
            .unwrap();
        let decoded = identity::RegisterRequest::decode(encoded.as_slice()).unwrap();
        assert_eq!(decoded.password.as_deref(), Some("secret"));
    }

    #[test]
    fn public_rest_request_api_uses_the_registered_protobuf_contract() {
        let request = prepare_rest_request(
            "POST",
            "/api/v1/register",
            Some(serde_json::json!({"password": "secret"})),
            None,
            None,
        )
        .unwrap();
        assert_eq!(request.protocol, RestProtocol::Protobuf);
        assert_eq!(request.accept, Some(PROTOBUF_MEDIA_TYPE));
        assert_eq!(request.content_type.as_deref(), Some(PROTOBUF_MEDIA_TYPE));
        let encoded = request.body.unwrap();
        let decoded = identity::RegisterRequest::decode(encoded.as_slice()).unwrap();
        assert_eq!(decoded.password.as_deref(), Some("secret"));
    }

    #[test]
    fn public_rest_request_api_preserves_json_routes_and_raw_downloads() {
        let bot_request = prepare_rest_request(
            "POST",
            "/api/bot/v1/answerCallbackQuery",
            Some(serde_json::json!({"callback_query_id": "callback"})),
            None,
            None,
        )
        .unwrap();
        assert_eq!(bot_request.protocol, RestProtocol::Json);
        assert_eq!(bot_request.accept, None);
        assert_eq!(
            bot_request.content_type.as_deref(),
            Some("application/json")
        );
        assert_eq!(
            serde_json::from_slice::<Value>(bot_request.body.as_deref().unwrap()).unwrap(),
            serde_json::json!({"callback_query_id": "callback"})
        );

        let avatar_request =
            prepare_rest_request("GET", "/api/v1/avatars/account", None, None, None).unwrap();
        assert_eq!(avatar_request.protocol, RestProtocol::RawProtobufErrors);
        assert_eq!(avatar_request.accept, Some(PROTOBUF_MEDIA_TYPE));
        assert_eq!(avatar_request.body, None);
    }

    #[test]
    fn public_rest_response_api_decodes_protobuf_and_keeps_raw_bytes() {
        let me = identity::MeResponse {
            id: "account".into(),
            user_id: 17,
            ..Default::default()
        }
        .encode_to_vec();
        let decoded: Value =
            serde_json::from_slice(&finish_rest_response("GET", "/api/v1/me", 200, &me).unwrap())
                .unwrap();
        assert_eq!(decoded["id"], "account");
        // Native and portable Rust DTOs use snake_case after decoding; the
        // browser binding maps this portable shape back to WEB camelCase.
        assert_eq!(decoded["user_id"], 17);

        let raw = b"image bytes";
        assert_eq!(
            finish_rest_response("GET", "/api/v1/avatars/account", 200, raw).unwrap(),
            raw
        );
        assert_eq!(
            finish_rest_response("POST", "/api/bot/v1/answerCallbackQuery", 204, &[]).unwrap(),
            b"null"
        );
    }

    #[test]
    fn list_response_unwraps_the_contract_wrapper() {
        let Protocol::Protobuf(route) = protocol_for("GET", "/api/v1/contacts").unwrap() else {
            panic!("contacts must use protobuf");
        };
        assert!(route.response.is_some());
        let encoded = identity::ContactsResponse { items: Vec::new() }.encode_to_vec();
        let decoded: Value =
            serde_json::from_slice(&decode_response_body(route, &encoded).unwrap()).unwrap();
        assert_eq!(decoded, serde_json::json!([]));
    }

    #[test]
    fn string_list_request_wrapper_is_encoded() {
        let Protocol::Protobuf(route) = protocol_for("POST", "/api/v1/accounts/batch").unwrap()
        else {
            panic!("accounts batch must use protobuf");
        };
        let encoded = encode_request_body(route, serde_json::json!({"account_ids": ["a", "b"]}))
            .unwrap()
            .unwrap();
        let decoded = identity::AccountsBatchRequest::decode(encoded.as_slice()).unwrap();
        assert_eq!(decoded.account_ids.unwrap().items, ["a", "b"]);
    }

    #[test]
    fn uint64_list_request_wrapper_is_encoded() {
        let Protocol::Protobuf(route) = protocol_for("POST", "/api/v1/attachments/init").unwrap()
        else {
            panic!("attachment init must use protobuf");
        };
        let encoded = encode_request_body(route, serde_json::json!({"chunk_sizes": [1, 2]}))
            .unwrap()
            .unwrap();
        let decoded = community::InitAttachmentRequest::decode(encoded.as_slice()).unwrap();
        assert_eq!(decoded.chunk_sizes.unwrap().items, [1, 2]);
    }

    #[test]
    fn prekey_json_alias_is_preserved_on_the_wire() {
        let Protocol::Protobuf(route) = protocol_for("POST", "/api/v1/devices/me/prekeys").unwrap()
        else {
            panic!("prekey upload must use protobuf");
        };
        let encoded = encode_request_body(
            route,
            serde_json::json!({
                "signed_prekey": {"id": 7, "pub": "key", "sig": "signature"}
            }),
        )
        .unwrap()
        .unwrap();
        let decoded = identity::UploadPrekeysRequest::decode(encoded.as_slice()).unwrap();
        assert_eq!(
            decoded.signed_prekey.unwrap().public_key.as_deref(),
            Some("key")
        );
    }

    #[test]
    fn prekey_response_uses_pub_alias_without_renaming_vapid_key() {
        let Protocol::Protobuf(vapid_route) = protocol_for("GET", "/api/v1/push/vapid").unwrap()
        else {
            panic!("VAPID route must use protobuf");
        };
        let vapid = identity::VapidResponse {
            public_key: "vapid-key".into(),
            subject: "mailto:push@example.test".into(),
        }
        .encode_to_vec();
        let vapid: Value =
            serde_json::from_slice(&decode_response_body(vapid_route, &vapid).unwrap()).unwrap();
        assert_eq!(vapid["public_key"], "vapid-key");
        assert!(vapid.get("pub").is_none());

        let Protocol::Protobuf(prekey_route) =
            protocol_for("GET", "/api/v1/accounts/account/devices/1/bundle").unwrap()
        else {
            panic!("prekey bundle route must use protobuf");
        };
        let prekeys = identity::PrekeyBundleResponse {
            one_time_prekey: Some(identity::PrekeyRef {
                id: Some(7),
                public_key: Some("prekey-public".into()),
            }),
            ..Default::default()
        }
        .encode_to_vec();
        let prekeys: Value =
            serde_json::from_slice(&decode_response_body(prekey_route, &prekeys).unwrap()).unwrap();
        assert_eq!(prekeys["one_time_prekey"]["id"], 7);
        assert_eq!(prekeys["one_time_prekey"]["pub"], "prekey-public");
        assert!(prekeys["one_time_prekey"].get("public_key").is_none());
    }

    #[test]
    fn protocol_exceptions_are_explicit_and_unknown_api_paths_fail_closed() {
        assert!(matches!(
            protocol_for("POST", "/api/bot/v1/messages").unwrap(),
            Protocol::Json
        ));
        assert!(matches!(
            protocol_for(
                "GET",
                "/api/v1/avatars/00000000-0000-0000-0000-000000000000"
            )
            .unwrap(),
            Protocol::RawProtobufErrors
        ));
        assert!(matches!(
            protocol_for("GET", "/health").unwrap(),
            Protocol::Protobuf(_)
        ));
        assert!(protocol_for("GET", "/api/v1/not-registered").is_err());
    }

    #[test]
    fn avatar_download_decodes_only_first_party_api_errors() {
        assert_eq!(
            classify_avatar_initial_response(200, false),
            AvatarInitialResponse::RawBytes
        );
        assert_eq!(
            classify_avatar_initial_response(302, true),
            AvatarInitialResponse::FollowStorageRedirect
        );
        assert_eq!(
            classify_avatar_initial_response(302, false),
            AvatarInitialResponse::RawRedirectError
        );
        assert_eq!(
            classify_avatar_initial_response(403, false),
            AvatarInitialResponse::ApiProtobufError
        );
    }

    #[test]
    fn health_error_body_keeps_health_response_fields() {
        let encoded = crate::proto::rest::HealthResponse {
            status: "degraded".into(),
            version: "0.1.0".into(),
            uptime_secs: 12,
            database: "down".into(),
            timestamp: 34,
        }
        .encode_to_vec();
        let Protocol::Protobuf(route) = protocol_for("GET", "/health").unwrap() else {
            panic!("health must use protobuf");
        };

        let body: Value =
            serde_json::from_str(&decode_http_error_body(Protocol::Protobuf(route), &encoded))
                .unwrap();
        assert_eq!(body["status"], "degraded");
        assert_eq!(body["database"], "down");
    }
}
