//! Named browser REST operations mirroring the public operations in
//! `friendshubWEB/src/api`. Callers pass JS objects with camelCase fields;
//! this module handles route construction, query encoding, and protobuf wire
//! field conversion before delegating to [`super::BrowserRestClient`].

use super::BrowserRestClient;
use js_sys::{Array, Error as JsError, Reflect, Uint8Array};
use serde_json::{Map, Number, Value};
use wasm_bindgen::JsCast;
use wasm_bindgen::prelude::*;
use web_sys::AbortSignal;

#[wasm_bindgen]
pub struct BrowserApi {
    api_base: String,
    rest: BrowserRestClient,
    session_token: Option<String>,
    device_number: Option<u32>,
    timeout_ms: u32,
}

#[wasm_bindgen]
impl BrowserApi {
    /// Creates the operation-oriented API using the same `/api/v1` base URL as
    /// [`BrowserRestClient`]. Authentication is set later with `setSession`.
    #[wasm_bindgen(constructor)]
    pub fn new(api_base: String) -> Result<BrowserApi, JsValue> {
        Ok(Self {
            rest: BrowserRestClient::new(api_base.clone())?,
            api_base,
            session_token: None,
            device_number: None,
            timeout_ms: super::DEFAULT_TIMEOUT_MS,
        })
    }

    /// Stores the current account session and device routing number.
    /// Pass null/undefined for `deviceNumber` to omit `X-Device-Number`.
    #[wasm_bindgen(js_name = setSession)]
    pub fn set_session(&mut self, session_token: String, device_number: Option<u32>) {
        self.session_token = Some(session_token);
        self.device_number = device_number;
        self.rest.set_device_number(device_number);
    }

    /// Clears the account session and device routing number.
    #[wasm_bindgen(js_name = clearSession)]
    pub fn clear_session(&mut self) {
        self.session_token = None;
        self.device_number = None;
        self.rest.set_device_number(None);
    }

    /// Changes the Fetch timeout used by all subsequent operations.
    #[wasm_bindgen(js_name = setTimeoutMs)]
    pub fn set_timeout_ms(&mut self, timeout_ms: u32) -> Result<(), JsValue> {
        self.rest.set_timeout_ms(timeout_ms)?;
        self.timeout_ms = timeout_ms;
        Ok(())
    }
}

impl BrowserApi {
    async fn invoke(
        &self,
        method: &'static str,
        template: &str,
        input: JsValue,
        authenticated: bool,
        query_aliases: &[(&str, &str)],
    ) -> Result<JsValue, JsValue> {
        self.invoke_with_headers(
            method,
            template,
            input,
            authenticated,
            query_aliases,
            Vec::new(),
        )
        .await
    }

    async fn invoke_with_headers(
        &self,
        method: &'static str,
        template: &str,
        input: JsValue,
        authenticated: bool,
        query_aliases: &[(&str, &str)],
        extra_headers: Vec<(String, String)>,
    ) -> Result<JsValue, JsValue> {
        let signal = signal_from_input(&input);
        let mut params = input_to_object(input)?;
        let path = resolve_path(template, &mut params)?;
        let token = authenticated.then(|| self.session_token.clone()).flatten();

        if method == "GET" {
            flatten_query_groups(&mut params);
            alias_query_keys(&mut params, query_aliases);
            let url = append_query(&path, params)?;
            self.rest
                .request_with_options(
                    method.to_owned(),
                    url,
                    None,
                    token,
                    signal,
                    None,
                    extra_headers,
                    authenticated,
                )
                .await
        } else {
            remove_transport_fields(&mut params);
            let body = if params.is_empty() {
                None
            } else {
                let json = camel_to_snake_json(Value::Object(params));
                Some(super::json_to_js_value(&json).map_err(|error| error.into_js())?)
            };
            self.rest
                .request_with_options(
                    method.to_owned(),
                    path,
                    body,
                    token,
                    signal,
                    None,
                    extra_headers,
                    authenticated,
                )
                .await
        }
    }

    async fn raw(
        &self,
        method: &'static str,
        path: String,
        body: JsValue,
        content_type: Option<String>,
        authenticated: bool,
        response_type: Option<&'static str>,
    ) -> Result<JsValue, JsValue> {
        self.raw_with_options(
            method,
            path,
            body,
            content_type,
            authenticated,
            true,
            response_type,
        )
        .await
    }

    async fn raw_with_options(
        &self,
        method: &'static str,
        path: String,
        body: JsValue,
        content_type: Option<String>,
        authenticated: bool,
        include_device_number: bool,
        response_type: Option<&'static str>,
    ) -> Result<JsValue, JsValue> {
        let mut rest = BrowserRestClient::new(self.api_base.clone())?;
        rest.set_timeout_ms(self.timeout_ms)?;
        if include_device_number {
            rest.set_device_number(self.device_number);
        }
        rest.request_raw(
            method.to_owned(),
            path,
            body,
            content_type,
            authenticated.then(|| self.session_token.clone()).flatten(),
            None,
            response_type.map(str::to_owned),
        )
        .await
    }

    async fn invoke_with_token(
        &self,
        method: &'static str,
        path: &str,
        input: JsValue,
        token: Option<String>,
        timeout_ms: Option<u32>,
        external_signal: Option<AbortSignal>,
    ) -> Result<JsValue, JsValue> {
        let mut params = input_to_object(input)?;
        flatten_query_groups(&mut params);
        let url = append_query(path, params)?;
        let mut rest = BrowserRestClient::new(self.api_base.clone())?;
        if let Some(timeout_ms) = timeout_ms {
            rest.set_timeout_ms(timeout_ms)?;
        }
        rest.request(method.to_owned(), url, None, token, external_signal, None)
            .await
    }
}

macro_rules! browser_api_methods {
    ($(($name:ident, $method:literal, $path:literal, $arguments:ident, $auth:literal, $aliases:expr)),+ $(,)?) => {
        $(browser_api_methods!(@method $name, $method, $path, $arguments, $auth, $aliases);)+
    };
    (@method $name:ident, $method:literal, $path:literal, none, $auth:literal, $aliases:expr) => {
        #[wasm_bindgen]
        impl BrowserApi {
            #[wasm_bindgen(js_name = $name)]
            #[allow(non_snake_case)]
            pub async fn $name(&self) -> Result<JsValue, JsValue> {
                self.invoke($method, $path, JsValue::UNDEFINED, $auth, $aliases).await
            }
        }
    };
    (@method $name:ident, $method:literal, $path:literal, input, $auth:literal, $aliases:expr) => {
        #[wasm_bindgen]
        impl BrowserApi {
            #[wasm_bindgen(js_name = $name)]
            #[allow(non_snake_case)]
            pub async fn $name(&self, input: JsValue) -> Result<JsValue, JsValue> {
                self.invoke($method, $path, input, $auth, $aliases).await
            }
        }
    };
}

// This list follows direct REST operations exported by the WEB API modules.
// JS argument objects contain only operation fields; session credentials are
// held on BrowserApi and never copied into request bodies.
browser_api_methods! {
    (register, "POST", "/register", input, false, &[]),
    (login, "POST", "/login", input, false, &[]),
    (loginWithTotp, "POST", "/login/2fa", input, false, &[]),
    (logout, "POST", "/logout", none, true, &[]),
    (getMe, "GET", "/me", none, true, &[]),
    (enrollTotp, "POST", "/2fa/enroll", none, true, &[]),
    (verifyTotpEnrollment, "POST", "/2fa/enroll/verify", input, true, &[]),
    (disableTotp, "POST", "/2fa/disable", input, true, &[]),
    (initiateAccountDeletion, "POST", "/account/delete/initiate", none, true, &[]),
    (confirmAccountDeletion, "POST", "/account/delete/confirm", input, true, &[]),
    (cancelAccountDeletion, "POST", "/account/delete/cancel", none, true, &[]),
    (getAccountDeletionStatus, "GET", "/account/delete/status", none, true, &[]),
    (listSessions, "GET", "/sessions", none, true, &[]),
    (revokeSession, "DELETE", "/sessions/{sessionId}", input, true, &[]),
    (listContacts, "GET", "/contacts", none, true, &[]),
    (searchContacts, "GET", "/contacts/search", input, true, &[("query", "q")]),
    (addContact, "POST", "/contacts", input, true, &[]),
    (removeContact, "DELETE", "/contacts/{targetAccountId}", input, true, &[]),
    (listBlocks, "GET", "/blocks", none, true, &[]),
    (blockAccount, "POST", "/blocks/{targetAccountId}", input, true, &[]),
    (unblockAccount, "DELETE", "/blocks/{targetAccountId}", input, true, &[]),
    (getProfilePrivacy, "GET", "/profile/privacy", none, true, &[]),
    (setProfileHidden, "PUT", "/profile/privacy/hide-profile", input, true, &[]),
    (setProfileHiddenFromSearch, "PUT", "/profile/privacy/hide-from-search", input, true, &[]),
    (listProfileExceptions, "GET", "/profile/privacy/profile-exceptions", none, true, &[]),
    (addProfileException, "POST", "/profile/privacy/profile-exceptions", input, true, &[]),
    (removeProfileException, "DELETE", "/profile/privacy/profile-exceptions/{targetAccountId}", input, true, &[]),
    (setUsername, "PUT", "/profile/username", input, true, &[]),
    (setStatus, "PUT", "/profile/status", input, true, &[]),
    (clearStatus, "DELETE", "/profile/status", none, true, &[]),
    (setInvisible, "PUT", "/profile/invisible", input, true, &[]),
    (getAllowNudges, "GET", "/profile/allow-nudges", none, true, &[]),
    (setAllowNudges, "PUT", "/profile/allow-nudges", input, true, &[]),
    (getInvisible, "GET", "/profile/invisible", none, true, &[]),
    (listPresenceExceptions, "GET", "/profile/presence-exceptions", none, true, &[]),
    (addPresenceException, "POST", "/profile/presence-exceptions", input, true, &[]),
    (removePresenceException, "POST", "/profile/presence-exceptions/remove", input, true, &[]),
    (getAccountProfile, "GET", "/accounts/{targetAccountId}/profile", input, true, &[]),
    (getAccountPresence, "GET", "/accounts/{targetAccountId}/presence", input, true, &[]),
    (getProfileFields, "GET", "/profile/fields", none, true, &[]),
    (setProfileFields, "PUT", "/profile/fields", input, true, &[]),
    (getDmPolicy, "GET", "/profile/dm-policy", none, true, &[]),
    (setDmPolicy, "PUT", "/profile/dm-policy", input, true, &[]),
    (getGroupAddPolicy, "GET", "/profile/group-add-policy", none, true, &[]),
    (setGroupAddPolicy, "PUT", "/profile/group-add-policy", input, true, &[]),
    (listGroupAddExceptions, "GET", "/profile/group-add-exceptions", none, true, &[]),
    (addGroupAddException, "POST", "/profile/group-add-exceptions", input, true, &[]),
    (removeGroupAddException, "DELETE", "/profile/group-add-exceptions/{accountId}", input, true, &[]),
    (listConversations, "GET", "/conversations", none, true, &[]),
    (createDirectConversation, "POST", "/conversations/direct", input, true, &[]),
    (markConversationRead, "POST", "/conversations/{conversationId}/read", input, true, &[]),
    (getConversationReads, "GET", "/conversations/{conversationId}/reads", input, true, &[]),
    (getConversation, "GET", "/conversations/{conversationId}", input, true, &[]),
    (leaveConversation, "POST", "/conversations/{conversationId}/leave", input, true, &[]),
    (archiveConversation, "POST", "/conversations/{conversationId}/archive", input, true, &[]),
    (unarchiveConversation, "DELETE", "/conversations/{conversationId}/archive", input, true, &[]),
    (muteConversation, "POST", "/conversations/{conversationId}/mute", input, true, &[]),
    (unmuteConversation, "DELETE", "/conversations/{conversationId}/mute", input, true, &[]),
    (getConversationEnvelopes, "GET", "/conversations/{conversationId}/envelopes", input, true, &[]),
    (listOwnDevices, "GET", "/devices", none, true, &[]),
    (revokeDevice, "DELETE", "/devices/{deviceId}", input, true, &[]),
    (listPeerDevices, "GET", "/accounts/{peerAccountId}/devices", input, true, &[]),
    (uploadPrekeys, "POST", "/devices/me/prekeys", input, true, &[]),
    (getPrekeyStatus, "GET", "/devices/me/prekeys/status", none, true, &[]),
    (getSavedConversation, "GET", "/saved", none, true, &[]),
    (listScheduled, "GET", "/scheduled", none, true, &[]),
    (cancelScheduled, "DELETE", "/scheduled/{envelopeId}", input, true, &[]),
    (recommendChunkSize, "POST", "/attachments/recommend", input, true, &[]),
    (initAttachment, "POST", "/attachments/init", input, true, &[]),
    (finalizeAttachment, "POST", "/attachments/{attachmentId}/finalize", input, true, &[]),
    (claimAttachment, "POST", "/attachments/{attachmentId}/claim", input, true, &[]),
    (releaseAttachment, "POST", "/attachments/{attachmentId}/release", input, true, &[]),
    (getAttachmentChunks, "GET", "/attachments/{attachmentId}", input, true, &[]),
    (pinMessage, "POST", "/conversations/{conversationId}/pinned", input, true, &[]),
    (unpinMessage, "DELETE", "/conversations/{conversationId}/pinned/{messageId}", input, true, &[]),
    (listPinnedMessages, "GET", "/conversations/{conversationId}/pinned", input, true, &[]),
    (listPolls, "GET", "/conversations/{conversationId}/polls", input, true, &[]),
    (getPoll, "GET", "/polls/{pollId}", input, true, &[]),
    (votePoll, "POST", "/polls/{pollId}/vote", input, true, &[]),
    (stopPoll, "POST", "/polls/{pollId}/stop", input, true, &[]),
    (deletePoll, "DELETE", "/polls/{pollId}", input, true, &[]),
    (addPollOption, "POST", "/polls/{pollId}/options", input, true, &[]),
    (deletePollOption, "DELETE", "/polls/{pollId}/options/{optionId}", input, true, &[]),
    (createGroup, "POST", "/groups", input, true, &[]),
    (listPublicGroups, "GET", "/groups/public", input, true, &[]),
    (joinGroup, "POST", "/groups/{conversationId}/join", input, true, &[]),
    (getGroupByHandle, "GET", "/groups/by-handle/{handle}", input, true, &[]),
    (listGroupMembers, "GET", "/groups/{conversationId}/members", input, true, &[]),
    (setGroupMemberTag, "PUT", "/groups/{conversationId}/members/{targetAccountId}/tag", input, true, &[]),
    (removeGroupMemberTag, "DELETE", "/groups/{conversationId}/members/{targetAccountId}/tag", input, true, &[]),
    (setMemberRole, "POST", "/groups/{conversationId}/members/role", input, true, &[]),
    (muteMember, "POST", "/groups/{conversationId}/members/mute", input, true, &[]),
    (setGroupHandle, "POST", "/groups/{conversationId}/profile", input, true, &[]),
    (createInvite, "POST", "/conversations/{conversationId}/invites", input, true, &[]),
    (listInvites, "GET", "/conversations/{conversationId}/invites", input, true, &[]),
    (revokeInvite, "DELETE", "/invites/{inviteId}", input, true, &[]),
    (getGroup, "GET", "/groups/{conversationId}", input, true, &[]),
    (updateGroup, "PATCH", "/groups/{conversationId}", input, true, &[]),
    (deleteGroup, "DELETE", "/groups/{conversationId}", input, true, &[]),
    (transferGroupOwnership, "POST", "/groups/{conversationId}/owner", input, true, &[]),
    (addGroupMember, "POST", "/groups/{conversationId}/members", input, true, &[]),
    (removeGroupMember, "DELETE", "/groups/{conversationId}/members/{accountId}", input, true, &[]),
    (banGroupMember, "POST", "/groups/{conversationId}/bans", input, true, &[]),
    (listGroupBans, "GET", "/groups/{conversationId}/bans", input, true, &[]),
    (unbanGroupMember, "DELETE", "/groups/{conversationId}/bans/{accountId}", input, true, &[]),
    (createChannel, "POST", "/channels", input, true, &[]),
    (listChannelMembers, "GET", "/channels/{channelId}/members", input, true, &[]),
    (setChannelMemberRole, "POST", "/channels/{channelId}/members/role", input, true, &[]),
    (removeChannelMember, "POST", "/channels/{channelId}/members/remove", input, true, &[]),
    (setLinkedGroup, "POST", "/channels/{channelId}/linked-group", input, true, &[]),
    (setChannelPublic, "POST", "/channels/{channelId}/public", input, true, &[]),
    (setChannelHandle, "POST", "/channels/{channelId}/profile", input, true, &[]),
    (addChannelBot, "POST", "/channels/{channelId}/bots", input, true, &[]),
    (subscribeChannel, "POST", "/channels/{channelId}/subscribe", input, true, &[]),
    (unsubscribeChannel, "DELETE", "/channels/{channelId}/subscribe", input, true, &[]),
    (getChannel, "GET", "/channels/{channelId}", input, true, &[]),
    (listPublicChannels, "GET", "/channels/public", input, true, &[]),
    (getChannelByHandle, "GET", "/channels/by-handle/{handle}", input, true, &[]),
    (deleteChannel, "DELETE", "/channels/{channelId}", input, true, &[]),
    (transferChannelOwnership, "POST", "/channels/{channelId}/owner", input, true, &[]),
    (getChannelAnalytics, "GET", "/channels/{channelId}/analytics", input, true, &[]),
    (listChannelPosts, "GET", "/channels/{channelId}/posts", input, true, &[]),
    (editChannelPost, "PATCH", "/channel-posts/{postId}", input, true, &[]),
    (deleteChannelPost, "DELETE", "/channel-posts/{postId}", input, true, &[]),
    (pinChannelPost, "POST", "/channel-posts/{postId}/pin", input, true, &[]),
    (unpinChannelPost, "DELETE", "/channel-posts/{postId}/pin", input, true, &[]),
    (listPinnedPosts, "GET", "/channels/{channelId}/pinned", input, true, &[]),
    (listPostReactions, "GET", "/channel-posts/{postId}/reactions", input, true, &[]),
    (getChannelPost, "GET", "/channel-posts/{postId}", input, true, &[]),
    (addPostReaction, "POST", "/channel-posts/{postId}/reactions", input, true, &[]),
    (removePostReaction, "DELETE", "/channel-posts/{postId}/reactions", input, true, &[]),
    (getPostDiscussion, "GET", "/channel-posts/{postId}/discussion", input, true, &[]),
    (getDiscoverProfile, "GET", "/discover/profile", none, true, &[]),
    (saveDiscoverProfile, "PUT", "/discover/profile", input, true, &[]),
    (hideDiscoverProfile, "DELETE", "/discover/profile", none, true, &[]),
    (listDiscoverProfiles, "GET", "/discover", input, true, &[("query", "q")]),
    (getDiscoverProfileDetails, "GET", "/discover/{accountId}", input, true, &[]),
    (resolveHandle, "GET", "/handles/{handle}", input, true, &[]),
    (checkHandleAvailability, "GET", "/handles/{handle}/available", input, true, &[]),
    (listSecurityEvents, "GET", "/security/events", input, true, &[]),
    (getIceServers, "GET", "/webrtc/ice-servers", none, true, &[]),
    (recordCall, "POST", "/calls", input, true, &[]),
    (listCalls, "GET", "/calls", input, true, &[]),
    (deleteCall, "DELETE", "/calls/{callId}", input, true, &[]),
    (clearCallHistory, "POST", "/calls/clear", none, true, &[]),
    (listFolders, "GET", "/folders", none, true, &[]),
    (createFolder, "POST", "/folders", input, true, &[]),
    (updateFolder, "PATCH", "/folders/{folderId}", input, true, &[]),
    (deleteFolder, "DELETE", "/folders/{folderId}", input, true, &[]),
    (addConversationToFolder, "POST", "/folders/{folderId}/items", input, true, &[]),
    (removeConversationFromFolder, "DELETE", "/folders/{folderId}/items/{conversationId}", input, true, &[]),
    (getBotInfo, "GET", "/bots/{botId}/info", input, true, &[]),
    (listOwnedBots, "GET", "/user/bots", none, true, &[]),
    (listBotMessages, "GET", "/bots/{botId}/messages", input, true, &[]),
    (sendBotMessage, "POST", "/bots/{botId}/messages", input, true, &[]),
    (listBots, "GET", "/bots", none, true, &[]),
    (createBot, "POST", "/bots", none, true, &[]),
    (setBotHandle, "POST", "/bots/{botId}/profile", input, true, &[]),
    (rotateBotToken, "POST", "/bots/{botId}/rotate-token", input, true, &[]),
    (deleteBot, "DELETE", "/bots/{botId}", input, true, &[]),
}

#[wasm_bindgen]
impl BrowserApi {
    /// Returns full encrypted-message history for the current device.
    #[wasm_bindgen(js_name = getSavedMessages)]
    pub async fn get_saved_messages(&self, input: JsValue) -> Result<JsValue, JsValue> {
        let response = self
            .invoke("GET", "/saved/messages", input, true, &[])
            .await?;
        property(&response, "envelopes")
            .ok_or_else(|| js_error("saved response is missing envelopes"))
    }

    /// Revokes all account sessions and returns the WEB-compatible count.
    #[wasm_bindgen(js_name = revokeAllSessions)]
    pub async fn revoke_all_sessions(&self) -> Result<JsValue, JsValue> {
        let response = self
            .invoke(
                "POST",
                "/sessions/revoke-all",
                JsValue::UNDEFINED,
                true,
                &[],
            )
            .await?;
        property(&response, "revoked")
            .ok_or_else(|| js_error("session response is missing revoked"))
    }

    /// Returns only the channel publication permission boolean.
    #[wasm_bindgen(js_name = canPublish)]
    pub async fn can_publish(&self, channel_id: String) -> Result<JsValue, JsValue> {
        let response = self
            .invoke(
                "GET",
                "/channels/{channelId}/can-publish",
                json_to_js(&serde_json::json!({ "channelId": channel_id }))?,
                true,
                &[],
            )
            .await?;
        property(&response, "canPublish")
            .ok_or_else(|| js_error("publish response is missing canPublish"))
    }

    /// Creates a poll in a conversation using WEB's request shape.
    #[wasm_bindgen(js_name = createPoll)]
    pub async fn create_poll(
        &self,
        conversation_id: String,
        input: JsValue,
    ) -> Result<JsValue, JsValue> {
        let mut params = input_to_object(input)?;
        params.insert("conversationId".to_owned(), Value::String(conversation_id));
        self.invoke(
            "POST",
            "/conversations/{conversationId}/polls",
            json_to_js(&Value::Object(params))?,
            true,
            &[],
        )
        .await
    }

    /// Resolves an invite and returns its conversation ID, matching WEB.
    #[wasm_bindgen(js_name = joinByInvite)]
    pub async fn join_by_invite(&self, token: String) -> Result<JsValue, JsValue> {
        let response = self
            .invoke(
                "POST",
                "/invites/join/{token}",
                json_to_js(&serde_json::json!({ "token": token }))?,
                true,
                &[],
            )
            .await?;
        property(&response, "conversationId")
            .ok_or_else(|| js_error("invite response is missing conversationId"))
    }

    /// Creates a channel post with WEB's required `Idempotency-Key` header.
    #[wasm_bindgen(js_name = createChannelPost)]
    pub async fn create_channel_post(
        &self,
        channel_id: String,
        input: JsValue,
        idempotency_key: String,
    ) -> Result<JsValue, JsValue> {
        let mut params = input_to_object(input)?;
        params.insert("channelId".to_owned(), Value::String(channel_id));
        params.remove("idempotencyKey");
        self.invoke_with_headers(
            "POST",
            "/channels/{channelId}/posts",
            json_to_js(&Value::Object(params))?,
            true,
            &[],
            vec![("Idempotency-Key".to_owned(), idempotency_key)],
        )
        .await
    }

    /// Returns the peer prekey bundle with its wire keys intact, as WEB expects.
    #[wasm_bindgen(js_name = getPeerBundle)]
    pub async fn get_peer_bundle(
        &self,
        peer_account_id: String,
        device_number: u32,
    ) -> Result<JsValue, JsValue> {
        let response = self
            .invoke(
                "GET",
                "/accounts/{peerAccountId}/devices/{deviceNumber}/bundle",
                json_to_js(&serde_json::json!({ "peerAccountId": peer_account_id, "deviceNumber": device_number }))?,
                true,
                &[],
            )
            .await?;
        let json = super::js_value_to_json(response).map_err(|error| error.into_js())?;
        json_to_js(&camel_to_snake_json(json))
    }

    /// Registers the current device using the session token without sending a
    /// device-routing header, matching WEB's `registerDevice` request.
    #[wasm_bindgen(js_name = registerDevice)]
    pub async fn register_device(&self, input: JsValue) -> Result<JsValue, JsValue> {
        let params = input_to_object(input)?;
        let body = json_to_js(&camel_to_snake_json(Value::Object(params)))?;
        let rest = BrowserRestClient::new(self.api_base.clone())?;
        rest.request_with_options(
            "POST".to_owned(),
            "/devices".to_owned(),
            Some(body),
            self.session_token.clone(),
            None,
            None,
            Vec::new(),
            false,
        )
        .await
    }

    /// Resolves up to 200 handles and returns the WEB-compatible items array.
    #[wasm_bindgen(js_name = resolveHandles)]
    pub async fn resolve_handles(&self, handles: JsValue) -> Result<JsValue, JsValue> {
        let response = self
            .invoke(
                "POST",
                "/handles/batch",
                object_with("handles", handles)?,
                true,
                &[],
            )
            .await?;
        property(&response, "items").ok_or_else(|| js_error("handle response is missing items"))
    }

    /// Loads all account summaries in WEB's 200-ID batches.
    #[wasm_bindgen(js_name = getAccountsBatch)]
    pub async fn get_accounts_batch(&self, account_ids: JsValue) -> Result<JsValue, JsValue> {
        let ids = input_to_array(account_ids)?;
        let mut unique_ids = Vec::with_capacity(ids.len());
        let mut seen = std::collections::HashSet::new();
        for id in ids {
            let id = id
                .as_str()
                .ok_or_else(|| js_error("account IDs must be strings"))?
                .to_owned();
            if seen.insert(id.clone()) {
                unique_ids.push(Value::String(id));
            }
        }
        let output = Array::new();
        for chunk in unique_ids.chunks(200) {
            let body = json_to_js(&serde_json::json!({ "accountIds": chunk }))?;
            let batch = self
                .invoke("POST", "/accounts/batch", body, true, &[])
                .await?;
            let rows = Array::from(&batch);
            for row in rows.iter() {
                output.push(&row);
            }
        }
        Ok(output.into())
    }

    /// Fetches global search and returns the WEB-compatible result array.
    #[wasm_bindgen(js_name = searchGlobal)]
    pub async fn search_global_results(&self, input: JsValue) -> Result<JsValue, JsValue> {
        let response = self
            .invoke("GET", "/search", input, true, &[("query", "q")])
            .await?;
        property(&response, "results").ok_or_else(|| js_error("search response is missing results"))
    }

    /// Fetches all post reactions in pages of 200, matching WEB's helper.
    #[wasm_bindgen(js_name = listAllPostReactions)]
    pub async fn list_all_post_reactions(&self, post_id: String) -> Result<JsValue, JsValue> {
        let mut cursor_created_at: Option<Value> = None;
        let mut cursor_actor_id: Option<String> = None;
        let mut rows = std::collections::HashMap::<String, Value>::new();
        loop {
            let mut query = serde_json::json!({ "postId": post_id, "limit": 200 });
            if let Some(created_at) = cursor_created_at.as_ref() {
                query["beforeCreatedAt"] = created_at.clone();
            }
            if let Some(actor_id) = cursor_actor_id.as_ref() {
                query["beforeActorId"] = Value::String(actor_id.clone());
            }
            let page = self
                .invoke(
                    "GET",
                    "/channel-posts/{postId}/reactions",
                    json_to_js(&query)?,
                    true,
                    &[],
                )
                .await?;
            let page_json = super::js_value_to_json(page).map_err(|error| error.into_js())?;
            let page_rows = page_json
                .as_array()
                .ok_or_else(|| js_error("reaction response is not an array"))?;
            let page_len = page_rows.len();
            for row in page_rows {
                let actor_type = row
                    .get("actorType")
                    .and_then(Value::as_str)
                    .ok_or_else(|| js_error("reaction row is missing actorType"))?;
                let actor_id = row
                    .get("actorId")
                    .and_then(Value::as_str)
                    .ok_or_else(|| js_error("reaction row is missing actorId"))?;
                rows.insert(format!("{actor_type}:{actor_id}"), row.clone());
            }
            if page_len < 200 {
                break;
            }
            let Some(last) = page_rows.last() else { break };
            let next_created_at = last
                .get("createdAt")
                .cloned()
                .ok_or_else(|| js_error("reaction row is missing createdAt"))?;
            let next_actor_id = last
                .get("actorId")
                .and_then(Value::as_str)
                .ok_or_else(|| js_error("reaction row is missing actorId"))?
                .to_owned();
            if cursor_created_at.as_ref() == Some(&next_created_at)
                && cursor_actor_id.as_deref() == Some(next_actor_id.as_str())
            {
                break;
            }
            cursor_created_at = Some(next_created_at);
            cursor_actor_id = Some(next_actor_id);
        }
        let mut rows = rows.into_values().collect::<Vec<_>>();
        rows.sort_by(|left, right| {
            let time_order = right
                .get("createdAt")
                .and_then(Value::as_i64)
                .cmp(&left.get("createdAt").and_then(Value::as_i64));
            if time_order.is_eq() {
                right
                    .get("actorId")
                    .and_then(Value::as_str)
                    .cmp(&left.get("actorId").and_then(Value::as_str))
            } else {
                time_order
            }
        });
        json_to_js(&Value::Array(rows))
    }

    /// Uploads an account WebP using the WEB upload-session and presigned PUT flow.
    #[wasm_bindgen(js_name = uploadAvatar)]
    pub async fn upload_avatar(&self, webp_bytes: Uint8Array) -> Result<JsValue, JsValue> {
        let length = webp_bytes.length();
        if length == 0 || length > 5 * 1024 * 1024 {
            return Err(js_error(
                "Avatar WebP size must be between 1 byte and 5 MiB",
            ));
        }
        let bytes: JsValue = webp_bytes.into();
        let mut restart = true;
        loop {
            let upload = self
                .invoke(
                    "POST",
                    "/avatars/me/uploads",
                    json_to_js(&serde_json::json!({ "sizeBytes": length }))?,
                    true,
                    &[],
                )
                .await?;
            let upload_json =
                super::js_value_to_json(upload.clone()).map_err(|error| error.into_js())?;
            let expected = upload_json
                .get("sizeBytes")
                .and_then(Value::as_u64)
                .ok_or_else(|| js_error("avatar upload response is missing sizeBytes"))?;
            if expected != u64::from(length) {
                return Err(js_error(
                    "Avatar upload session returned a different byte length",
                ));
            }
            let url = upload_json
                .get("url")
                .and_then(Value::as_str)
                .ok_or_else(|| js_error("avatar upload response is missing url"))?;
            self.raw("PUT", url.to_owned(), bytes.clone(), None, false, None)
                .await?;
            let upload_id = upload_json
                .get("uploadId")
                .and_then(Value::as_str)
                .ok_or_else(|| js_error("avatar upload response is missing uploadId"))?;
            let path = format!("/avatars/me/uploads/{}/finalize", encode_segment(upload_id));
            match self
                .invoke("POST", &path, JsValue::UNDEFINED, true, &[])
                .await
            {
                Ok(result) => return Ok(result),
                Err(error) if restart && error_status(&error) == Some(404) => restart = false,
                Err(error) => return Err(error),
            }
        }
    }

    #[wasm_bindgen(js_name = deleteAvatar)]
    pub async fn delete_avatar(&self) -> Result<JsValue, JsValue> {
        self.invoke("DELETE", "/avatars/me", JsValue::UNDEFINED, true, &[])
            .await
    }

    #[wasm_bindgen(js_name = uploadGroupAvatar)]
    pub async fn upload_group_avatar(
        &self,
        group_id: String,
        webp_bytes: Uint8Array,
    ) -> Result<JsValue, JsValue> {
        self.upload_entity_avatar("groups", group_id, webp_bytes)
            .await
    }

    #[wasm_bindgen(js_name = deleteGroupAvatar)]
    pub async fn delete_group_avatar(&self, group_id: String) -> Result<JsValue, JsValue> {
        self.invoke(
            "DELETE",
            "/groups/{groupId}/avatar",
            json_to_js(&serde_json::json!({ "groupId": group_id }))?,
            true,
            &[],
        )
        .await
    }

    #[wasm_bindgen(js_name = uploadChannelAvatar)]
    pub async fn upload_channel_avatar(
        &self,
        channel_id: String,
        webp_bytes: Uint8Array,
    ) -> Result<JsValue, JsValue> {
        self.upload_entity_avatar("channels", channel_id, webp_bytes)
            .await
    }

    #[wasm_bindgen(js_name = deleteChannelAvatar)]
    pub async fn delete_channel_avatar(&self, channel_id: String) -> Result<JsValue, JsValue> {
        self.invoke(
            "DELETE",
            "/channels/{channelId}/avatar",
            json_to_js(&serde_json::json!({ "channelId": channel_id }))?,
            true,
            &[],
        )
        .await
    }

    #[wasm_bindgen(js_name = putAttachmentChunk)]
    pub async fn put_attachment_chunk(
        &self,
        upload_url: String,
        sealed: Uint8Array,
    ) -> Result<JsValue, JsValue> {
        self.raw_with_options("PUT", upload_url, sealed.into(), None, false, false, None)
            .await
    }

    #[wasm_bindgen(js_name = fetchAttachmentChunk)]
    pub async fn fetch_attachment_chunk(&self, download_url: String) -> Result<JsValue, JsValue> {
        let mut rest = BrowserRestClient::new(self.api_base.clone())?;
        rest.set_timeout_ms(self.timeout_ms)?;
        rest.request(
            "GET".to_owned(),
            download_url,
            None,
            None,
            None,
            Some("bytes".to_owned()),
        )
        .await
    }

    /// Calls the JSON-only Bot API endpoint using its bot token.
    #[wasm_bindgen(js_name = getBotUpdates)]
    pub async fn get_bot_updates(&self, token: String, input: JsValue) -> Result<JsValue, JsValue> {
        let signal = signal_from_input(&input);
        let mut params = input_to_object(input)?;
        remove_transport_fields(&mut params);
        let timeout = bot_query_integer(&mut params, "timeout", 60, 0, 60);
        bot_query_integer(&mut params, "offset", 0, 0, u32::MAX);
        bot_query_integer(&mut params, "limit", 100, 1, 500);
        self.invoke_with_token(
            "GET",
            "/api/bot/v1/getUpdates",
            json_to_js(&Value::Object(params))?,
            Some(token),
            Some((timeout + 5) * 1000),
            signal,
        )
        .await
    }

    /// Calls the JSON-only Bot API callback-answer endpoint using its bot token.
    #[wasm_bindgen(js_name = answerBotCallbackQuery)]
    pub async fn answer_bot_callback_query(
        &self,
        token: String,
        input: JsValue,
    ) -> Result<JsValue, JsValue> {
        let body = json_to_js(&camel_to_snake_json(
            super::js_value_to_json(input).map_err(|error| error.into_js())?,
        ))?;
        let rest = BrowserRestClient::new(self.api_base.clone())?;
        rest.request(
            "POST".to_owned(),
            "/api/bot/v1/answerCallbackQuery".to_owned(),
            Some(body),
            Some(token),
            None,
            None,
        )
        .await
    }
}

impl BrowserApi {
    async fn upload_entity_avatar(
        &self,
        entity: &str,
        entity_id: String,
        bytes: Uint8Array,
    ) -> Result<JsValue, JsValue> {
        if bytes.length() == 0 || bytes.length() > 5 * 1024 * 1024 {
            return Err(js_error(
                "Avatar WebP size must be between 1 byte and 5 MiB",
            ));
        }
        let (path_template, key) = if entity == "groups" {
            ("/groups/{groupId}/avatar", "groupId")
        } else {
            ("/channels/{channelId}/avatar", "channelId")
        };
        let mut params = Map::new();
        params.insert(key.to_owned(), Value::String(entity_id));
        let path = resolve_path(path_template, &mut params)?;
        self.raw(
            "POST",
            path,
            bytes.into(),
            Some("image/webp".to_owned()),
            true,
            None,
        )
        .await
    }
}

fn input_to_object(input: JsValue) -> Result<Map<String, Value>, JsValue> {
    if input.is_undefined() || input.is_null() {
        return Ok(Map::new());
    }
    let value = super::js_value_to_json(input).map_err(|error| error.into_js())?;
    value
        .as_object()
        .cloned()
        .ok_or_else(|| js_error("operation input must be an object"))
}

fn input_to_array(input: JsValue) -> Result<Vec<Value>, JsValue> {
    let value = super::js_value_to_json(input).map_err(|error| error.into_js())?;
    value
        .as_array()
        .cloned()
        .ok_or_else(|| js_error("expected an array of account IDs"))
}

fn object_with(key: &str, value: JsValue) -> Result<JsValue, JsValue> {
    let json = super::js_value_to_json(value).map_err(|error| error.into_js())?;
    let mut object = Map::new();
    object.insert(key.to_owned(), json);
    json_to_js(&Value::Object(object))
}

fn resolve_path(template: &str, params: &mut Map<String, Value>) -> Result<String, JsValue> {
    let mut path = String::with_capacity(template.len());
    let mut remaining = template;
    while let Some(start) = remaining.find('{') {
        let before = &remaining[..start];
        path.push_str(before);
        let after_open = &remaining[start + 1..];
        let Some(end) = after_open.find('}') else {
            return Err(js_error("invalid route template"));
        };
        let name = &after_open[..end];
        let value = params
            .remove(name)
            .and_then(scalar_to_string)
            .ok_or_else(|| {
                js_error(&format!("operation input is missing path parameter {name}"))
            })?;
        path.push_str(&encode_segment(&value));
        remaining = &after_open[end + 1..];
    }
    path.push_str(remaining);
    Ok(path)
}

fn scalar_to_string(value: Value) -> Option<String> {
    match value {
        Value::String(value) => Some(value),
        Value::Number(value) => Some(value.to_string()),
        Value::Bool(value) => Some(value.to_string()),
        Value::Null | Value::Array(_) | Value::Object(_) => None,
    }
}

fn flatten_query_groups(params: &mut Map<String, Value>) {
    for group in ["query", "filters", "cursor"] {
        if let Some(Value::Object(values)) = params.remove(group) {
            for (key, value) in values {
                params.entry(key).or_insert(value);
            }
        }
    }
    remove_transport_fields(params);
}

fn remove_transport_fields(params: &mut Map<String, Value>) {
    params.remove("signal");
    params.remove("account");
    params.remove("sessionToken");
    params.remove("deviceNumber");
}

fn alias_query_keys(params: &mut Map<String, Value>, aliases: &[(&str, &str)]) {
    for (from, to) in aliases {
        if let Some(value) = params.remove(*from) {
            params.entry((*to).to_owned()).or_insert(value);
        }
    }
}

fn append_query(path: &str, params: Map<String, Value>) -> Result<String, JsValue> {
    let mut pairs = Vec::new();
    for (key, value) in params {
        if value.is_null() {
            continue;
        }
        let value = match value {
            Value::Array(items) => items
                .iter()
                .filter_map(scalar_to_string_ref)
                .collect::<Vec<_>>()
                .join(","),
            value => scalar_to_string(value)
                .ok_or_else(|| js_error("query parameters must be scalar or arrays of scalars"))?,
        };
        pairs.push(format!(
            "{}={}",
            encode_component(&camel_to_snake(&key)),
            encode_component(&value)
        ));
    }
    if pairs.is_empty() {
        Ok(path.to_owned())
    } else {
        Ok(format!("{path}?{}", pairs.join("&")))
    }
}

fn scalar_to_string_ref(value: &Value) -> Option<String> {
    match value {
        Value::String(value) => Some(value.clone()),
        Value::Number(value) => Some(value.to_string()),
        Value::Bool(value) => Some(value.to_string()),
        Value::Null | Value::Array(_) | Value::Object(_) => None,
    }
}

fn signal_from_input(input: &JsValue) -> Option<AbortSignal> {
    if input.is_null() || input.is_undefined() {
        return None;
    }
    Reflect::get(input, &JsValue::from_str("signal"))
        .ok()
        .and_then(|value| value.dyn_into::<AbortSignal>().ok())
}

fn encode_segment(input: &str) -> String {
    encode_component(input)
}

fn encode_component(input: &str) -> String {
    let mut encoded = String::with_capacity(input.len());
    for byte in input.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            encoded.push('%');
            encoded.push_str(&format!("{byte:02X}"));
        }
    }
    encoded
}

fn camel_to_snake(input: &str) -> String {
    let mut output = String::with_capacity(input.len() + 4);
    let mut chars = input.chars().peekable();
    let mut previous_was_lower_or_digit = false;
    while let Some(ch) = chars.next() {
        if ch == '-' {
            output.push('_');
            previous_was_lower_or_digit = false;
        } else if ch.is_ascii_uppercase() {
            if previous_was_lower_or_digit
                || chars.peek().is_some_and(|next| next.is_ascii_lowercase())
                    && !output.is_empty()
                    && !output.ends_with('_')
            {
                output.push('_');
            }
            output.push(ch.to_ascii_lowercase());
            previous_was_lower_or_digit = false;
        } else {
            output.push(ch);
            previous_was_lower_or_digit = ch.is_ascii_lowercase() || ch.is_ascii_digit();
        }
    }
    output
}

fn camel_to_snake_json(value: Value) -> Value {
    match value {
        Value::Object(object) => Value::Object(
            object
                .into_iter()
                .map(|(key, value)| (camel_to_snake(&key), camel_to_snake_json(value)))
                .collect(),
        ),
        Value::Array(values) => Value::Array(values.into_iter().map(camel_to_snake_json).collect()),
        other => other,
    }
}

fn property(value: &JsValue, key: &str) -> Option<JsValue> {
    Reflect::get(value, &JsValue::from_str(key))
        .ok()
        .filter(|value| !value.is_undefined())
}

fn json_to_js(value: &Value) -> Result<JsValue, JsValue> {
    super::json_to_js_value(value).map_err(|error| error.into_js())
}

fn js_error(message: &str) -> JsValue {
    JsError::new(message).into()
}

fn error_status(error: &JsValue) -> Option<u16> {
    Reflect::get(error, &JsValue::from_str("status"))
        .ok()
        .and_then(|value| value.as_f64())
        .and_then(|value| u16::try_from(value as u64).ok())
}

fn bot_query_integer(
    params: &mut Map<String, Value>,
    key: &str,
    default: u32,
    minimum: u32,
    maximum: u32,
) -> u32 {
    let value = params
        .remove(key)
        .and_then(|value| match value {
            Value::Number(number) => number.as_f64(),
            Value::String(string) => string.parse::<f64>().ok(),
            _ => None,
        })
        .map(|value| value.trunc().clamp(f64::from(minimum), f64::from(maximum)) as u32)
        .unwrap_or(default.clamp(minimum, maximum));
    params.insert(key.to_owned(), Value::Number(Number::from(value)));
    value
}

#[cfg(test)]
mod tests {
    use super::{camel_to_snake, camel_to_snake_json, encode_component};
    use serde_json::json;

    #[test]
    fn camel_case_conversion_matches_web_wire_names() {
        assert_eq!(camel_to_snake("replyToPostId"), "reply_to_post_id");
        assert_eq!(camel_to_snake("identityKeyPub"), "identity_key_pub");
        assert_eq!(
            camel_to_snake_json(json!({"accountIds": ["a"], "replyToId": null})),
            json!({"account_ids": ["a"], "reply_to_id": null})
        );
    }

    #[test]
    fn route_components_are_encoded_without_form_semantics() {
        assert_eq!(encode_component("a/b +"), "a%2Fb%20%2B");
    }
}
