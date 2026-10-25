//! Named safe Rust methods for the native dispatcher.
//!
//! Request and response types are intentionally generic because the API
//! crate keeps its wire DTOs private. Define application-owned types with
//! `serde::Serialize` and `serde::Deserialize` and pass them to these
//! methods. The serialized request is JSON matching the corresponding
//! FriendsHub operation; response decoding is performed inside the library.

use serde::Serialize;
use serde::de::DeserializeOwned;

use super::{Client, method_ids};
use crate::error::Result;

macro_rules! request_methods {
    ($($name:ident => $method_id:ident, $operation:literal;)+) => {
        impl Client {
            $(
                #[doc = concat!("Calls the `", $operation, "` dispatcher operation using an application-defined serde request and response type.")]
                pub fn $name<Q, R>(&self, request: &Q) -> Result<R>
                where
                    Q: Serialize,
                    R: DeserializeOwned,
                {
                    self.call_json(method_ids::$method_id, request)
                }
            )+
        }
    };
}

macro_rules! empty_request_methods {
    ($($name:ident => $method_id:ident, $operation:literal;)+) => {
        impl Client {
            $(
                #[doc = concat!("Calls the `", $operation, "` operation, which does not take an application request body.")]
                pub fn $name<R>(&self) -> Result<R>
                where
                    R: DeserializeOwned,
                {
                    self.call_json(method_ids::$method_id, &serde_json::Value::Null)
                }
            )+
        }
    };
}

// The names preserve the dispatcher area in their prefix, so callers can
// search this API alongside method_ids and avoid ambiguous verbs.
request_methods! {
    auth_register => AUTH_REGISTER, "auth_register";
    auth_login => AUTH_LOGIN, "auth_login";
    auth_login_2fa => AUTH_LOGIN_2FA, "auth_login_2fa";
    twofa_enroll_verify => TWOFA_ENROLL_VERIFY, "twofa_enroll_verify";
    twofa_disable => TWOFA_DISABLE, "twofa_disable";
    contacts_add => CONTACTS_ADD, "contacts_add";
    contacts_remove => CONTACTS_REMOVE, "contacts_remove";
    contacts_block => CONTACTS_BLOCK, "contacts_block";
    contacts_unblock => CONTACTS_UNBLOCK, "contacts_unblock";
    chat_extras_contact_search => CHAT_EXTRAS_CONTACT_SEARCH, "chat_extras_contact_search";
    conversations_create_direct => CONVERSATIONS_CREATE_DIRECT, "conversations_create_direct";
    conversations_get_one => CONVERSATIONS_GET_ONE, "conversations_get_one";
    conversations_leave => CONVERSATIONS_LEAVE, "conversations_leave";
    conversations_archive => CONVERSATIONS_ARCHIVE, "conversations_archive";
    conversations_unarchive => CONVERSATIONS_UNARCHIVE, "conversations_unarchive";
    conversations_mute => CONVERSATIONS_MUTE, "conversations_mute";
    conversations_unmute => CONVERSATIONS_UNMUTE, "conversations_unmute";
    chat_extras_conversation_envelopes => CHAT_EXTRAS_CONVERSATION_ENVELOPES, "chat_extras_conversation_envelopes";
    chat_extras_conversation_reads => CHAT_EXTRAS_CONVERSATION_READS, "chat_extras_conversation_reads";
    chat_extras_conversation_mark_read => CHAT_EXTRAS_CONVERSATION_MARK_READ, "chat_extras_conversation_mark_read";
    messages_establish_session => MESSAGES_ESTABLISH_SESSION, "messages_establish_session";
    messages_send => MESSAGES_SEND, "messages_send";
    messages_decrypt => MESSAGES_DECRYPT, "messages_decrypt";
    messages_send_message => MESSAGES_SEND_MESSAGE, "messages_send_message";
    message_actions_send_edit => MESSAGE_ACTIONS_SEND_EDIT, "message_actions_send_edit";
    message_actions_send_delete => MESSAGE_ACTIONS_SEND_DELETE, "message_actions_send_delete";
    message_actions_send_reaction => MESSAGE_ACTIONS_SEND_REACTION, "message_actions_send_reaction";
    devices_register => DEVICES_REGISTER, "devices_register";
    devices_revoke => DEVICES_REVOKE, "devices_revoke";
    device_init_initialize => DEVICE_INIT_INITIALIZE, "device_init_initialize";
    device_cache_api_refresh => DEVICE_CACHE_API_REFRESH, "device_cache_api_refresh";
    device_cache_api_invalidate => DEVICE_CACHE_API_INVALIDATE, "device_cache_api_invalidate";
    prekeys_upload => PREKEYS_UPLOAD, "prekeys_upload";
    prekeys_fetch_bundle => PREKEYS_FETCH_BUNDLE, "prekeys_fetch_bundle";
    attachments_upload => ATTACHMENTS_UPLOAD, "attachments_upload";
    attachments_download => ATTACHMENTS_DOWNLOAD, "attachments_download";
    attachments_claim => ATTACHMENTS_CLAIM, "attachments_claim";
    attachments_release => ATTACHMENTS_RELEASE, "attachments_release";
    attachments_recommend => ATTACHMENTS_RECOMMEND, "attachments_recommend";
    attachments_send_key => ATTACHMENTS_SEND_KEY, "attachments_send_key";
    avatars_upload => AVATARS_UPLOAD, "avatars_upload";
    avatars_serve => AVATARS_SERVE, "avatars_serve";
    avatars_init_upload => AVATARS_INIT_UPLOAD, "avatars_init_upload";
    avatars_finalize_upload => AVATARS_FINALIZE_UPLOAD, "avatars_finalize_upload";
    avatars_upload_group => AVATARS_UPLOAD_GROUP, "avatars_upload_group";
    avatars_delete_group => AVATARS_DELETE_GROUP, "avatars_delete_group";
    avatars_upload_channel => AVATARS_UPLOAD_CHANNEL, "avatars_upload_channel";
    avatars_delete_channel => AVATARS_DELETE_CHANNEL, "avatars_delete_channel";
    bots_set_profile => BOTS_SET_PROFILE, "bots_set_profile";
    bots_rotate_token => BOTS_ROTATE_TOKEN, "bots_rotate_token";
    bots_delete => BOTS_DELETE, "bots_delete";
    bots_get_bot_info => BOTS_GET_BOT_INFO, "bots_get_bot_info";
    bots_get_history => BOTS_GET_HISTORY, "bots_get_history";
    bots_send_to_bot => BOTS_SEND_TO_BOT, "bots_send_to_bot";
    bot_answer_callback_query => BOT_ANSWER_CALLBACK_QUERY, "bot_answer_callback_query";
    channels_create => CHANNELS_CREATE, "channels_create";
    channels_list_members => CHANNELS_LIST_MEMBERS, "channels_list_members";
    channels_set_role => CHANNELS_SET_ROLE, "channels_set_role";
    channels_remove_member => CHANNELS_REMOVE_MEMBER, "channels_remove_member";
    channels_set_linked_group => CHANNELS_SET_LINKED_GROUP, "channels_set_linked_group";
    channels_set_public => CHANNELS_SET_PUBLIC, "channels_set_public";
    channels_set_user_profile => CHANNELS_SET_USER_PROFILE, "channels_set_user_profile";
    channels_add_bot => CHANNELS_ADD_BOT, "channels_add_bot";
    channels_can_publish => CHANNELS_CAN_PUBLISH, "channels_can_publish";
    channels_subscribe => CHANNELS_SUBSCRIBE, "channels_subscribe";
    channels_unsubscribe => CHANNELS_UNSUBSCRIBE, "channels_unsubscribe";
    community_extras_get_channel => COMMUNITY_EXTRAS_GET_CHANNEL, "community_extras_get_channel";
    community_extras_list_public_channels => COMMUNITY_EXTRAS_LIST_PUBLIC_CHANNELS, "community_extras_list_public_channels";
    community_extras_lookup_channel_by_handle => COMMUNITY_EXTRAS_LOOKUP_CHANNEL_BY_HANDLE, "community_extras_lookup_channel_by_handle";
    community_extras_delete_channel => COMMUNITY_EXTRAS_DELETE_CHANNEL, "community_extras_delete_channel";
    channel_posts_publish => CHANNEL_POSTS_PUBLISH, "channel_posts_publish";
    channel_posts_list => CHANNEL_POSTS_LIST, "channel_posts_list";
    channel_posts_edit => CHANNEL_POSTS_EDIT, "channel_posts_edit";
    channel_posts_delete => CHANNEL_POSTS_DELETE, "channel_posts_delete";
    channel_posts_set_reaction => CHANNEL_POSTS_SET_REACTION, "channel_posts_set_reaction";
    channel_posts_remove_reaction => CHANNEL_POSTS_REMOVE_REACTION, "channel_posts_remove_reaction";
    channel_posts_list_reactions => CHANNEL_POSTS_LIST_REACTIONS, "channel_posts_list_reactions";
    channel_posts_pin => CHANNEL_POSTS_PIN, "channel_posts_pin";
    channel_posts_unpin => CHANNEL_POSTS_UNPIN, "channel_posts_unpin";
    channel_posts_list_pinned => CHANNEL_POSTS_LIST_PINNED, "channel_posts_list_pinned";
    channel_posts_get_discussion => CHANNEL_POSTS_GET_DISCUSSION, "channel_posts_get_discussion";
    channel_posts_get_one => CHANNEL_POSTS_GET_ONE, "channel_posts_get_one";
    community_extras_transfer_channel_owner => COMMUNITY_EXTRAS_TRANSFER_CHANNEL_OWNER, "community_extras_transfer_channel_owner";
    community_extras_get_channel_analytics => COMMUNITY_EXTRAS_GET_CHANNEL_ANALYTICS, "community_extras_get_channel_analytics";
    groups_create => GROUPS_CREATE, "groups_create";
    groups_list_public => GROUPS_LIST_PUBLIC, "groups_list_public";
    groups_join_public => GROUPS_JOIN_PUBLIC, "groups_join_public";
    groups_lookup_by_handle => GROUPS_LOOKUP_BY_HANDLE, "groups_lookup_by_handle";
    groups_list_members => GROUPS_LIST_MEMBERS, "groups_list_members";
    groups_set_role => GROUPS_SET_ROLE, "groups_set_role";
    groups_mute_member => GROUPS_MUTE_MEMBER, "groups_mute_member";
    groups_set_user_profile => GROUPS_SET_USER_PROFILE, "groups_set_user_profile";
    community_extras_get_group => COMMUNITY_EXTRAS_GET_GROUP, "community_extras_get_group";
    community_extras_update_group => COMMUNITY_EXTRAS_UPDATE_GROUP, "community_extras_update_group";
    community_extras_delete_group => COMMUNITY_EXTRAS_DELETE_GROUP, "community_extras_delete_group";
    community_extras_transfer_group_owner => COMMUNITY_EXTRAS_TRANSFER_GROUP_OWNER, "community_extras_transfer_group_owner";
    community_extras_add_group_member => COMMUNITY_EXTRAS_ADD_GROUP_MEMBER, "community_extras_add_group_member";
    community_extras_remove_group_member => COMMUNITY_EXTRAS_REMOVE_GROUP_MEMBER, "community_extras_remove_group_member";
    community_extras_set_group_member_tag => COMMUNITY_EXTRAS_SET_GROUP_MEMBER_TAG, "community_extras_set_group_member_tag";
    community_extras_remove_group_member_tag => COMMUNITY_EXTRAS_REMOVE_GROUP_MEMBER_TAG, "community_extras_remove_group_member_tag";
    community_extras_list_group_bans => COMMUNITY_EXTRAS_LIST_GROUP_BANS, "community_extras_list_group_bans";
    community_extras_ban_group_member => COMMUNITY_EXTRAS_BAN_GROUP_MEMBER, "community_extras_ban_group_member";
    community_extras_unban_group_member => COMMUNITY_EXTRAS_UNBAN_GROUP_MEMBER, "community_extras_unban_group_member";
    groups_send_create_distribution => GROUPS_SEND_CREATE_DISTRIBUTION, "groups_send_create_distribution";
    groups_send_send_group_message => GROUPS_SEND_SEND_GROUP_MESSAGE, "groups_send_send_group_message";
    invites_create => INVITES_CREATE, "invites_create";
    invites_list => INVITES_LIST, "invites_list";
    invites_revoke => INVITES_REVOKE, "invites_revoke";
    invites_join_by_token => INVITES_JOIN_BY_TOKEN, "invites_join_by_token";
    calls_list => CALLS_LIST, "calls_list";
    calls_record => CALLS_RECORD, "calls_record";
    calls_delete_one => CALLS_DELETE_ONE, "calls_delete_one";
    profile_update_username => PROFILE_UPDATE_USERNAME, "profile_update_username";
    profile_update_custom_status => PROFILE_UPDATE_CUSTOM_STATUS, "profile_update_custom_status";
    profile_set_invisible_mode => PROFILE_SET_INVISIBLE_MODE, "profile_set_invisible_mode";
    profile_add_exception => PROFILE_ADD_EXCEPTION, "profile_add_exception";
    profile_remove_exception => PROFILE_REMOVE_EXCEPTION, "profile_remove_exception";
    profile_get_public_profile => PROFILE_GET_PUBLIC_PROFILE, "profile_get_public_profile";
    profile_get_presence => PROFILE_GET_PRESENCE, "profile_get_presence";
    profile_extras_set_profile_hidden => PROFILE_EXTRAS_SET_PROFILE_HIDDEN, "profile_extras_set_profile_hidden";
    profile_extras_set_hidden_from_search => PROFILE_EXTRAS_SET_HIDDEN_FROM_SEARCH, "profile_extras_set_hidden_from_search";
    profile_extras_add_profile_exception => PROFILE_EXTRAS_ADD_PROFILE_EXCEPTION, "profile_extras_add_profile_exception";
    profile_extras_remove_profile_exception => PROFILE_EXTRAS_REMOVE_PROFILE_EXCEPTION, "profile_extras_remove_profile_exception";
    profile_extras_set_profile_fields => PROFILE_EXTRAS_SET_PROFILE_FIELDS, "profile_extras_set_profile_fields";
    profile_extras_set_dm_policy => PROFILE_EXTRAS_SET_DM_POLICY, "profile_extras_set_dm_policy";
    profile_extras_set_group_add_policy => PROFILE_EXTRAS_SET_GROUP_ADD_POLICY, "profile_extras_set_group_add_policy";
    profile_extras_add_group_add_exception => PROFILE_EXTRAS_ADD_GROUP_ADD_EXCEPTION, "profile_extras_add_group_add_exception";
    profile_extras_remove_group_add_exception => PROFILE_EXTRAS_REMOVE_GROUP_ADD_EXCEPTION, "profile_extras_remove_group_add_exception";
    profile_extras_set_allow_nudges => PROFILE_EXTRAS_SET_ALLOW_NUDGES, "profile_extras_set_allow_nudges";
    profile_extras_save_discover_profile => PROFILE_EXTRAS_SAVE_DISCOVER_PROFILE, "profile_extras_save_discover_profile";
    profile_extras_list_discover_profiles => PROFILE_EXTRAS_LIST_DISCOVER_PROFILES, "profile_extras_list_discover_profiles";
    profile_extras_get_discover_profile_details => PROFILE_EXTRAS_GET_DISCOVER_PROFILE_DETAILS, "profile_extras_get_discover_profile_details";
    profile_extras_subscribe_push => PROFILE_EXTRAS_SUBSCRIBE_PUSH, "profile_extras_subscribe_push";
    profile_extras_unsubscribe_push => PROFILE_EXTRAS_UNSUBSCRIBE_PUSH, "profile_extras_unsubscribe_push";
    account_deletion_confirm => ACCOUNT_DELETION_CONFIRM, "account_deletion_confirm";
    sessions_revoke_one => SESSIONS_REVOKE_ONE, "sessions_revoke_one";
    sessions_revoke_all => SESSIONS_REVOKE_ALL, "sessions_revoke_all";
    user_profiles_lookup => USER_PROFILES_LOOKUP, "user_profiles_lookup";
    user_profiles_check_available => USER_PROFILES_CHECK_AVAILABLE, "user_profiles_check_available";
    user_profiles_batch_lookup => USER_PROFILES_BATCH_LOOKUP, "user_profiles_batch_lookup";
    chat_extras_conversation_pins_list => CHAT_EXTRAS_CONVERSATION_PINS_LIST, "chat_extras_conversation_pins_list";
    chat_extras_conversation_pin => CHAT_EXTRAS_CONVERSATION_PIN, "chat_extras_conversation_pin";
    chat_extras_conversation_unpin => CHAT_EXTRAS_CONVERSATION_UNPIN, "chat_extras_conversation_unpin";
    chat_extras_conversation_polls_list => CHAT_EXTRAS_CONVERSATION_POLLS_LIST, "chat_extras_conversation_polls_list";
    chat_extras_poll_get => CHAT_EXTRAS_POLL_GET, "chat_extras_poll_get";
    chat_extras_poll_create => CHAT_EXTRAS_POLL_CREATE, "chat_extras_poll_create";
    chat_extras_poll_vote => CHAT_EXTRAS_POLL_VOTE, "chat_extras_poll_vote";
    chat_extras_poll_stop => CHAT_EXTRAS_POLL_STOP, "chat_extras_poll_stop";
    chat_extras_poll_delete => CHAT_EXTRAS_POLL_DELETE, "chat_extras_poll_delete";
    chat_extras_poll_add_option => CHAT_EXTRAS_POLL_ADD_OPTION, "chat_extras_poll_add_option";
    chat_extras_poll_delete_option => CHAT_EXTRAS_POLL_DELETE_OPTION, "chat_extras_poll_delete_option";
    poll_crypto_create_conversation_poll => POLL_CRYPTO_CREATE_CONVERSATION_POLL, "poll_crypto_create_conversation_poll";
    poll_crypto_encrypt_poll_payload => POLL_CRYPTO_ENCRYPT_POLL_PAYLOAD, "poll_crypto_encrypt_poll_payload";
    poll_crypto_encrypt_poll_option => POLL_CRYPTO_ENCRYPT_POLL_OPTION, "poll_crypto_encrypt_poll_option";
    poll_crypto_decrypt_poll_payload => POLL_CRYPTO_DECRYPT_POLL_PAYLOAD, "poll_crypto_decrypt_poll_payload";
    history_replay_begin_conversation_page => HISTORY_REPLAY_BEGIN_CONVERSATION_PAGE, "history_replay_begin_conversation_page";
    history_replay_begin_saved_page => HISTORY_REPLAY_BEGIN_SAVED_PAGE, "history_replay_begin_saved_page";
    history_replay_commit => HISTORY_REPLAY_COMMIT, "history_replay_commit";
    history_replay_discard => HISTORY_REPLAY_DISCARD, "history_replay_discard";
    chat_extras_saved_messages => CHAT_EXTRAS_SAVED_MESSAGES, "chat_extras_saved_messages";
    chat_extras_folder_create => CHAT_EXTRAS_FOLDER_CREATE, "chat_extras_folder_create";
    chat_extras_folder_update => CHAT_EXTRAS_FOLDER_UPDATE, "chat_extras_folder_update";
    chat_extras_folder_delete => CHAT_EXTRAS_FOLDER_DELETE, "chat_extras_folder_delete";
    chat_extras_folder_add_conversation => CHAT_EXTRAS_FOLDER_ADD_CONVERSATION, "chat_extras_folder_add_conversation";
    chat_extras_folder_remove_conversation => CHAT_EXTRAS_FOLDER_REMOVE_CONVERSATION, "chat_extras_folder_remove_conversation";
    chat_extras_scheduled_cancel => CHAT_EXTRAS_SCHEDULED_CANCEL, "chat_extras_scheduled_cancel";
    chat_extras_global_search => CHAT_EXTRAS_GLOBAL_SEARCH, "chat_extras_global_search";
    webrtc_create_offer => WEBRTC_CREATE_OFFER, "webrtc_create_offer";
    webrtc_accept_offer => WEBRTC_ACCEPT_OFFER, "webrtc_accept_offer";
    webrtc_apply_answer => WEBRTC_APPLY_ANSWER, "webrtc_apply_answer";
    webrtc_add_ice => WEBRTC_ADD_ICE, "webrtc_add_ice";
    webrtc_create_data_channel => WEBRTC_CREATE_DATA_CHANNEL, "webrtc_create_data_channel";
    webrtc_close_call => WEBRTC_CLOSE_CALL, "webrtc_close_call";
    webrtc_data_send_channel_data => WEBRTC_DATA_SEND_CHANNEL_DATA, "webrtc_data_send_channel_data";
    webrtc_video_add_video_track => WEBRTC_VIDEO_ADD_VIDEO_TRACK, "webrtc_video_add_video_track";
    webrtc_video_write_video_frame => WEBRTC_VIDEO_WRITE_VIDEO_FRAME, "webrtc_video_write_video_frame";
    webrtc_video_read_video_frame => WEBRTC_VIDEO_READ_VIDEO_FRAME, "webrtc_video_read_video_frame";
    webrtc_video_add_audio_track => WEBRTC_VIDEO_ADD_AUDIO_TRACK, "webrtc_video_add_audio_track";
    webrtc_video_write_audio_frame => WEBRTC_VIDEO_WRITE_AUDIO_FRAME, "webrtc_video_write_audio_frame";
    webrtc_video_read_audio_frame => WEBRTC_VIDEO_READ_AUDIO_FRAME, "webrtc_video_read_audio_frame";
    webrtc_initiate_call => WEBRTC_INITIATE_CALL, "webrtc_initiate_call";
    webrtc_accept_call => WEBRTC_ACCEPT_CALL, "webrtc_accept_call";
    webrtc_send_ice => WEBRTC_SEND_ICE, "webrtc_send_ice";
    webrtc_hangup => WEBRTC_HANGUP, "webrtc_hangup";
    webrtc_reject => WEBRTC_REJECT, "webrtc_reject";
    ws_send_envelope => WS_SEND_ENVELOPE, "ws_send_envelope";
    ws_send_typing => WS_SEND_TYPING, "ws_send_typing";
    ws_send_nudge => WS_SEND_NUDGE, "ws_send_nudge";
    ws_request_history => WS_REQUEST_HISTORY, "ws_request_history";
    ws_ping => WS_PING, "ws_ping";
    ws_send_history => WS_SEND_HISTORY, "ws_send_history";
}

empty_request_methods! {
    ping => PING, "ping";
    version => VERSION, "version";
    auth_logout => AUTH_LOGOUT, "auth_logout";
    auth_me => AUTH_ME, "auth_me";
    twofa_enroll => TWOFA_ENROLL, "twofa_enroll";
    contacts_list => CONTACTS_LIST, "contacts_list";
    contacts_list_blocked => CONTACTS_LIST_BLOCKED, "contacts_list_blocked";
    conversations_list => CONVERSATIONS_LIST, "conversations_list";
    devices_list => DEVICES_LIST, "devices_list";
    device_init_status => DEVICE_INIT_STATUS, "device_init_status";
    device_init_ensure_prekeys => DEVICE_INIT_ENSURE_PREKEYS, "device_init_ensure_prekeys";
    prekeys_status => PREKEYS_STATUS, "prekeys_status";
    avatars_delete => AVATARS_DELETE, "avatars_delete";
    bots_list => BOTS_LIST, "bots_list";
    bots_create => BOTS_CREATE, "bots_create";
    bots_list_my_bots => BOTS_LIST_MY_BOTS, "bots_list_my_bots";
    calls_clear => CALLS_CLEAR, "calls_clear";
    profile_clear_custom_status => PROFILE_CLEAR_CUSTOM_STATUS, "profile_clear_custom_status";
    profile_list_exceptions => PROFILE_LIST_EXCEPTIONS, "profile_list_exceptions";
    profile_extras_get_privacy => PROFILE_EXTRAS_GET_PRIVACY, "profile_extras_get_privacy";
    profile_extras_list_profile_exceptions => PROFILE_EXTRAS_LIST_PROFILE_EXCEPTIONS, "profile_extras_list_profile_exceptions";
    profile_extras_get_profile_fields => PROFILE_EXTRAS_GET_PROFILE_FIELDS, "profile_extras_get_profile_fields";
    profile_extras_get_dm_policy => PROFILE_EXTRAS_GET_DM_POLICY, "profile_extras_get_dm_policy";
    profile_extras_get_group_add_policy => PROFILE_EXTRAS_GET_GROUP_ADD_POLICY, "profile_extras_get_group_add_policy";
    profile_extras_list_group_add_exceptions => PROFILE_EXTRAS_LIST_GROUP_ADD_EXCEPTIONS, "profile_extras_list_group_add_exceptions";
    profile_extras_get_allow_nudges => PROFILE_EXTRAS_GET_ALLOW_NUDGES, "profile_extras_get_allow_nudges";
    profile_extras_get_discover_profile => PROFILE_EXTRAS_GET_DISCOVER_PROFILE, "profile_extras_get_discover_profile";
    profile_extras_hide_discover_profile => PROFILE_EXTRAS_HIDE_DISCOVER_PROFILE, "profile_extras_hide_discover_profile";
    profile_extras_get_vapid => PROFILE_EXTRAS_GET_VAPID, "profile_extras_get_vapid";
    profile_extras_list_security_events => PROFILE_EXTRAS_LIST_SECURITY_EVENTS, "profile_extras_list_security_events";
    profile_get_invisible => PROFILE_GET_INVISIBLE, "profile_get_invisible";
    account_deletion_initiate => ACCOUNT_DELETION_INITIATE, "account_deletion_initiate";
    account_deletion_cancel => ACCOUNT_DELETION_CANCEL, "account_deletion_cancel";
    account_deletion_status => ACCOUNT_DELETION_STATUS, "account_deletion_status";
    sessions_list => SESSIONS_LIST, "sessions_list";
    chat_extras_saved_conversation => CHAT_EXTRAS_SAVED_CONVERSATION, "chat_extras_saved_conversation";
    chat_extras_folders_list => CHAT_EXTRAS_FOLDERS_LIST, "chat_extras_folders_list";
    chat_extras_scheduled_list => CHAT_EXTRAS_SCHEDULED_LIST, "chat_extras_scheduled_list";
    webrtc_ice_servers => WEBRTC_ICE_SERVERS, "webrtc_ice_servers";
    webrtc_list_active => WEBRTC_LIST_ACTIVE, "webrtc_list_active";
    ws_start => WS_START, "ws_start";
    ws_stop => WS_STOP, "ws_stop";
}

#[cfg(test)]
mod poll_crypto_typed_api_tests {
    use crate::{client::Client, error::Result};
    use serde_json::Value;

    #[test]
    fn all_poll_crypto_typed_methods_are_publicly_callable() {
        let methods: [fn(&Client, &Value) -> Result<Value>; 4] = [
            Client::poll_crypto_create_conversation_poll::<Value, Value>,
            Client::poll_crypto_encrypt_poll_payload::<Value, Value>,
            Client::poll_crypto_encrypt_poll_option::<Value, Value>,
            Client::poll_crypto_decrypt_poll_payload::<Value, Value>,
        ];
        assert_eq!(methods.len(), 4);
    }
}

#[cfg(test)]
mod history_replay_typed_api_tests {
    use crate::{client::Client, error::Result};
    use serde_json::Value;

    #[test]
    fn all_history_replay_typed_methods_are_publicly_callable() {
        let methods: [fn(&Client, &Value) -> Result<Value>; 4] = [
            Client::history_replay_begin_conversation_page::<Value, Value>,
            Client::history_replay_begin_saved_page::<Value, Value>,
            Client::history_replay_commit::<Value, Value>,
            Client::history_replay_discard::<Value, Value>,
        ];
        assert_eq!(methods.len(), 4);
    }
}
