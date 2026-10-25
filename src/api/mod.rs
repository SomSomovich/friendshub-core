use std::sync::Arc;

use crate::db::pending_events;
use crate::error::{Error, Result};
use crate::events::types::Event;
use crate::runtime::ActorState;

pub mod account_deletion;
pub mod attachments;
pub mod auth;
pub mod avatars;
pub mod bots;
pub mod calls;
pub mod channel_posts;
pub mod channels;
pub mod chat_extras;
pub mod common;
pub mod community_extras;
pub mod contacts;
pub mod conversations;
pub mod device_cache_api;
pub mod device_init;
pub mod devices;
pub mod groups;
pub mod groups_send;
pub mod history_replay;
pub mod history_sync;
pub mod invites;
pub mod message_actions;
pub mod messages;
pub mod poll_crypto;
pub mod prekeys;
pub mod profile;
pub mod profile_extras;
pub mod sessions;
pub mod twofa;
pub mod user_profiles;
pub mod webrtc;
pub mod webrtc_data;
pub mod webrtc_video;
pub mod ws;

pub struct DispatchMarker;

/// Method IDs are namespaced by area. See docs/ffi.md for the full table.
pub async fn dispatch(state: Arc<ActorState>, method: u32, payload: Vec<u8>) -> Result<Vec<u8>> {
    let crypto_guard = if method_mutates_crypto_state(method) {
        Some(state.crypto_state_lock.lock().await)
    } else {
        None
    };

    let result = match method {
        // service
        0x0000_0001 => ping().await,
        0x0000_0002 => version(&state).await,
        0x0000_0004 => ws::ack_event(&state, payload).await,
        0x0000_0005 => activate_push(&state).await,

        // auth
        0x0001_0001 => auth::register(&state, payload).await,
        0x0001_0002 => auth::login(&state, payload).await,
        0x0001_0003 => auth::login_2fa(&state, payload).await,
        0x0001_0004 => auth::logout(&state).await,
        0x0001_0005 => auth::me(&state).await,
        0x0001_0006 => twofa::enroll(&state, payload).await,
        0x0001_0007 => twofa::enroll_verify(&state, payload).await,
        0x0001_0008 => twofa::disable(&state, payload).await,

        // contacts / blocks
        0x0002_0001 => contacts::list(&state, payload).await,
        0x0002_0002 => contacts::add(&state, payload).await,
        0x0002_0003 => contacts::remove(&state, payload).await,
        0x0002_0004 => contacts::block(&state, payload).await,
        0x0002_0005 => contacts::unblock(&state, payload).await,
        0x0002_0006 => contacts::list_blocked(&state, payload).await,
        0x0002_0007 => chat_extras::contact_search(&state, payload).await,

        // conversations
        0x0003_0001 => conversations::list(&state, payload).await,
        0x0003_0002 => conversations::create_direct(&state, payload).await,
        0x0003_0003 => conversations::get_one(&state, payload).await,
        0x0003_0004 => conversations::leave(&state, payload).await,
        0x0003_0005 => conversations::archive(&state, payload).await,
        0x0003_0006 => conversations::unarchive(&state, payload).await,
        0x0003_0007 => conversations::mute(&state, payload).await,
        0x0003_0008 => conversations::unmute(&state, payload).await,
        0x0003_0009 => chat_extras::conversation_envelopes(&state, payload).await,
        0x0003_000A => chat_extras::conversation_reads(&state, payload).await,
        0x0003_000B => chat_extras::conversation_mark_read(&state, payload).await,

        // messages
        0x0004_0001 => messages::establish_session(&state, payload).await,
        0x0004_0002 => messages::send(&state, payload).await,
        0x0004_0003 => messages::decrypt(&state, payload).await,
        0x0004_0004 => messages::send_message(&state, payload).await,
        0x0004_0010 => message_actions::send_edit(&state, payload).await,
        0x0004_0011 => message_actions::send_delete(&state, payload).await,
        0x0004_0012 => message_actions::send_reaction(&state, payload).await,

        // devices
        0x0005_0001 => devices::list(&state, payload).await,
        0x0005_0002 => devices::register(&state, payload).await,
        0x0005_0003 => devices::revoke(&state, payload).await,
        0x0005_0004 => device_init::initialize(&state, payload).await,
        0x0005_0005 => device_init::status(&state, payload).await,
        0x0005_0006 => device_cache_api::refresh(&state, payload).await,
        0x0005_0007 => device_cache_api::invalidate(&state, payload).await,
        0x0005_0015 => device_init::ensure_prekeys(&state, payload).await,

        // prekeys
        0x0005_0011 => prekeys::upload(&state, payload).await,
        0x0005_0012 => prekeys::status(&state, payload).await,
        0x0005_0013 => prekeys::fetch_bundle(&state, payload).await,

        // attachments
        0x0006_0001 => attachments::upload(&state, payload).await,
        0x0006_0002 => attachments::download(&state, payload).await,
        0x0006_0003 => attachments::claim(&state, payload).await,
        0x0006_0004 => attachments::release(&state, payload).await,
        0x0006_0005 => attachments::recommend(&state, payload).await,
        0x0006_0006 => attachments::send_key(&state, payload).await,

        // avatars
        0x0007_0001 => avatars::upload(&state, payload).await,
        0x0007_0002 => avatars::delete(&state, payload).await,
        0x0007_0003 => avatars::serve(&state, payload).await,
        0x0007_0004 => avatars::init_upload(&state, payload).await,
        0x0007_0005 => avatars::finalize_upload(&state, payload).await,
        0x0007_0006 => avatars::upload_group(&state, payload).await,
        0x0007_0007 => avatars::delete_group(&state, payload).await,
        0x0007_0008 => avatars::upload_channel(&state, payload).await,
        0x0007_0009 => avatars::delete_channel(&state, payload).await,

        // bots
        0x0008_0001 => bots::list(&state, payload).await,
        0x0008_0002 => bots::create(&state, payload).await,
        0x0008_0003 => bots::set_profile(&state, payload).await,
        0x0008_0004 => bots::rotate_token(&state, payload).await,
        0x0008_0005 => bots::delete(&state, payload).await,
        0x0008_0006 => bots::list_my_bots(&state, payload).await,
        0x0008_0007 => bots::get_bot_info(&state, payload).await,
        0x0008_0008 => bots::get_history(&state, payload).await,
        0x0008_0009 => bots::send_to_bot(&state, payload).await,
        0x0008_000A => crate::bot_api::dispatch_answer_callback_query(&state, payload).await,

        // channels
        0x0009_0001 => channels::create(&state, payload).await,
        0x0009_0002 => channels::list_members(&state, payload).await,
        0x0009_0003 => channels::set_role(&state, payload).await,
        0x0009_0004 => channels::remove_member(&state, payload).await,
        0x0009_0005 => channels::set_linked_group(&state, payload).await,
        0x0009_0006 => channels::set_public(&state, payload).await,
        0x0009_0007 => channels::set_user_profile(&state, payload).await,
        0x0009_0008 => channels::add_bot(&state, payload).await,
        0x0009_0009 => channels::can_publish(&state, payload).await,
        0x0009_000A => channels::subscribe(&state, payload).await,
        0x0009_000B => channels::unsubscribe(&state, payload).await,
        0x0009_000C => community_extras::get_channel(&state, payload).await,
        0x0009_000D => community_extras::list_public_channels(&state, payload).await,
        0x0009_000E => community_extras::lookup_channel_by_handle(&state, payload).await,
        0x0009_000F => community_extras::delete_channel(&state, payload).await,
        0x0009_0010 => channel_posts::publish(&state, payload).await,
        0x0009_0011 => channel_posts::list(&state, payload).await,
        0x0009_0012 => channel_posts::edit(&state, payload).await,
        0x0009_0013 => channel_posts::delete(&state, payload).await,
        0x0009_0014 => channel_posts::set_reaction(&state, payload).await,
        0x0009_0015 => channel_posts::remove_reaction(&state, payload).await,
        0x0009_0016 => channel_posts::list_reactions(&state, payload).await,
        0x0009_0017 => channel_posts::pin(&state, payload).await,
        0x0009_0018 => channel_posts::unpin(&state, payload).await,
        0x0009_0019 => channel_posts::list_pinned(&state, payload).await,
        0x0009_001A => channel_posts::get_discussion(&state, payload).await,
        0x0009_001B => community_extras::transfer_channel_owner(&state, payload).await,
        0x0009_001C => community_extras::get_channel_analytics(&state, payload).await,
        0x0009_001D => channel_posts::get_one(&state, payload).await,

        // groups
        0x000A_0001 => groups::create(&state, payload).await,
        0x000A_0002 => groups::list_public(&state, payload).await,
        0x000A_0003 => groups::join_public(&state, payload).await,
        0x000A_0004 => groups::lookup_by_handle(&state, payload).await,
        0x000A_0005 => groups::list_members(&state, payload).await,
        0x000A_0006 => groups::set_role(&state, payload).await,
        0x000A_0007 => groups::mute_member(&state, payload).await,
        0x000A_0008 => groups::set_user_profile(&state, payload).await,
        0x000A_0009 => community_extras::get_group(&state, payload).await,
        0x000A_000A => community_extras::update_group(&state, payload).await,
        0x000A_000B => community_extras::delete_group(&state, payload).await,
        0x000A_000C => community_extras::transfer_group_owner(&state, payload).await,
        0x000A_000D => community_extras::add_group_member(&state, payload).await,
        0x000A_000E => community_extras::remove_group_member(&state, payload).await,
        0x000A_000F => community_extras::set_group_member_tag(&state, payload).await,
        0x000A_0010 => community_extras::remove_group_member_tag(&state, payload).await,
        0x000A_0011 => community_extras::list_group_bans(&state, payload).await,
        0x000A_0012 => community_extras::ban_group_member(&state, payload).await,
        0x000A_0013 => community_extras::unban_group_member(&state, payload).await,
        0x000A_0020 => groups_send::create_distribution(&state, payload).await,
        0x000A_0021 => groups_send::send_group_message(&state, payload).await,

        // invites
        0x000B_0001 => invites::create(&state, payload).await,
        0x000B_0002 => invites::list(&state, payload).await,
        0x000B_0003 => invites::revoke(&state, payload).await,
        0x000B_0004 => invites::join_by_token(&state, payload).await,

        // calls
        0x000C_0001 => calls::list(&state, payload).await,
        0x000C_0002 => calls::record(&state, payload).await,
        0x000C_0003 => calls::delete_one(&state, payload).await,
        0x000C_0004 => calls::clear(&state, payload).await,

        // profile
        0x000D_0001 => profile::update_username(&state, payload).await,
        0x000D_0002 => profile::update_custom_status(&state, payload).await,
        0x000D_0003 => profile::clear_custom_status(&state, payload).await,
        0x000D_0004 => profile::set_invisible_mode(&state, payload).await,
        0x000D_0005 => profile::list_exceptions(&state, payload).await,
        0x000D_0006 => profile::add_exception(&state, payload).await,
        0x000D_0007 => profile::remove_exception(&state, payload).await,
        0x000D_0008 => profile::get_public_profile(&state, payload).await,
        0x000D_0009 => profile::get_presence(&state, payload).await,
        0x000D_0010 => profile_extras::get_privacy(&state, payload).await,
        0x000D_0011 => profile_extras::set_profile_hidden(&state, payload).await,
        0x000D_0012 => profile_extras::set_hidden_from_search(&state, payload).await,
        0x000D_0013 => profile_extras::list_profile_exceptions(&state, payload).await,
        0x000D_0014 => profile_extras::add_profile_exception(&state, payload).await,
        0x000D_0015 => profile_extras::remove_profile_exception(&state, payload).await,
        0x000D_0016 => profile_extras::get_profile_fields(&state, payload).await,
        0x000D_0017 => profile_extras::set_profile_fields(&state, payload).await,
        0x000D_0018 => profile_extras::get_dm_policy(&state, payload).await,
        0x000D_0019 => profile_extras::set_dm_policy(&state, payload).await,
        0x000D_001A => profile_extras::get_group_add_policy(&state, payload).await,
        0x000D_001B => profile_extras::set_group_add_policy(&state, payload).await,
        0x000D_001C => profile_extras::list_group_add_exceptions(&state, payload).await,
        0x000D_001D => profile_extras::add_group_add_exception(&state, payload).await,
        0x000D_001E => profile_extras::remove_group_add_exception(&state, payload).await,
        0x000D_001F => profile_extras::get_allow_nudges(&state, payload).await,
        0x000D_0020 => profile_extras::set_allow_nudges(&state, payload).await,
        0x000D_0021 => profile_extras::get_discover_profile(&state, payload).await,
        0x000D_0022 => profile_extras::save_discover_profile(&state, payload).await,
        0x000D_0023 => profile_extras::hide_discover_profile(&state, payload).await,
        0x000D_0024 => profile_extras::list_discover_profiles(&state, payload).await,
        0x000D_0025 => profile_extras::get_discover_profile_details(&state, payload).await,
        0x000D_0026 => profile_extras::get_vapid(&state, payload).await,
        0x000D_0027 => profile_extras::subscribe_push(&state, payload).await,
        0x000D_0028 => profile_extras::unsubscribe_push(&state, payload).await,
        0x000D_0029 => profile_extras::list_security_events(&state, payload).await,
        0x000D_002A => profile::get_invisible_mode(&state, payload).await,

        // account deletion
        0x000E_0001 => account_deletion::initiate(&state, payload).await,
        0x000E_0002 => account_deletion::confirm(&state, payload).await,
        0x000E_0003 => account_deletion::cancel(&state, payload).await,
        0x000E_0004 => account_deletion::status(&state, payload).await,

        // sessions
        0x000F_0001 => sessions::list(&state, payload).await,
        0x000F_0002 => sessions::revoke_one(&state, payload).await,
        0x000F_0003 => sessions::revoke_all(&state, payload).await,

        // handles
        0x0010_0001 => user_profiles::lookup(&state, payload).await,
        0x0010_0002 => user_profiles::check_available(&state, payload).await,
        0x0010_0003 => user_profiles::batch_lookup(&state, payload).await,

        // conversation extensions
        0x0013_0001 => chat_extras::conversation_pins_list(&state, payload).await,
        0x0013_0002 => chat_extras::conversation_pin(&state, payload).await,
        0x0013_0003 => chat_extras::conversation_unpin(&state, payload).await,
        0x0013_0004 => chat_extras::conversation_polls_list(&state, payload).await,
        0x0013_0005 => chat_extras::poll_get(&state, payload).await,
        0x0013_0006 => chat_extras::poll_create(&state, payload).await,
        0x0013_0007 => chat_extras::poll_vote(&state, payload).await,
        0x0013_0008 => chat_extras::poll_stop(&state, payload).await,
        0x0013_0009 => chat_extras::poll_delete(&state, payload).await,
        0x0013_000A => chat_extras::poll_add_option(&state, payload).await,
        0x0013_000B => chat_extras::poll_delete_option(&state, payload).await,
        0x0013_000C => chat_extras::saved_conversation(&state, payload).await,
        0x0013_000D => chat_extras::saved_messages(&state, payload).await,
        0x0013_000E => chat_extras::folders_list(&state, payload).await,
        0x0013_000F => chat_extras::folder_create(&state, payload).await,
        0x0013_0010 => chat_extras::folder_update(&state, payload).await,
        0x0013_0011 => chat_extras::folder_delete(&state, payload).await,
        0x0013_0012 => chat_extras::folder_add_conversation(&state, payload).await,
        0x0013_0013 => chat_extras::folder_remove_conversation(&state, payload).await,
        0x0013_0014 => chat_extras::scheduled_list(&state, payload).await,
        0x0013_0015 => chat_extras::scheduled_cancel(&state, payload).await,
        0x0013_0016 => chat_extras::global_search(&state, payload).await,
        crate::method_ids::POLL_CRYPTO_CREATE_CONVERSATION_POLL => {
            poll_crypto::create_conversation_poll(&state, payload).await
        }
        crate::method_ids::POLL_CRYPTO_ENCRYPT_POLL_PAYLOAD => {
            poll_crypto::encrypt_poll_payload(&state, payload).await
        }
        crate::method_ids::POLL_CRYPTO_ENCRYPT_POLL_OPTION => {
            poll_crypto::encrypt_poll_option(&state, payload).await
        }
        crate::method_ids::POLL_CRYPTO_DECRYPT_POLL_PAYLOAD => {
            poll_crypto::decrypt_poll_payload(&state, payload).await
        }
        crate::method_ids::HISTORY_REPLAY_BEGIN_CONVERSATION_PAGE => {
            history_replay::begin_conversation_page(&state, payload).await
        }
        crate::method_ids::HISTORY_REPLAY_BEGIN_SAVED_PAGE => {
            history_replay::begin_saved_page(&state, payload).await
        }
        crate::method_ids::HISTORY_REPLAY_COMMIT => history_replay::commit(&state, payload).await,
        crate::method_ids::HISTORY_REPLAY_DISCARD => history_replay::discard(&state, payload).await,

        // webrtc
        0x0011_0001 => webrtc::ice_servers(&state, payload).await,
        0x0012_0001 => webrtc::create_offer(&state, payload).await,
        0x0012_0002 => webrtc::accept_offer(&state, payload).await,
        0x0012_0003 => webrtc::apply_answer(&state, payload).await,
        0x0012_0004 => webrtc::add_ice(&state, payload).await,
        0x0012_0005 => webrtc::create_data_channel(&state, payload).await,
        0x0012_0006 => webrtc::close_call(&state, payload).await,
        0x0012_0007 => webrtc::list_active(&state, payload).await,
        0x0012_0015 => webrtc_data::send_channel_data(&state, payload).await,
        0x0012_0020 => webrtc_video::add_video_track(&state, payload).await,
        0x0012_0021 => webrtc_video::write_video_frame(&state, payload).await,
        0x0012_0022 => webrtc_video::read_video_frame(&state, payload).await,
        0x0012_0030 => webrtc_video::add_audio_track(&state, payload).await,
        0x0012_0031 => webrtc_video::write_audio_frame(&state, payload).await,
        0x0012_0032 => webrtc_video::read_audio_frame(&state, payload).await,
        0x0012_0010 => webrtc::initiate_call(&state, payload).await,
        0x0012_0011 => webrtc::accept_call(&state, payload).await,
        0x0012_0012 => webrtc::send_ice(&state, payload).await,
        0x0012_0013 => webrtc::hangup(&state, payload).await,
        0x0012_0014 => webrtc::reject(&state, payload).await,

        // websocket lifecycle
        0x00FF_0001 => ws::start(&state).await,
        0x00FF_0002 => ws::stop(&state).await,
        0x00FF_0003 => ws::send_envelope(&state, payload).await,
        0x00FF_0004 => ws::send_typing(&state, payload).await,
        0x00FF_0005 => ws::send_nudge(&state, payload).await,
        0x00FF_0006 => ws::request_history(&state, payload).await,
        0x00FF_0007 => ws::ping(&state, payload).await,
        crate::method_ids::WS_SEND_HISTORY => history_sync::send_history(&state, payload).await,

        _ => Err(Error::UnknownMethod(method)),
    };
    if crypto_guard.is_some() {
        emit_pending_identity_changes(&state).await;
    } else {
        // Identity-change notifications update the same table that a crypto
        // snapshot rollback replaces. Keep even this post-dispatch write out
        // of an in-flight rollback.
        let _crypto_guard = state.crypto_state_lock.lock().await;
        emit_pending_identity_changes(&state).await;
    }
    result
}

fn method_mutates_crypto_state(method: u32) -> bool {
    matches!(
        method,
        0x0000_0005
            | 0x0001_0001..=0x0001_0004
            | 0x0004_0001..=0x0004_0004
            | 0x0004_0010..=0x0004_0012
            | 0x0005_0004
            | 0x0005_0015
            | 0x0006_0006
            | 0x000A_0020..=0x000A_0021
            | crate::method_ids::POLL_CRYPTO_CREATE_CONVERSATION_POLL
            | crate::method_ids::POLL_CRYPTO_ENCRYPT_POLL_PAYLOAD
            | crate::method_ids::POLL_CRYPTO_ENCRYPT_POLL_OPTION
            | crate::method_ids::POLL_CRYPTO_DECRYPT_POLL_PAYLOAD
            | crate::method_ids::HISTORY_REPLAY_COMMIT
            | crate::method_ids::WS_SEND_HISTORY
            | 0x0012_0010..=0x0012_0014
    )
}

#[cfg(test)]
mod crypto_state_serialization_tests {
    use std::sync::Arc;

    use sqlx::sqlite::SqlitePoolOptions;

    use super::method_mutates_crypto_state;
    use crate::config::{Config, DiscoveryConfig};
    use crate::error::Error;
    use crate::runtime::ActorState;
    use crate::transport::HttpClient;

    #[test]
    fn serialized_method_set_covers_every_public_crypto_mutation_path() {
        for method in [
            0x0000_0005, // push activation emits crypto identity changes
            0x0001_0001, // register
            0x0001_0002, // login
            0x0001_0003, // login with TOTP
            0x0001_0004, // logout
            0x0004_0001, // establish Signal session
            0x0004_0002, // encrypt one envelope
            0x0004_0003, // decrypt one envelope
            0x0004_0004, // send a message
            0x0004_0010, // edit
            0x0004_0011, // delete
            0x0004_0012, // reaction
            0x0005_0004, // initialize device keys
            0x0005_0015, // replenish local prekeys
            0x0006_0006, // encrypt and send attachment key
            0x000A_0020, // distribute sender key
            0x000A_0021, // send sender-key message
            crate::method_ids::POLL_CRYPTO_CREATE_CONVERSATION_POLL,
            crate::method_ids::POLL_CRYPTO_ENCRYPT_POLL_PAYLOAD,
            crate::method_ids::POLL_CRYPTO_ENCRYPT_POLL_OPTION,
            crate::method_ids::POLL_CRYPTO_DECRYPT_POLL_PAYLOAD,
            crate::method_ids::HISTORY_REPLAY_COMMIT,
            crate::method_ids::WS_SEND_HISTORY,
            0x0012_0010, // call offer
            0x0012_0011, // call answer
            0x0012_0012, // ICE signal
            0x0012_0013, // hangup signal
            0x0012_0014, // reject signal
        ] {
            assert!(
                method_mutates_crypto_state(method),
                "method 0x{method:08x} must be serialized with crypto updates"
            );
        }

        for method in [
            0x0000_0001, // ping
            0x0003_0001, // list conversations
            0x0004_0005, // unknown message method
            0x0005_0005, // read device initialization status
            0x0006_0001, // seal/upload attachment without Signal state
            0x00FF_0003, // upload caller-prepared envelope
        ] {
            assert!(
                !method_mutates_crypto_state(method),
                "unrelated method 0x{method:08x} must not hold the crypto lock"
            );
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn crypto_mutation_dispatch_waits_for_the_shared_state_guard() {
        let config = Config {
            db_path: "/tmp/friendshub-core-crypto-serialization-test.db".into(),
            api_base: "http://127.0.0.1".into(),
            ws_url: "ws://127.0.0.1/ws".into(),
            discovery: DiscoveryConfig {
                enabled: false,
                ..DiscoveryConfig::default()
            },
            log_level: "off".into(),
            log_format: "text".into(),
        };
        let db = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .expect("open in-memory database");
        crate::db::migrations::MIGRATOR
            .run(&db)
            .await
            .expect("apply migrations");
        let http = HttpClient::new(&config).expect("build HTTP client");
        let state = Arc::new(ActorState::new(config, db, http));

        let guard = state.crypto_state_lock.lock().await;
        let mut request = Box::pin(super::dispatch(
            state.clone(),
            0x0004_0001,
            b"not-json".to_vec(),
        ));
        tokio::select! {
            result = &mut request => panic!("crypto dispatch bypassed the state guard: {result:?}"),
            _ = tokio::task::yield_now() => {}
        }
        drop(guard);

        assert!(matches!(request.await, Err(Error::InvalidPayload(_))));
    }
}

/// Restores durable events into the in-memory queue before the actor becomes
/// available. The rows remain in SQLite until the consumer acknowledges them.
pub(crate) async fn restore_pending_events(state: &ActorState) -> Result<()> {
    for row in pending_events::list_all(&state.db).await? {
        let event_id = match u64::try_from(row.id) {
            Ok(id) => id,
            Err(_) => {
                tracing::warn!(event_id = row.id, "ignoring pending event with invalid ID");
                continue;
            }
        };
        let payload = match serde_json::from_str(&row.payload) {
            Ok(payload) => payload,
            Err(error) => {
                tracing::error!(event_id, %error, "ignoring malformed pending event payload");
                continue;
            }
        };
        state.events.push(Event {
            id: Some(event_id),
            kind: row.event_type,
            payload,
        });
    }
    Ok(())
}

async fn activate_push(state: &Arc<ActorState>) -> Result<Vec<u8>> {
    // Emit these before draining the backlog so identity changes discovered
    // during an earlier API call are included in this push activation.
    emit_pending_identity_changes(state).await;
    state
        .events
        .drain_backlog_to_handler()
        .map_err(|error| Error::Internal(format!("could not activate event callbacks: {error}")))?;
    Ok(serde_json::to_vec(&serde_json::json!({
        "active": state.events.has_handler(),
    }))?)
}

async fn ping() -> Result<Vec<u8>> {
    Ok(br#"{"pong":true}"#.to_vec())
}

async fn version(state: &Arc<ActorState>) -> Result<Vec<u8>> {
    let v = serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "abi": crate::ffi::ABI_VERSION,
        "api_base": state.config.api_base,
        "ws_url": state.config.ws_url,
        "ws_running": state.ws.is_running(),
    });
    Ok(serde_json::to_vec(&v)?)
}

/// Claims un-notified identity changes before moving them into the event
/// queue. The conditional update and returned rows are one SQLite statement,
/// so concurrent API dispatches cannot enqueue the same warning twice. The
/// event is ephemeral: the consumer is expected to show it immediately and
/// the durable copy is not replayed after a crash.
pub(crate) async fn emit_pending_identity_changes(state: &Arc<ActorState>) {
    #[derive(sqlx::FromRow)]
    struct Row {
        id: i64,
        account_id: String,
        device_number: i64,
        old_key: Vec<u8>,
        new_key: Vec<u8>,
        changed_at: i64,
    }

    let mut rows: Vec<Row> = match sqlx::query_as::<_, Row>(
        "UPDATE identity_changes SET notified = 1
          WHERE id IN (
              SELECT id FROM identity_changes WHERE notified = 0 ORDER BY id ASC LIMIT 64
          )
          RETURNING id, account_id, device_number, old_key, new_key, changed_at",
    )
    .fetch_all(&state.db)
    .await
    {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(error = ?e, "identity_changes query failed");
            return;
        }
    };

    if rows.is_empty() {
        return;
    }

    rows.sort_by_key(|row| row.id);
    for r in rows {
        state.events.push(crate::events::types::Event::ephemeral(
            "identity_changed",
            serde_json::json!({
                "account_id": r.account_id,
                "device_number": r.device_number,
                "old_key_hex": hex::encode(&r.old_key),
                "new_key_hex": hex::encode(&r.new_key),
                "changed_at": r.changed_at,
            }),
        ));
    }
}

#[cfg(test)]
mod identity_change_tests {
    use std::sync::{Arc, mpsc};
    use std::time::Duration;

    use sqlx::sqlite::SqlitePoolOptions;

    use super::*;
    use crate::config::{Config, DiscoveryConfig};
    use crate::events::{EventHandler, types::Event};
    use crate::runtime::ActorState;
    use crate::transport::HttpClient;

    struct IdentityChangeCounter(mpsc::Sender<()>);

    impl EventHandler for IdentityChangeCounter {
        fn on_identity_changed(&self, _event: &Event) {
            let _ = self.0.send(());
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn concurrent_dispatches_emit_each_identity_change_once() {
        let config = Config {
            db_path: "/tmp/friendshub-core-identity-event-test.db".into(),
            api_base: "http://127.0.0.1".into(),
            ws_url: "ws://127.0.0.1/ws".into(),
            discovery: DiscoveryConfig {
                enabled: false,
                ..DiscoveryConfig::default()
            },
            log_level: "error".into(),
            log_format: "text".into(),
        };
        let db = SqlitePoolOptions::new()
            .max_connections(4)
            .connect("sqlite::memory:")
            .await
            .expect("open in-memory database");
        crate::db::migrations::MIGRATOR
            .run(&db)
            .await
            .expect("apply migrations");
        sqlx::query(
            "INSERT INTO identity_changes (account_id, device_number, old_key, new_key, changed_at) VALUES ('peer', 2, x'01', x'02', 1)",
        )
        .execute(&db)
        .await
        .expect("seed pending identity change");

        let events = Arc::new(crate::events::EventQueue::new());
        let (tx, rx) = mpsc::channel();
        events
            .set_handler(Arc::new(IdentityChangeCounter(tx)))
            .expect("install callback handler");
        events
            .drain_backlog_to_handler()
            .expect("activate callback handler");
        let http = HttpClient::new(&config).expect("build HTTP client");
        let state = Arc::new(ActorState::new_with_events(
            config,
            db,
            http,
            events.clone(),
        ));

        tokio::join!(
            emit_pending_identity_changes(&state),
            emit_pending_identity_changes(&state),
        );

        rx.recv_timeout(Duration::from_secs(1))
            .expect("the warning must be emitted");
        assert!(
            rx.recv_timeout(Duration::from_millis(50)).is_err(),
            "a concurrent dispatch must not enqueue a duplicate warning"
        );
        events.clear_handler_and_wait();
    }
}

#[cfg(test)]
mod poll_crypto_dispatch_tests {
    use std::sync::Arc;

    use sqlx::sqlite::SqlitePoolOptions;

    use super::dispatch;
    use crate::config::{Config, DiscoveryConfig};
    use crate::error::Error;
    use crate::events::EventQueue;
    use crate::runtime::ActorState;
    use crate::transport::HttpClient;

    #[tokio::test(flavor = "current_thread")]
    async fn poll_crypto_method_ids_reach_their_handlers() {
        let config = Config {
            db_path: "/tmp/friendshub-core-poll-dispatch-test.db".into(),
            api_base: "http://127.0.0.1".into(),
            ws_url: "ws://127.0.0.1/ws".into(),
            discovery: DiscoveryConfig {
                enabled: false,
                ..DiscoveryConfig::default()
            },
            log_level: "error".into(),
            log_format: "text".into(),
        };
        let db = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .expect("open in-memory database");
        crate::db::migrations::MIGRATOR
            .run(&db)
            .await
            .expect("apply migrations");
        let http = HttpClient::new(&config).expect("build HTTP client");
        let state = Arc::new(ActorState::new_with_events(
            config,
            db,
            http,
            Arc::new(EventQueue::new()),
        ));

        for method_id in [
            crate::method_ids::POLL_CRYPTO_CREATE_CONVERSATION_POLL,
            crate::method_ids::POLL_CRYPTO_ENCRYPT_POLL_PAYLOAD,
            crate::method_ids::POLL_CRYPTO_ENCRYPT_POLL_OPTION,
            crate::method_ids::POLL_CRYPTO_DECRYPT_POLL_PAYLOAD,
        ] {
            let error = dispatch(state.clone(), method_id, b"not-json".to_vec())
                .await
                .expect_err("invalid JSON must be rejected by the selected poll handler");
            assert!(
                matches!(error, Error::InvalidPayload(_)),
                "method 0x{method_id:08x} did not reach its poll handler: {error:?}"
            );
        }
    }
}

#[cfg(test)]
mod history_sync_dispatch_tests {
    use std::sync::Arc;

    use sqlx::sqlite::SqlitePoolOptions;

    use super::dispatch;
    use crate::config::{Config, DiscoveryConfig};
    use crate::error::Error;
    use crate::events::EventQueue;
    use crate::runtime::ActorState;
    use crate::transport::HttpClient;

    #[tokio::test(flavor = "current_thread")]
    async fn history_sync_method_reaches_its_handler() {
        let config = Config {
            db_path: "/tmp/friendshub-core-history-sync-dispatch-test.db".into(),
            api_base: "http://127.0.0.1".into(),
            ws_url: "ws://127.0.0.1/ws".into(),
            discovery: DiscoveryConfig {
                enabled: false,
                ..DiscoveryConfig::default()
            },
            log_level: "error".into(),
            log_format: "text".into(),
        };
        let db = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .expect("open in-memory database");
        crate::db::migrations::MIGRATOR
            .run(&db)
            .await
            .expect("apply migrations");
        let http = HttpClient::new(&config).expect("build HTTP client");
        let state = Arc::new(ActorState::new_with_events(
            config,
            db,
            http,
            Arc::new(EventQueue::new()),
        ));

        let error = dispatch(state, 0x00FF_0008, b"not-json".to_vec())
            .await
            .expect_err("invalid JSON must be rejected by the history sender");
        assert!(
            matches!(error, Error::InvalidPayload(_)),
            "method 0x00ff0008 did not reach the history handler: {error:?}"
        );
    }
}

#[cfg(test)]
mod history_replay_dispatch_tests {
    use std::sync::Arc;

    use sqlx::sqlite::SqlitePoolOptions;

    use super::dispatch;
    use crate::config::{Config, DiscoveryConfig};
    use crate::error::Error;
    use crate::events::EventQueue;
    use crate::runtime::ActorState;
    use crate::transport::HttpClient;

    #[tokio::test(flavor = "current_thread")]
    async fn history_replay_method_ids_reach_their_handlers() {
        let config = Config {
            db_path: "/tmp/friendshub-core-history-replay-dispatch-test.db".into(),
            api_base: "http://127.0.0.1".into(),
            ws_url: "ws://127.0.0.1/ws".into(),
            discovery: DiscoveryConfig {
                enabled: false,
                ..DiscoveryConfig::default()
            },
            log_level: "error".into(),
            log_format: "text".into(),
        };
        let db = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .expect("open in-memory database");
        crate::db::migrations::MIGRATOR
            .run(&db)
            .await
            .expect("apply migrations");
        let http = HttpClient::new(&config).expect("build HTTP client");
        let state = Arc::new(ActorState::new_with_events(
            config,
            db,
            http,
            Arc::new(EventQueue::new()),
        ));

        for method_id in [0x0013_0030, 0x0013_0031, 0x0013_0032, 0x0013_0033] {
            let error = dispatch(state.clone(), method_id, b"not-json".to_vec())
                .await
                .expect_err("invalid JSON must be rejected by a history replay handler");
            assert!(
                matches!(error, Error::InvalidPayload(_)),
                "method 0x{method_id:08x} did not reach history replay: {error:?}"
            );
        }
    }
}
