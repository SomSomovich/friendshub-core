use std::sync::Arc;
use std::time::Duration;

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
pub mod common;
pub mod contacts;
pub mod conversations;
pub mod device_init;
pub mod device_cache_api;
pub mod devices;
pub mod groups;
pub mod groups_send;
pub mod invites;
pub mod message_actions;
pub mod messages;
pub mod prekeys;
pub mod profile;
pub mod sessions;
pub mod twofa;
pub mod user_profiles;
pub mod webrtc;
pub mod webrtc_video;
pub mod webrtc_data;
pub mod ws;

pub struct DispatchMarker;

/// Method IDs are namespaced by area. See docs/ffi.md for the full table.
pub async fn dispatch(state: Arc<ActorState>, method: u32, payload: Vec<u8>) -> Result<Vec<u8>> {
    match method {
        // service
        0x0000_0001 => ping().await,
        0x0000_0002 => version(&state).await,
        0x0000_0003 => poll_event(&state, &payload).await,
        0x0000_0004 => ws::ack_event(&state, payload).await,

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

        // conversations
        0x0003_0001 => conversations::list(&state, payload).await,
        0x0003_0002 => conversations::create_direct(&state, payload).await,
        0x0003_0003 => conversations::get_one(&state, payload).await,
        0x0003_0004 => conversations::leave(&state, payload).await,
        0x0003_0005 => conversations::archive(&state, payload).await,
        0x0003_0006 => conversations::unarchive(&state, payload).await,
        0x0003_0007 => conversations::mute(&state, payload).await,
        0x0003_0008 => conversations::unmute(&state, payload).await,

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

        // groups
        0x000A_0001 => groups::create(&state, payload).await,
        0x000A_0002 => groups::list_public(&state, payload).await,
        0x000A_0003 => groups::join_public(&state, payload).await,
        0x000A_0004 => groups::lookup_by_handle(&state, payload).await,
        0x000A_0005 => groups::list_members(&state, payload).await,
        0x000A_0006 => groups::set_role(&state, payload).await,
        0x000A_0007 => groups::mute_member(&state, payload).await,
        0x000A_0008 => groups::set_user_profile(&state, payload).await,
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

        _ => Err(Error::UnknownMethod(method)),
    }
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

async fn poll_event(state: &Arc<ActorState>, payload: &[u8]) -> Result<Vec<u8>> {
    // Identity key changes are stored in a table by the crypto store, which
    // has no access to the event queue. Move any waiting rows into the
    // queue before polling so the consumer sees them in order.
    emit_pending_identity_changes(state).await;

    let timeout_ms = if payload.len() >= 4 {
        u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]) as u64
    } else {
        0
    };

    let timeout = Duration::from_millis(timeout_ms);
    match state.events.poll(timeout).await {
        Some(ev) => Ok(serde_json::to_vec(&ev)?),
        None => Ok(Vec::new()),
    }
}

#[allow(dead_code)]
fn _touch(_: Event) {}

/// Moves un-notified identity changes into the event queue and marks them
/// notified. The event is ephemeral: the consumer is expected to show it
/// immediately and the durable copy is not replayed after a crash. If the
/// UI is not running, the warning would arrive too late to matter anyway.
async fn emit_pending_identity_changes(state: &Arc<ActorState>) {
    #[derive(sqlx::FromRow)]
    struct Row {
        id: i64,
        account_id: String,
        device_number: i64,
        old_key: Vec<u8>,
        new_key: Vec<u8>,
        changed_at: i64,
    }

    let rows: Vec<Row> = match sqlx::query_as::<_, Row>(
        "SELECT id, account_id, device_number, old_key, new_key, changed_at FROM identity_changes WHERE notified = 0 ORDER BY id ASC LIMIT 64",
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

    let mut acked: Vec<i64> = Vec::with_capacity(rows.len());
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
        acked.push(r.id);
    }

    for id in acked {
        let _ = sqlx::query("UPDATE identity_changes SET notified = 1 WHERE id = ?")
            .bind(id)
            .execute(&state.db)
            .await;
    }
}
