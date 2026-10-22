//! Safe native Rust client facade.
//!
//! The facade accepts and returns owned Rust values. Buffer allocation,
//! protobuf/HTTP conversion, actor scheduling, and event storage stay inside
//! the library.

use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::config::Config;
use crate::db;
use crate::error::{Error, Result};
use crate::events::{Event, EventHandler, EventQueue};
use crate::runtime::{Actor, ActorState};
use crate::transport::HttpClient;

pub mod method_ids {
    include!("method_ids.rs");
}

/// One native FriendsHub client instance for one account and database.
pub struct Client {
    actor: Actor,
    events: Arc<EventQueue>,
}

impl Client {
    /// Opens a client, resolves configured service URLs, and applies database
    /// migrations before returning.
    pub fn open(config: Config) -> Result<Self> {
        crate::logging::init_once(&config.log_level, &config.log_format);
        let events = Arc::new(EventQueue::new());
        let actor_events = events.clone();
        let actor = Actor::spawn(move || {
            Box::pin(async move {
                let resolved = crate::discovery::resolve(&config).await?;
                let mut config = config;
                config.api_base = resolved.api_base;
                config.ws_url = resolved.ws_url;

                let http = HttpClient::new(&config)?;
                let db = db::pool::open(&config.db_path).await?;
                db::migrations::MIGRATOR
                    .run(&db)
                    .await
                    .map_err(|e| Error::Database(format!("migrations failed: {e}")))?;
                Ok(ActorState::new_with_events(config, db, http, actor_events))
            })
        })?;
        Ok(Self { actor, events })
    }

    /// Calls a dispatcher method with a JSON request and decodes its JSON
    /// response into an owned Rust value.
    pub fn call_json<Q, R>(&self, method_id: u32, request: &Q) -> Result<R>
    where
        Q: Serialize,
        R: DeserializeOwned,
    {
        let request = serde_json::to_vec(request)?;
        let response = self.actor.call(method_id, request)?;
        serde_json::from_slice(&response).map_err(Error::from)
    }

    /// Calls a dispatcher method with raw request bytes and returns owned
    /// response bytes. This is useful for protobuf payloads and binary APIs.
    pub fn call_bytes(&self, method_id: u32, request: &[u8]) -> Result<Vec<u8>> {
        self.actor.call(method_id, request.to_vec())
    }

    /// Waits for the next event using the compatibility pull interface.
    /// Registered handlers receive future events on the callback worker.
    pub fn poll_event(&self, timeout: Duration) -> Result<Option<Event>> {
        let bytes = self
            .actor
            .call(method_ids::POLL_EVENT, 0_u32.to_le_bytes().to_vec())?;
        if !bytes.is_empty() {
            return serde_json::from_slice(&bytes)
                .map(Some)
                .map_err(Error::from);
        }
        Ok(self.events.poll(timeout))
    }

    /// Acknowledges a durable event, including its delivery receipt when
    /// applicable. Ephemeral events have no ID to acknowledge.
    pub fn ack_event(&self, event_id: u64) -> Result<()> {
        self.actor
            .call(0x0000_0004, event_id.to_le_bytes().to_vec())?;
        Ok(())
    }

    /// Routes queued and future events to a type-specific handler on a
    /// dedicated worker thread. Unacknowledged durable events restored from
    /// the database are pushed as part of registration. Event data is
    /// borrowed only for each method call.
    pub fn set_event_handler(&self, handler: Arc<dyn EventHandler>) -> Result<()> {
        self.events.set_handler(handler).map_err(|error| {
            Error::Internal(format!("could not start event callback worker: {error}"))
        })?;
        if let Err(error) = self.actor.call(method_ids::ACTIVATE_EVENT_PUSH, Vec::new()) {
            self.events.clear_handler_and_wait();
            return Err(error);
        }
        Ok(())
    }

    /// Returns future events to `poll_event` and waits for in-flight callback
    /// work to finish.
    pub fn clear_event_handler(&self) {
        self.events.clear_handler_and_wait();
    }
}
