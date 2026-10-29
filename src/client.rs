//! Safe native Rust client facade.
//!
//! The facade accepts and returns owned Rust values. Buffer allocation,
//! protobuf/HTTP conversion, actor scheduling, and event storage stay inside
//! the library.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::config::Config;
use crate::db;
use crate::error::{Error, Result};
use crate::events::{EventHandler, EventQueue};
use crate::runtime::{Actor, ActorState};
use crate::transport::HttpClient;

pub mod method_ids {
    include!("method_ids.rs");
}

mod typed;

/// One native FriendsHub client instance for one account and database.
pub struct Client {
    actor: Actor,
    events: Arc<EventQueue>,
    lifecycle: RwLock<()>,
    event_lifecycle: Mutex<()>,
    closed: AtomicBool,
}

impl Client {
    /// Opens a client, resolves configured service URLs, and applies database
    /// schema migrations before returning.
    pub fn open(config: Config) -> Result<Self> {
        #[cfg(target_os = "android")]
        let android_open_guard = db::key_store::android::begin_core_open()?;

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

        #[cfg(target_os = "android")]
        android_open_guard.commit();

        Ok(Self {
            actor,
            events,
            lifecycle: RwLock::new(()),
            event_lifecycle: Mutex::new(()),
            closed: AtomicBool::new(false),
        })
    }

    /// Calls a dispatcher method with a JSON request and decodes its JSON
    /// response into an owned Rust value.
    pub fn call_json<Q, R>(&self, method_id: u32, request: &Q) -> Result<R>
    where
        Q: Serialize,
        R: DeserializeOwned,
    {
        let _guard = self.lifecycle.read().map_err(|_| Error::ActorClosed)?;
        if self.is_shutdown() {
            return Err(Error::ActorClosed);
        }
        let request = serde_json::to_vec(request)?;
        let response = self.actor.call(method_id, request)?;
        serde_json::from_slice(&response).map_err(Error::from)
    }

    /// Calls a dispatcher method with raw request bytes and returns owned
    /// response bytes. This is useful for protobuf payloads and binary APIs.
    pub fn call_bytes(&self, method_id: u32, request: &[u8]) -> Result<Vec<u8>> {
        let _guard = self.lifecycle.read().map_err(|_| Error::ActorClosed)?;
        if self.is_shutdown() {
            return Err(Error::ActorClosed);
        }
        self.actor.call(method_id, request.to_vec())
    }

    /// Acknowledges a durable event, including its delivery receipt when
    /// applicable. Ephemeral events have no ID to acknowledge.
    pub fn ack_event(&self, event_id: u64) -> Result<()> {
        let _guard = self.lifecycle.read().map_err(|_| Error::ActorClosed)?;
        if self.is_shutdown() {
            return Err(Error::ActorClosed);
        }
        self.actor
            .call(0x0000_0004, event_id.to_le_bytes().to_vec())?;
        Ok(())
    }

    /// Routes queued and future events to a type-specific handler on a
    /// dedicated worker thread. Unacknowledged durable events restored from
    /// the database are pushed as part of registration. Event data is
    /// borrowed only for each method call.
    pub fn set_event_handler(&self, handler: Arc<dyn EventHandler>) -> Result<()> {
        let _guard = self
            .event_lifecycle
            .lock()
            .map_err(|_| Error::ActorClosed)?;
        if self.is_shutdown() {
            return Err(Error::ActorClosed);
        }
        // Replacing a handler joins callbacks which can call the client. Do
        // not hold the lifecycle read lock here: a queued shutdown writer
        // would otherwise block a callback needed to finish this replacement.
        self.events.set_handler(handler).map_err(|error| {
            Error::Internal(format!("could not start event callback worker: {error}"))
        })?;
        if let Err(error) = self.actor.call(method_ids::ACTIVATE_EVENT_PUSH, Vec::new()) {
            self.events.clear_handler_and_wait();
            return Err(error);
        }
        if self.is_shutdown() {
            self.events.clear_handler_and_wait();
            return Err(Error::ActorClosed);
        }
        Ok(())
    }

    /// Stop this local client without revoking the remote session. Blocks
    /// until accepted calls finish, actor tasks and database handles close,
    /// and event callbacks return. Call only from an application worker,
    /// never from an event callback or the UI thread. Future calls fail.
    pub fn shutdown_local(&self) -> Result<()> {
        self.closed.store(true, Ordering::SeqCst);
        let result = {
            let _guard = self.lifecycle.write().map_err(|_| Error::ActorClosed)?;
            self.actor.shutdown()
        };
        // Do not hold the lifecycle write lock while joining callbacks: a
        // callback may be completing an acknowledgement against this client.
        self.clear_event_handler();
        result
    }

    /// True once local shutdown has started; useful for discarding stale UI
    /// completions that were queued before account removal.
    pub fn is_shutdown(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    /// Erase a tombstoned database and its path-scoped OS credential after
    /// all clients for that path have closed. This never calls the server.
    /// The caller must keep its durable removal marker until this succeeds.
    pub fn remove_local_database(
        path: &std::path::Path,
    ) -> std::result::Result<(), db::pool::LocalDatabaseRemovalError> {
        db::pool::remove_local_database(path)
    }

    /// Stops event delivery and waits for in-flight callback work to finish.
    /// Events produced while no handler is registered are pushed when the
    /// next handler is installed.
    pub fn clear_event_handler(&self) {
        let _guard = self
            .event_lifecycle
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.events.clear_handler_and_wait();
    }
}
