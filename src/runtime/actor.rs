use std::future::Future;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use futures::future::BoxFuture;
use tokio::runtime::Runtime;
use tokio::sync::{Mutex, mpsc};
use tokio::task::LocalSet;

use crate::config::Config;
use crate::db::Db;
use crate::error::{Error, Result};
use crate::events::EventQueue;
use crate::transport::{HttpClient, WsClient};
use crate::webrtc::WebRtcManager;

/// Messages the actor thread understands. `Shutdown` exists so `fh_destroy`
/// can ask the websocket to close and the loop to stop, instead of dropping
/// the sender and letting the socket die with the process.
pub enum ActorMessage {
    Call(Request),
    Shutdown,
}

pub struct Request {
    pub method: u32,
    pub payload: Vec<u8>,
    pub reply: crossbeam_channel::Sender<Result<Vec<u8>>>,
}

pub struct Actor {
    tx: mpsc::UnboundedSender<ActorMessage>,
    thread_done: crossbeam_channel::Receiver<()>,
    thread: Option<thread::JoinHandle<()>>,
}

pub struct ActorState {
    pub config: Config,
    pub db: Db,
    pub http: HttpClient,
    pub ws: Arc<WsClient>,
    pub events: Arc<EventQueue>,
    pub webrtc: Arc<WebRtcManager>,
    /// Serializes every operation that reads or mutates Signal/sender-key
    /// state. Snapshot rollback replaces complete crypto tables, so it must
    /// not overlap another ratchet update or identity-change notification.
    pub(crate) crypto_state_lock: Arc<Mutex<()>>,
    pub(crate) history_replay_stages: Arc<Mutex<crate::crypto::history_stage::ReplayStages>>,
}

fn run_local_set<F>(runtime: &Runtime, local: LocalSet, future: F)
where
    F: Future<Output = ()>,
{
    runtime.block_on(async move {
        local.run_until(future).await;
        drop(local);
        tokio::task::yield_now().await;
    });
}

impl ActorState {
    pub fn new(config: Config, db: Db, http: HttpClient) -> Self {
        Self::new_with_events(config, db, http, Arc::new(EventQueue::new()))
    }

    pub fn new_with_events(
        config: Config,
        db: Db,
        http: HttpClient,
        events: Arc<EventQueue>,
    ) -> Self {
        Self {
            config,
            db,
            http,
            ws: Arc::new(WsClient::new()),
            events,
            webrtc: Arc::new(WebRtcManager::new()),
            crypto_state_lock: Arc::new(Mutex::new(())),
            history_replay_stages: Arc::new(Mutex::new(
                crate::crypto::history_stage::ReplayStages::default(),
            )),
        }
    }
}

impl Actor {
    pub fn spawn<F>(init: F) -> Result<Self>
    where
        F: FnOnce() -> BoxFuture<'static, Result<ActorState>> + Send + 'static,
    {
        let (tx, rx) = mpsc::unbounded_channel::<ActorMessage>();
        let (init_tx, init_rx) = crossbeam_channel::bounded::<Result<()>>(1);
        let (thread_done_tx, thread_done) = crossbeam_channel::bounded::<()>(1);

        let thread = thread::Builder::new()
            .name("friendshub-core".into())
            .spawn(move || {
                let rt = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(rt) => rt,
                    Err(e) => {
                        let _ = init_tx.send(Err(Error::RuntimeBuild(e.to_string())));
                        return;
                    }
                };

                let local = LocalSet::new();
                run_local_set(&rt, local, async move {
                    let state = match init().await {
                        Ok(s) => s,
                        Err(e) => {
                            let _ = init_tx.send(Err(e));
                            return;
                        }
                    };
                    if let Err(error) = crate::api::restore_pending_events(&state).await {
                        let _ = init_tx.send(Err(error));
                        return;
                    }
                    let state = Arc::new(state);

                    // WebRTC event forwarder. Runs for the lifetime of the actor.
                    {
                        let state_for_loop = state.clone();
                        let manager = state.webrtc.clone();
                        tokio::task::spawn_local(async move {
                            manager.run_event_loop(state_for_loop).await;
                        });
                    }

                    // Periodic cleanup of tables that would otherwise grow
                    // without bound. Runs for the lifetime of the actor.
                    {
                        let db = state.db.clone();
                        let crypto_state_lock = state.crypto_state_lock.clone();
                        tokio::task::spawn_local(async move {
                            crate::db::cleanup::run(db, crypto_state_lock).await;
                        });
                    }

                    if init_tx.send(Ok(())).is_err() {
                        return;
                    }
                    drop(init_tx);

                    run(rx, state).await;
                });
                drop(rt);
                let _ = thread_done_tx.send(());
            })
            .map_err(|e| Error::SpawnThread(e.to_string()))?;

        match init_rx.recv() {
            Ok(Ok(())) => Ok(Self {
                tx,
                thread_done,
                thread: Some(thread),
            }),
            Ok(Err(e)) => {
                let _ = thread.join();
                Err(e)
            }
            Err(_) => {
                let _ = thread.join();
                Err(Error::ActorClosed)
            }
        }
    }

    pub fn call(&self, method: u32, payload: Vec<u8>) -> Result<Vec<u8>> {
        let (reply_tx, reply_rx) = crossbeam_channel::bounded(1);
        let req = Request {
            method,
            payload,
            reply: reply_tx,
        };
        self.tx
            .send(ActorMessage::Call(req))
            .map_err(|_| Error::ActorClosed)?;
        reply_rx.recv().map_err(|_| Error::ActorClosed)?
    }
}

impl Drop for Actor {
    fn drop(&mut self) {
        // The completion signal arrives after LocalSet and Tokio runtime
        // teardown, because SQLx connections can be returned while tasks drop.
        let _ = self.tx.send(ActorMessage::Shutdown);
        match self.thread_done.recv_timeout(Duration::from_secs(2)) {
            Ok(()) | Err(crossbeam_channel::RecvTimeoutError::Disconnected) => {
                if let Some(thread) = self.thread.take() {
                    let _ = thread.join();
                }
            }
            Err(crossbeam_channel::RecvTimeoutError::Timeout) => {}
        }
    }
}

async fn run(mut rx: mpsc::UnboundedReceiver<ActorMessage>, state: Arc<ActorState>) {
    while let Some(msg) = rx.recv().await {
        match msg {
            ActorMessage::Call(req) => {
                let state = state.clone();
                tokio::task::spawn_local(async move {
                    let result = crate::api::dispatch(state, req.method, req.payload).await;
                    let _ = req.reply.send(result);
                });
            }
            ActorMessage::Shutdown => {
                let _ = state.ws.stop().await;
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::panic::{AssertUnwindSafe, catch_unwind};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use tokio::sync::oneshot;

    struct ConnectionDropProbe {
        _connection: sqlx::pool::PoolConnection<sqlx::Sqlite>,
        saw_tokio_context: Arc<AtomicBool>,
    }

    impl Drop for ConnectionDropProbe {
        fn drop(&mut self) {
            self.saw_tokio_context.store(
                tokio::runtime::Handle::try_current().is_ok(),
                Ordering::SeqCst,
            );
        }
    }

    #[test]
    fn local_task_pool_connections_drop_inside_the_tokio_context() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let pool = runtime
            .block_on(
                sqlx::sqlite::SqlitePoolOptions::new()
                    .max_connections(1)
                    .connect("sqlite::memory:"),
            )
            .unwrap();
        let pool_for_task = pool.clone();
        let saw_tokio_context = Arc::new(AtomicBool::new(false));
        let context_probe = saw_tokio_context.clone();
        let (started_tx, started_rx) = oneshot::channel();
        let local = LocalSet::new();
        let actor = async move {
            tokio::task::spawn_local(async move {
                let connection = pool_for_task.acquire().await.unwrap();
                let _connection = ConnectionDropProbe {
                    _connection: connection,
                    saw_tokio_context: context_probe,
                };
                let _ = started_tx.send(());
                std::future::pending::<()>().await;
            });
            started_rx.await.unwrap();
        };

        let teardown = catch_unwind(AssertUnwindSafe(|| run_local_set(&runtime, local, actor)));
        runtime.block_on(pool.close());
        assert!(teardown.is_ok(), "local actor task teardown panicked");
        assert!(
            saw_tokio_context.load(Ordering::SeqCst),
            "local actor task was dropped after leaving the Tokio context"
        );
    }
}
