use std::sync::Arc;
use std::thread;
use std::time::Duration;

use futures::future::BoxFuture;
use tokio::sync::mpsc;
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
    Shutdown(crossbeam_channel::Sender<()>),
}

pub struct Request {
    pub method: u32,
    pub payload: Vec<u8>,
    pub reply: crossbeam_channel::Sender<Result<Vec<u8>>>,
}

pub struct Actor {
    tx: mpsc::UnboundedSender<ActorMessage>,
}

pub struct ActorState {
    pub config: Config,
    pub db: Db,
    pub http: HttpClient,
    pub ws: Arc<WsClient>,
    pub events: EventQueue,
    pub webrtc: Arc<WebRtcManager>,
}

impl ActorState {
    pub fn new(config: Config, db: Db, http: HttpClient) -> Self {
        Self {
            config,
            db,
            http,
            ws: Arc::new(WsClient::new()),
            events: EventQueue::new(),
            webrtc: Arc::new(WebRtcManager::new()),
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

        thread::Builder::new()
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
                rt.block_on(local.run_until(async move {
                    let state = match init().await {
                        Ok(s) => s,
                        Err(e) => {
                            let _ = init_tx.send(Err(e));
                            return;
                        }
                    };
                    let state = Arc::new(state);

                    {
                        let state_for_loop = state.clone();
                        let manager = state.webrtc.clone();
                        tokio::task::spawn_local(async move {
                            manager.run_event_loop(state_for_loop).await;
                        });
                    }

                    if init_tx.send(Ok(())).is_err() {
                        return;
                    }
                    drop(init_tx);

                    run(rx, state).await;
                }));
            })
            .map_err(|e| Error::SpawnThread(e.to_string()))?;

        match init_rx.recv() {
            Ok(Ok(())) => Ok(Self { tx }),
            Ok(Err(e)) => Err(e),
            Err(_) => Err(Error::ActorClosed),
        }
    }

    pub fn call(&self, method: u32, payload: Vec<u8>) -> Result<Vec<u8>> {
        let (reply_tx, reply_rx) = crossbeam_channel::bounded(1);
        let req = Request { method, payload, reply: reply_tx };
        self.tx
            .send(ActorMessage::Call(req))
            .map_err(|_| Error::ActorClosed)?;
        reply_rx.recv().map_err(|_| Error::ActorClosed)?
    }
}

impl Drop for Actor {
    fn drop(&mut self) {
        // Ask the actor thread to close the websocket and stop. The wait is
        // bounded: if the thread is stuck on a request, do not hold the
        // process open for it.
        let (done_tx, done_rx) = crossbeam_channel::bounded(1);
        if self.tx.send(ActorMessage::Shutdown(done_tx)).is_ok() {
            let _ = done_rx.recv_timeout(Duration::from_secs(2));
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
            ActorMessage::Shutdown(done) => {
                let _ = state.ws.stop().await;
                let _ = done.send(());
                break;
            }
        }
    }
}
