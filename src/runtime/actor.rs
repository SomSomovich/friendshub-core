use std::sync::Arc;
use std::thread;

use futures::future::BoxFuture;
use tokio::sync::mpsc;
use tokio::task::LocalSet;

use crate::config::Config;
use crate::db::Db;
use crate::error::{Error, Result};
use crate::events::EventQueue;
use crate::transport::{HttpClient, WsClient};

pub struct Actor {
    tx: mpsc::UnboundedSender<Request>,
}

pub struct Request {
    pub method: u32,
    pub payload: Vec<u8>,
    pub reply: crossbeam_channel::Sender<Result<Vec<u8>>>,
}

pub struct ActorState {
    pub config: Config,
    pub db: Db,
    pub http: HttpClient,
    pub ws: Arc<WsClient>,
    pub events: EventQueue,
}

impl ActorState {
    pub fn new(config: Config, db: Db, http: HttpClient) -> Self {
        Self {
            config,
            db,
            http,
            ws: Arc::new(WsClient::new()),
            events: EventQueue::new(),
        }
    }
}

impl Actor {
    pub fn spawn<F>(init: F) -> Result<Self>
    where
        F: FnOnce() -> BoxFuture<'static, Result<ActorState>> + Send + 'static,
    {
        let (tx, rx) = mpsc::unbounded_channel::<Request>();
        let (init_tx, init_rx) = crossbeam_channel::bounded::<Result<()>>(1);

        thread::Builder::new()
            .name("friendshub-core".into())
            .spawn(move || {
                // libsignal declares its store traits with `#[async_trait(?Send)]`,
                // which makes every future awaiting them `!Send`. A multi-threaded
                // runtime will not schedule such a future at all, so the actor runs
                // on a single-threaded runtime with a LocalSet and request handlers
                // are dispatched through spawn_local.
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

                    if init_tx.send(Ok(())).is_err() {
                        return;
                    }
                    drop(init_tx);

                    run(rx, Arc::new(state)).await;
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
        self.tx.send(req).map_err(|_| Error::ActorClosed)?;
        reply_rx.recv().map_err(|_| Error::ActorClosed)?
    }
}

async fn run(mut rx: mpsc::UnboundedReceiver<Request>, state: Arc<ActorState>) {
    while let Some(req) = rx.recv().await {
        let state = state.clone();
        tokio::task::spawn_local(async move {
            let result = crate::api::dispatch(state, req.method, req.payload).await;
            let _ = req.reply.send(result);
        });
    }
}
