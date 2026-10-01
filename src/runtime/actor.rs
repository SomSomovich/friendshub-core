use std::sync::Arc;
use std::thread;

use futures::future::BoxFuture;
use tokio::sync::mpsc;

use crate::config::Config;
use crate::db::Db;
use crate::error::{Error, Result};

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
}

impl ActorState {
    pub fn new(config: Config, db: Db) -> Self {
        Self { config, db }
    }
}

impl Actor {
    pub fn spawn<F>(init: F) -> Result<Self>
    where
        F: FnOnce() -> BoxFuture<'static, Result<ActorState>> + Send + 'static,
    {
        let (tx, rx) = mpsc::unbounded_channel::<Request>();
        let (init_tx, init_rx) = crossbeam_channel::bounded::<Result<()>>(1);

        // The thread owns the runtime; nothing else may hold a handle to it,
        // otherwise Runtime::drop panics when it runs on the wrong thread.
        thread::Builder::new()
            .name("friendshub-core".into())
            .spawn(move || {
                let rt = match tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(2)
                    .thread_name("friendshub-core-w")
                    .enable_all()
                    .build()
                {
                    Ok(rt) => rt,
                    Err(e) => {
                        let _ = init_tx.send(Err(Error::RuntimeBuild(e.to_string())));
                        return;
                    }
                };

                rt.block_on(async move {
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
                });
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
        tokio::spawn(async move {
            let result = crate::api::dispatch(&state, req.method, req.payload).await;
            let _ = req.reply.send(result);
        });
    }
}
