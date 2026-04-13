use std::{
    fmt,
    future::Future,
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, OnceLock},
};

use tokio::{
    net::{TcpListener, TcpStream},
    sync::{oneshot, Mutex},
    task::{JoinHandle, JoinSet},
};

use crate::{
    error::{ProxyError, Result},
    types::Listen,
};

type ListenerBindFuture = Pin<Box<dyn Future<Output = Result<TcpListener>> + Send + 'static>>;
type ListenerAcceptFuture = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;

pub type ListenerFactory = dyn Fn(SocketAddr) -> ListenerBindFuture + Send + Sync;
pub type ListenerAcceptHandler =
    dyn Fn(TcpStream, SocketAddr) -> ListenerAcceptFuture + Send + Sync;

#[derive(Default)]
struct ListenerState {
    close_tx: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<Result<()>>>,
}

pub struct Listener {
    listen: Listen,
    factory: Arc<ListenerFactory>,
    handler: OnceLock<Arc<ListenerAcceptHandler>>,
    state: Mutex<ListenerState>,
}

impl fmt::Debug for Listener {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let running = self
            .state
            .try_lock()
            .map(|state| state.task.is_some())
            .unwrap_or(false);
        f.debug_struct("Listener")
            .field("listen", &self.listen)
            .field("handler_bound", &self.handler.get().is_some())
            .field("running", &running)
            .finish()
    }
}

impl Listener {
    pub fn new(listen: Listen, factory: Arc<ListenerFactory>) -> Self {
        Self {
            listen,
            factory,
            handler: OnceLock::new(),
            state: Mutex::new(ListenerState::default()),
        }
    }

    pub fn listen(&self) -> &Listen {
        &self.listen
    }

    pub fn bind_addr(&self) -> Result<SocketAddr> {
        self.listen.parse_addr().map_err(|err| {
            ProxyError::config(format!("listen must be a valid socket address: {err}"))
        })
    }

    pub fn bind_handler(&self, handler: Arc<ListenerAcceptHandler>) -> Result<()> {
        self.handler
            .set(handler)
            .map_err(|_| ProxyError::protocol("listener handler is already bound"))
    }

    pub async fn start(&self) -> Result<()> {
        let handler =
            Arc::clone(self.handler.get().ok_or_else(|| {
                ProxyError::protocol("listener handler must be bound before start")
            })?);
        let mut state = self.state.lock().await;
        if state.task.is_some() {
            return Ok(());
        }

        let listener = (self.factory)(self.bind_addr()?).await?;
        let (close_tx, mut close_rx) = oneshot::channel();
        let task = tokio::spawn(async move {
            let mut connections = JoinSet::new();
            let mut shutting_down = false;

            loop {
                if shutting_down && connections.is_empty() {
                    break;
                }

                tokio::select! {
                    _ = &mut close_rx, if !shutting_down => {
                        shutting_down = true;
                    }
                    accept_result = listener.accept(), if !shutting_down => {
                        let (stream, peer) = accept_result?;
                        let handler = Arc::clone(&handler);
                        connections.spawn(async move {
                            handler(stream, peer).await;
                        });
                    }
                    maybe_task = connections.join_next(), if !connections.is_empty() => {
                        if let Some(Err(err)) = maybe_task {
                            return Err(ProxyError::protocol_ctx(
                                "listener connection task join failed",
                                err,
                            ));
                        }
                    }
                }
            }

            Ok(())
        });

        state.close_tx = Some(close_tx);
        state.task = Some(task);
        Ok(())
    }

    pub async fn close(&self) -> Result<()> {
        let (close_tx, task) = {
            let mut state = self.state.lock().await;
            (state.close_tx.take(), state.task.take())
        };

        if let Some(close_tx) = close_tx {
            let _ = close_tx.send(());
        }

        let Some(task) = task else {
            return Ok(());
        };

        match task.await {
            Ok(result) => result,
            Err(err) => Err(ProxyError::protocol_ctx("listener task join failed", err)),
        }
    }
}
