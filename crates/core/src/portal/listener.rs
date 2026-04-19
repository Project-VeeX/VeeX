use std::{
    fmt,
    future::Future,
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, OnceLock},
};

use tokio::{
    net::{TcpListener, TcpStream, UdpSocket},
    sync::{Mutex, oneshot},
    task::{JoinHandle, JoinSet},
};

use crate::{
    error::{ProxyError, Result},
    io::PacketWriter,
    types::Listen,
};

/// Listener is responsible for:
/// - binding and accepting incoming connections / packets
/// - inbound-side context lowering
///
/// Listener MUST NOT:
/// - perform protocol parsing
/// - perform routing / dispatch decisions
/// - interact with outbound logic
type ListenerBindFuture = Pin<Box<dyn Future<Output = Result<TcpListener>> + Send + 'static>>;
type ListenerAcceptFuture = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;
type PacketListenerBindFuture = Pin<Box<dyn Future<Output = Result<UdpSocket>> + Send + 'static>>;
type PacketListenerReceiveFuture = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;

pub type ListenerFactory = dyn Fn(SocketAddr) -> ListenerBindFuture + Send + Sync;
pub type ListenerAcceptHandler =
    dyn Fn(TcpStream, SocketAddr) -> ListenerAcceptFuture + Send + Sync;
pub type PacketListenerFactory = dyn Fn(SocketAddr) -> PacketListenerBindFuture + Send + Sync;
pub type PacketListenerReceiveHandler =
    dyn Fn(PacketListenerReceive) -> PacketListenerReceiveFuture + Send + Sync;

pub struct PacketListenerReceive {
    pub local_addr: SocketAddr,
    pub peer: SocketAddr,
    pub payload: Vec<u8>,
    pub writer: Arc<dyn PacketWriter>,
}

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

#[derive(Default)]
struct PacketListenerState {
    close_tx: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<Result<()>>>,
}

pub struct PacketListener {
    listen: Listen,
    factory: Arc<PacketListenerFactory>,
    handler: OnceLock<Arc<PacketListenerReceiveHandler>>,
    state: Mutex<PacketListenerState>,
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

impl fmt::Debug for PacketListener {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let running = self
            .state
            .try_lock()
            .map(|state| state.task.is_some())
            .unwrap_or(false);
        f.debug_struct("PacketListener")
            .field("listen", &self.listen)
            .field("handler_bound", &self.handler.get().is_some())
            .field("running", &running)
            .finish()
    }
}

impl PacketListener {
    pub fn new(listen: Listen, factory: Arc<PacketListenerFactory>) -> Self {
        Self {
            listen,
            factory,
            handler: OnceLock::new(),
            state: Mutex::new(PacketListenerState::default()),
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

    pub fn bind_handler(&self, handler: Arc<PacketListenerReceiveHandler>) -> Result<()> {
        self.handler
            .set(handler)
            .map_err(|_| ProxyError::protocol("packet listener handler is already bound"))
    }

    pub async fn start(&self) -> Result<()> {
        let handler = Arc::clone(self.handler.get().ok_or_else(|| {
            ProxyError::protocol("packet listener handler must be bound before start")
        })?);
        let mut state = self.state.lock().await;
        if state.task.is_some() {
            return Ok(());
        }

        let socket = Arc::new((self.factory)(self.bind_addr()?).await?);
        let local_addr = socket.local_addr()?;
        let writer: Arc<dyn PacketWriter> = Arc::new(UdpPacketWriter {
            socket: Arc::clone(&socket),
        });
        let (close_tx, mut close_rx) = oneshot::channel();
        let task = tokio::spawn(async move {
            let mut packets = JoinSet::new();
            let mut buf = vec![0u8; u16::MAX as usize];
            let mut shutting_down = false;

            loop {
                if shutting_down && packets.is_empty() {
                    break;
                }

                tokio::select! {
                    _ = &mut close_rx, if !shutting_down => {
                        shutting_down = true;
                    }
                    recv_result = socket.recv_from(&mut buf), if !shutting_down => {
                        let (size, peer) = recv_result?;
                        let handler = Arc::clone(&handler);
                        let writer = Arc::clone(&writer);
                        let payload = buf[..size].to_vec();
                        packets.spawn(async move {
                            handler(PacketListenerReceive {
                                local_addr,
                                peer,
                                payload,
                                writer,
                            })
                            .await;
                        });
                    }
                    maybe_task = packets.join_next(), if !packets.is_empty() => {
                        if let Some(Err(err)) = maybe_task {
                            return Err(ProxyError::protocol_ctx(
                                "packet listener receive task join failed",
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
            Err(err) => Err(ProxyError::protocol_ctx(
                "packet listener task join failed",
                err,
            )),
        }
    }
}

struct UdpPacketWriter {
    socket: Arc<UdpSocket>,
}

impl PacketWriter for UdpPacketWriter {
    fn send_to(
        &self,
        peer: SocketAddr,
        payload: Vec<u8>,
    ) -> crate::portal::traits::BoxFuture<'_, ()> {
        Box::pin(async move {
            self.socket.send_to(&payload, peer).await?;
            Ok(())
        })
    }
}
