//! Tor hidden service utilities for iroh.
//!
//! This crate provides utilities for creating Tor hidden services that can be used
//! as a custom transport for iroh networking.

use std::{collections::HashMap, future::Future, sync::Arc};

use anyhow::{Context, Result, anyhow};
use bytes::Bytes;
use iroh::{
    EndpointId, SecretKey, TransportAddr,
    discovery::{Discovery, DiscoveryError, DiscoveryItem, EndpointData, EndpointInfo},
    endpoint::{
        Builder,
        presets::Preset,
        transports::{Addr, Transmit, UserSender, UserTransport, UserTransportFactory},
    },
};
use iroh_base::UserAddr;
use n0_future::{boxed::BoxFuture, stream};
use n0_watcher::Watchable;
#[cfg(test)]
use sha2::{Digest, Sha512};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
    sync::Mutex,
};
use tokio_socks::tcp::Socks5Stream;
use torut::onion::{OnionAddressV3, TorPublicKeyV3};
#[cfg(test)]
use torut::onion::TorSecretKeyV3;

/// Convert an iroh SecretKey to a Tor v3 secret key.
#[cfg(test)]
pub(crate) fn iroh_to_tor_secret_key(key: &SecretKey) -> TorSecretKeyV3 {
    let seed = key.to_bytes();
    let hash = Sha512::digest(seed);
    let mut expanded_bytes: [u8; 64] = hash.into();
    expanded_bytes[0] &= 248;
    expanded_bytes[31] &= 63;
    expanded_bytes[31] |= 64;
    TorSecretKeyV3::from(expanded_bytes)
}

/// Get the onion address for an iroh `EndpointId` (public key only).
fn onion_address_from_endpoint(endpoint: EndpointId) -> Result<OnionAddressV3> {
    let bytes = endpoint.as_bytes();
    let tor_public =
        TorPublicKeyV3::from_bytes(bytes).context("Invalid endpoint public key for Tor")?;
    Ok(tor_public.get_onion_address())
}

/// A packet carried over the Tor stream transport.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TorPacket {
    /// Source endpoint id (32 bytes).
    pub from: EndpointId,
    /// Raw packet payload.
    pub data: Bytes,
    /// Optional segment size hint for GRO; not a payload size limit.
    pub segment_size: Option<u16>,
}

const FLAG_SEGMENT_SIZE: u8 = 0x01;
/// Transport id for the Tor user transport.
const TOR_USER_TRANSPORT_ID: u64 = 0x544f52;

/// Build a user transport address for the Tor transport.
fn tor_user_addr(endpoint: EndpointId) -> UserAddr {
    UserAddr::from_parts(TOR_USER_TRANSPORT_ID, endpoint.as_bytes())
}

/// Discovery service that maps any `EndpointId` to its Tor user transport address.
#[derive(Debug, Clone)]
struct TorUserAddrDiscovery;

impl Discovery for TorUserAddrDiscovery {
    fn resolve(
        &self,
        endpoint_id: EndpointId,
    ) -> Option<n0_future::boxed::BoxStream<Result<DiscoveryItem, DiscoveryError>>> {
        let info = EndpointInfo {
            endpoint_id,
            data: EndpointData::new([TransportAddr::User(tor_user_addr(endpoint_id))]),
        };
        Some(Box::pin(stream::once(Ok(DiscoveryItem::new(
            info,
            "tor-user-addr",
            None,
        )))))
    }
}

fn parse_user_addr(addr: &UserAddr) -> Result<EndpointId> {
    if addr.id() != TOR_USER_TRANSPORT_ID {
        return Err(anyhow!("unexpected transport id"));
    }
    let data = addr.data();
    if data.len() != 32 {
        return Err(anyhow!("unexpected endpoint id length"));
    }
    let bytes: [u8; 32] = data.try_into().context("endpoint id bytes")?;
    EndpointId::from_bytes(&bytes).context("endpoint id parse")
}

/// Read a single packet from a stream. Returns `Ok(None)` on clean EOF.
pub(crate) async fn read_tor_packet<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<Option<TorPacket>> {
    let mut flags = [0u8; 1];
    let mut read = 0usize;
    while read < flags.len() {
        let n = reader
            .read(&mut flags[read..])
            .await
            .context("Failed to read packet flags")?;
        if n == 0 {
            return Ok(None);
        }
        read += n;
    }

    let mut from_bytes = [0u8; 32];
    reader
        .read_exact(&mut from_bytes)
        .await
        .context("Failed to read packet source")?;
    let from =
        EndpointId::from_bytes(&from_bytes).context("Failed to parse packet source EndpointId")?;

    let segment_size = if flags[0] & FLAG_SEGMENT_SIZE != 0 {
        let mut size_bytes = [0u8; 2];
        reader
            .read_exact(&mut size_bytes)
            .await
            .context("Failed to read segment size")?;
        Some(u16::from_be_bytes(size_bytes))
    } else {
        None
    };

    let mut len_bytes = [0u8; 4];
    reader
        .read_exact(&mut len_bytes)
        .await
        .context("Failed to read data length")?;
    let len = u32::from_be_bytes(len_bytes) as usize;

    let mut data = vec![0u8; len];
    reader
        .read_exact(&mut data)
        .await
        .context("Failed to read packet data")?;

    Ok(Some(TorPacket {
        from,
        data: Bytes::from(data),
        segment_size,
    }))
}

/// Write a single packet to a stream.
pub(crate) async fn write_tor_packet<W: AsyncWrite + Unpin>(
    writer: &mut W,
    packet: &TorPacket,
) -> Result<()> {
    let mut flags = 0u8;
    if packet.segment_size.is_some() {
        flags |= FLAG_SEGMENT_SIZE;
    }
    writer
        .write_all(&[flags])
        .await
        .context("Failed to write packet flags")?;
    writer
        .write_all(packet.from.as_bytes())
        .await
        .context("Failed to write packet source")?;
    if let Some(segment_size) = packet.segment_size {
        writer
            .write_all(&segment_size.to_be_bytes())
            .await
            .context("Failed to write segment size")?;
    }
    let len = u32::try_from(packet.data.len()).context("Packet too large to encode")?;
    writer
        .write_all(&len.to_be_bytes())
        .await
        .context("Failed to write data length")?;
    writer
        .write_all(&packet.data)
        .await
        .context("Failed to write packet data")?;
    writer.flush().await.context("Failed to flush packet")?;
    Ok(())
}

/// A service that reads framed packets from a stream and dispatches them to a channel.
#[derive(Clone)]
pub(crate) struct TorPacketService {
    sender: tokio::sync::mpsc::Sender<TorPacket>,
}

impl TorPacketService {
    /// Create a new service with the given handler.
    pub(crate) fn new(sender: tokio::sync::mpsc::Sender<TorPacket>) -> Self {
        Self { sender }
    }

    /// Handle packets on a single stream until EOF.
    pub(crate) async fn handle_stream(&self, mut stream: TcpStream) -> Result<()> {
        while let Some(packet) = read_tor_packet(&mut stream).await? {
            let _ = self.sender.send(packet).await;
        }
        Ok(())
    }
}

/// IO for Tor-backed streams.
pub(crate) struct TorStreamIo {
    accept: Box<dyn Fn() -> BoxFuture<Result<TcpStream>> + Send + Sync>,
    connect: Box<dyn Fn(EndpointId) -> BoxFuture<Result<TcpStream>> + Send + Sync>,
}

impl TorStreamIo {
    /// Create a new IO wrapper from accept/connect functions.
    pub(crate) fn new<Accept, Connect, AcceptFut, ConnectFut>(accept: Accept, connect: Connect) -> Self
    where
        Accept: Fn() -> AcceptFut + Send + Sync + 'static,
        AcceptFut: Future<Output = Result<TcpStream>> + Send + 'static,
        Connect: Fn(EndpointId) -> ConnectFut + Send + Sync + 'static,
        ConnectFut: Future<Output = Result<TcpStream>> + Send + 'static,
    {
        Self {
            accept: Box::new(move || Box::pin(accept())),
            connect: Box::new(move |endpoint| Box::pin(connect(endpoint))),
        }
    }

    /// Connect to the remote endpoint's stream transport.
    fn connect(&self, endpoint: EndpointId) -> BoxFuture<Result<TcpStream>> {
        (self.connect)(endpoint)
    }

    /// Accept the next incoming stream.
    fn accept(&self) -> BoxFuture<Result<TcpStream>> {
        (self.accept)()
    }
}

/// Packet writer that reuses per-endpoint streams.
pub(crate) struct TorPacketSender {
    io: Arc<TorStreamIo>,
    streams: Mutex<HashMap<EndpointId, Arc<Mutex<TcpStream>>>>,
}

impl TorPacketSender {
    /// Create a new sender with the provided connector.
    pub(crate) fn new(io: Arc<TorStreamIo>) -> Self {
        Self {
            io,
            streams: Mutex::new(HashMap::new()),
        }
    }

    /// Send a packet to the given endpoint, reusing an existing stream when available.
    pub(crate) async fn send(&self, to: EndpointId, packet: &TorPacket) -> Result<()> {
        let stream = self.get_or_connect(to).await?;
        let mut guard = stream.lock().await;
        match write_tor_packet(&mut *guard, packet).await {
            Ok(()) => Ok(()),
            Err(err) => {
                drop(guard);
                self.streams.lock().await.remove(&to);
                Err(err)
            }
        }
    }

    async fn get_or_connect(&self, to: EndpointId) -> Result<Arc<Mutex<TcpStream>>> {
        if let Some(existing) = self.streams.lock().await.get(&to).cloned() {
            return Ok(existing);
        }

        let stream = self.io.connect(to).await?;
        let stream = Arc::new(Mutex::new(stream));

        let mut guard = self.streams.lock().await;
        Ok(guard.entry(to).or_insert_with(|| stream.clone()).clone())
    }

    /// Close and remove a cached stream for the given endpoint.
    #[allow(dead_code)]
    pub(crate) async fn close(&self, to: EndpointId) -> Result<()> {
        let stream = self.streams.lock().await.remove(&to);
        if let Some(stream) = stream {
            let mut guard = stream.lock().await;
            guard
                .shutdown()
                .await
                .context("Failed to shutdown stream")?;
        }
        Ok(())
    }

    /// Close and remove all cached streams.
    #[allow(dead_code)]
    pub(crate) async fn close_all(&self) -> Result<()> {
        let streams: Vec<_> = self.streams.lock().await.drain().map(|(_, v)| v).collect();
        for stream in streams {
            let mut guard = stream.lock().await;
            guard
                .shutdown()
                .await
                .context("Failed to shutdown stream")?;
        }
        Ok(())
    }
}

const DEFAULT_RECV_CAPACITY: usize = 64 * 1024;
const DEFAULT_SOCKS_PORT: u16 = 9050;
const DEFAULT_ONION_PORT: u16 = 9999;

/// Builder for [`TorUserTransport`].
pub struct TorUserTransportBuilder {
    secret_key: SecretKey,
    socks_port: u16,
    onion_port: u16,
    recv_capacity: usize,
    #[cfg(test)]
    io: Option<Arc<TorStreamIo>>,
    listener: Option<Arc<tokio::net::TcpListener>>,
}

impl TorUserTransportBuilder {
    /// Set the SOCKS5 proxy port (default: 9050).
    pub fn socks_port(mut self, port: u16) -> Self {
        self.socks_port = port;
        self
    }

    /// Set the onion service port (default: 9999).
    pub fn onion_port(mut self, port: u16) -> Self {
        self.onion_port = port;
        self
    }

    /// Set the receive buffer capacity (default: 64KB).
    pub fn recv_capacity(mut self, capacity: usize) -> Self {
        self.recv_capacity = capacity;
        self
    }

    /// Provide a pre-bound TCP listener instead of binding one automatically.
    pub fn listener(mut self, listener: tokio::net::TcpListener) -> Self {
        self.listener = Some(Arc::new(listener));
        self
    }

    /// Override with custom IO (for testing with local TCP instead of Tor).
    #[cfg(test)]
    pub(crate) fn io(mut self, io: Arc<TorStreamIo>) -> Self {
        self.io = Some(io);
        self
    }

    /// Build the transport.
    ///
    /// This creates an inert transport factory that holds the configuration.
    /// The actual transport instance is created when `bind()` is called.
    pub async fn build(self) -> TorUserTransport {
        let local_id = self.secret_key.public();

        #[cfg(test)]
        if let Some(io) = self.io {
            return TorUserTransport {
                local_id,
                io,
                recv_capacity: self.recv_capacity,
            };
        }

        let listener = match self.listener {
            Some(l) => l,
            None => {
                let l = tokio::net::TcpListener::bind("127.0.0.1:0")
                    .await
                    .expect("failed to bind listener");
                Arc::new(l)
            }
        };
        let socks_addr: std::net::SocketAddr =
            format!("127.0.0.1:{}", self.socks_port).parse().unwrap();
        let onion_port = self.onion_port;
        let io = Arc::new(TorStreamIo::new(
            move || {
                let listener = listener.clone();
                async move {
                    let (stream, _) = listener.accept().await?;
                    Ok(stream)
                }
            },
            move |endpoint| async move {
                let onion = onion_address_from_endpoint(endpoint)?;
                let onion_addr = format!("{}.onion", onion.get_address_without_dot_onion());
                let stream =
                    Socks5Stream::connect(socks_addr, (onion_addr.as_str(), onion_port)).await?;
                Ok(stream.into_inner())
            },
        ));

        TorUserTransport {
            local_id,
            io,
            recv_capacity: self.recv_capacity,
        }
    }
}

/// A Tor-backed user transport factory for iroh.
///
/// This holds the configuration and IO for the Tor transport. The actual
/// transport instance is created when iroh calls `bind()` during endpoint setup.
///
/// Use `TorUserTransport::builder()` to create and configure.
///
/// # Example
///
/// ```ignore
/// let transport = TorUserTransport::builder(secret_key).build().await;
///
/// Endpoint::builder()
///     .secret_key(secret_key)
///     .preset(transport.preset())
///     .bind()
///     .await?
/// ```
pub struct TorUserTransport {
    local_id: EndpointId,
    io: Arc<TorStreamIo>,
    recv_capacity: usize,
}

impl TorUserTransport {
    /// Create a builder for configuring a Tor user transport.
    ///
    /// # Arguments
    ///
    /// * `secret_key` - The iroh secret key for this endpoint
    pub fn builder(secret_key: SecretKey) -> TorUserTransportBuilder {
        TorUserTransportBuilder {
            secret_key,
            socks_port: DEFAULT_SOCKS_PORT,
            onion_port: DEFAULT_ONION_PORT,
            recv_capacity: DEFAULT_RECV_CAPACITY,
            #[cfg(test)]
            io: None,
            listener: None,
        }
    }

    /// Returns a discovery service for this transport.
    ///
    /// The discovery service maps any `EndpointId` to its Tor user transport address.
    pub fn discovery(&self) -> impl Discovery {
        TorUserAddrDiscovery
    }

    /// Returns a preset that configures an endpoint to use this Tor transport.
    ///
    /// The preset adds the Tor user transport factory and discovery service.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let transport = TorUserTransport::builder(sk.clone()).build().await;
    ///
    /// Endpoint::builder()
    ///     .secret_key(sk)
    ///     .preset(transport.preset())
    ///     .bind()
    ///     .await?
    /// ```
    pub fn preset(self) -> impl Preset {
        TorPreset {
            factory: Arc::new(self),
        }
    }
}

impl std::fmt::Debug for TorUserTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TorUserTransport")
            .field("local_id", &self.local_id)
            .finish()
    }
}

impl UserTransportFactory for TorUserTransport {
    fn bind(&self) -> std::io::Result<Box<dyn UserTransport>> {
        let (tx, rx) = tokio::sync::mpsc::channel(self.recv_capacity);
        let service = TorPacketService::new(tx);
        let sender = Arc::new(TorPacketSender::new(self.io.clone()));
        let watchable = Watchable::new(vec![tor_user_addr(self.local_id)]);

        let io = self.io.clone();
        tokio::spawn(async move {
            loop {
                match io.accept().await {
                    Ok(stream) => {
                        let service = service.clone();
                        tokio::spawn(async move {
                            let _ = service.handle_stream(stream).await;
                        });
                    }
                    Err(err) => {
                        tracing::warn!("Tor accept loop stopped: {err:#}");
                        break;
                    }
                }
            }
        });

        Ok(Box::new(TorUserTransportInstance {
            local_id: self.local_id,
            watchable,
            receiver: rx,
            sender,
        }))
    }
}

/// Internal preset for configuring an iroh endpoint to use the Tor transport.
struct TorPreset {
    factory: Arc<dyn UserTransportFactory>,
}

impl Preset for TorPreset {
    fn apply(self, builder: Builder) -> Builder {
        builder
            .add_user_transport(self.factory)
            .discovery(TorUserAddrDiscovery)
    }
}

/// Active Tor transport instance created by [`TorUserTransport::bind()`].
///
/// This is the actual transport that handles sending and receiving packets.
struct TorUserTransportInstance {
    local_id: EndpointId,
    watchable: Watchable<Vec<UserAddr>>,
    receiver: tokio::sync::mpsc::Receiver<TorPacket>,
    sender: Arc<TorPacketSender>,
}

impl std::fmt::Debug for TorUserTransportInstance {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TorUserTransportInstance")
            .field("local_id", &self.local_id)
            .finish()
    }
}

struct TorUserSender {
    local_id: EndpointId,
    sender: Arc<TorPacketSender>,
}

impl std::fmt::Debug for TorUserSender {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TorUserSender")
            .field("local_id", &self.local_id)
            .finish()
    }
}

impl UserSender for TorUserSender {
    fn is_valid_send_addr(&self, addr: &UserAddr) -> bool {
        addr.id() == TOR_USER_TRANSPORT_ID && addr.data().len() == 32
    }

    fn poll_send(
        &self,
        _cx: &mut std::task::Context,
        dst: UserAddr,
        transmit: &Transmit<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let to = parse_user_addr(&dst).map_err(std::io::Error::other)?;
        let segment_size = transmit
            .segment_size
            .map(|size| {
                u16::try_from(size).map_err(|_| std::io::Error::other("segment size too large"))
            })
            .transpose()?;
        let chunk_size = segment_size
            .map(|s| s as usize)
            .unwrap_or(transmit.contents.len().max(1));

        for chunk in transmit.contents.chunks(chunk_size) {
            let packet = TorPacket {
                from: self.local_id,
                data: Bytes::copy_from_slice(chunk),
                segment_size,
            };
            let sender = self.sender.clone();
            tokio::spawn(async move {
                let _ = sender.send(to, &packet).await;
            });
        }

        std::task::Poll::Ready(Ok(()))
    }
}

impl UserTransport for TorUserTransportInstance {
    fn watch_local_addrs(&self) -> n0_watcher::Direct<Vec<UserAddr>> {
        self.watchable.watch()
    }

    fn create_sender(&self) -> Arc<dyn UserSender> {
        Arc::new(TorUserSender {
            local_id: self.local_id,
            sender: self.sender.clone(),
        })
    }

    fn poll_recv(
        &mut self,
        cx: &mut std::task::Context,
        bufs: &mut [std::io::IoSliceMut<'_>],
        metas: &mut [quinn_udp::RecvMeta],
        source_addrs: &mut [Addr],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let n = bufs.len().min(metas.len()).min(source_addrs.len());
        if n == 0 {
            return std::task::Poll::Ready(Ok(0));
        }

        let mut filled = 0usize;
        while filled < n {
            match self.receiver.poll_recv(cx) {
                std::task::Poll::Pending => {
                    if filled == 0 {
                        return std::task::Poll::Pending;
                    }
                    break;
                }
                std::task::Poll::Ready(None) => {
                    return std::task::Poll::Ready(Err(std::io::Error::other(
                        "packet channel closed",
                    )));
                }
                std::task::Poll::Ready(Some(packet)) => {
                    if bufs[filled].len() < packet.data.len() {
                        continue;
                    }
                    bufs[filled][..packet.data.len()].copy_from_slice(&packet.data);
                    metas[filled].len = packet.data.len();
                    metas[filled].stride = packet
                        .segment_size
                        .map(|s| s as usize)
                        .unwrap_or(packet.data.len());
                    source_addrs[filled] = Addr::User(tor_user_addr(packet.from));
                    filled += 1;
                }
            }
        }

        if filled > 0 {
            std::task::Poll::Ready(Ok(filled))
        } else {
            std::task::Poll::Pending
        }
    }
}

#[cfg(test)]
mod tests;
