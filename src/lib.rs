//! Tor hidden service utilities for iroh.
//!
//! This crate provides utilities for creating Tor hidden services that can be used
//! as a custom transport for iroh networking.

use std::{
    collections::HashMap,
    future::Future,
    pin::Pin,
    str::FromStr,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, anyhow};
use bytes::Bytes;
use iroh::{
    EndpointId, SecretKey, TransportAddr,
    discovery::{Discovery, DiscoveryError, DiscoveryItem, EndpointData, EndpointInfo},
    endpoint::transports::{Addr, Transmit, UserSender, UserTransport, UserTransportFactory},
};
use iroh_base::UserAddr;
use n0_future::{boxed::BoxFuture, stream};
use n0_watcher::Watchable;
use sha2::{Digest, Sha512};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::{net::TcpStream, sync::Mutex, time::sleep};
// Re-export TorSecretKeyV3 for users who want to use native Tor keys
pub use torut::onion::TorSecretKeyV3;
use torut::{
    control::{AuthenticatedConn, ConnError, UnauthenticatedConn},
    onion::{OnionAddressV3, TorPublicKeyV3},
};

/// Default Tor control port
pub const DEFAULT_CONTROL_PORT: u16 = 9051;

/// Default Tor SOCKS5 proxy port
pub const DEFAULT_SOCKS_PORT: u16 = 9050;

/// Convert an iroh SecretKey to a Tor v3 secret key.
///
/// Iroh uses standard Ed25519 32-byte secret keys (seeds), while Tor uses
/// 64-byte "expanded" secret keys. This function performs the expansion
/// using SHA-512 as specified in RFC 8032.
///
/// Note: torut uses ed25519-dalek 1.x internally. We generate the expanded
/// key format that torut expects by using its internal ed25519-dalek types.
pub fn iroh_to_tor_secret_key(key: &SecretKey) -> TorSecretKeyV3 {
    // Get the 32-byte seed from iroh's SecretKey
    let seed = key.to_bytes();

    // Use SHA-512 expansion and Ed25519 clamping for the scalar.
    // Tor expects an expanded secret key (scalar + nonce) in ed25519-dalek 1.x format.
    let hash = Sha512::digest(seed);
    let mut expanded_bytes: [u8; 64] = hash.into();
    // Clamp per RFC 8032.
    expanded_bytes[0] &= 248;
    expanded_bytes[31] &= 63;
    expanded_bytes[31] |= 64;

    // TorSecretKeyV3::from expects a 64-byte array
    TorSecretKeyV3::from(expanded_bytes)
}

/// Generate a new Tor secret key using torut's native key generation.
/// This is useful for testing that the basic mechanism works.
pub fn generate_tor_key() -> TorSecretKeyV3 {
    TorSecretKeyV3::generate()
}

/// Get the onion address for an iroh `EndpointId` (public key only).
pub fn onion_address_from_endpoint(endpoint: EndpointId) -> Result<OnionAddressV3> {
    let bytes = endpoint.as_bytes();
    let tor_public =
        TorPublicKeyV3::from_bytes(bytes).context("Invalid endpoint public key for Tor")?;
    Ok(tor_public.get_onion_address())
}

/// Type alias for the async event handler function.
type EventHandler = Box<
    dyn Fn(
            torut::control::AsyncEvent<'static>,
        ) -> Pin<Box<dyn Future<Output = Result<(), ConnError>> + Send>>
        + Send
        + Sync,
>;

/// A connection to the Tor control port.
pub struct TorControl {
    conn: AuthenticatedConn<TcpStream, EventHandler>,
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
pub fn tor_user_addr(endpoint: EndpointId) -> UserAddr {
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

/// Connector for establishing Tor-backed streams keyed by endpoint id.
/// IO for Tor-backed streams.
pub struct TorStreamIo {
    accept: Box<dyn Fn() -> BoxFuture<Result<TcpStream>> + Send + Sync>,
    connect: Box<dyn Fn(EndpointId) -> BoxFuture<Result<TcpStream>> + Send + Sync>,
}

impl TorStreamIo {
    /// Create a new IO wrapper from accept/connect functions.
    pub fn new<Accept, Connect, AcceptFut, ConnectFut>(accept: Accept, connect: Connect) -> Self
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
    pub fn connect(&self, endpoint: EndpointId) -> BoxFuture<Result<TcpStream>> {
        (self.connect)(endpoint)
    }

    /// Accept the next incoming stream.
    pub fn accept(&self) -> BoxFuture<Result<TcpStream>> {
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

/// Builder for [`TorUserTransport`].
pub struct TorUserTransportBuilder {
    local_id: EndpointId,
    io: Arc<TorStreamIo>,
    recv_capacity: usize,
}

impl TorUserTransportBuilder {
    /// Build the transport.
    ///
    /// This spawns a background task to accept incoming Tor streams.
    pub fn build(self) -> TorUserTransport {
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

        TorUserTransport {
            local_id: self.local_id,
            io: self.io,
            watchable,
            receiver: rx,
            sender,
        }
    }
}

/// A Tor-backed user transport for iroh.
///
/// Use `TorUserTransport::builder()` to create and configure.
///
/// # Example
///
/// ```ignore
/// let transport = TorUserTransport::builder(endpoint_id, io).build();
///
/// Endpoint::builder()
///     .add_user_transport(transport.factory())
///     .discovery(transport.discovery())
///     // ...
/// ```
pub struct TorUserTransport {
    local_id: EndpointId,
    io: Arc<TorStreamIo>,
    watchable: Watchable<Vec<UserAddr>>,
    receiver: tokio::sync::mpsc::Receiver<TorPacket>,
    sender: Arc<TorPacketSender>,
}

impl TorUserTransport {
    /// Create a builder for configuring a Tor user transport.
    pub fn builder(local_id: EndpointId, io: Arc<TorStreamIo>) -> TorUserTransportBuilder {
        TorUserTransportBuilder {
            local_id,
            io,
            recv_capacity: DEFAULT_RECV_CAPACITY,
        }
    }

    /// Returns a factory for use with iroh's `add_user_transport`.
    pub fn factory(&self) -> Arc<dyn UserTransportFactory> {
        Arc::new(TorUserTransportFactory {
            local_id: self.local_id,
            io: self.io.clone(),
        })
    }

    /// Returns a discovery service for this transport.
    ///
    /// The discovery service maps any `EndpointId` to its Tor user transport address.
    pub fn discovery(&self) -> impl Discovery {
        TorUserAddrDiscovery
    }
}

impl std::fmt::Debug for TorUserTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TorUserTransport")
            .field("local_id", &self.local_id)
            .finish()
    }
}

/// Internal factory implementation.
#[derive(Clone)]
struct TorUserTransportFactory {
    local_id: EndpointId,
    io: Arc<TorStreamIo>,
}

impl std::fmt::Debug for TorUserTransportFactory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TorUserTransportFactory")
            .field("local_id", &self.local_id)
            .finish()
    }
}

impl UserTransportFactory for TorUserTransportFactory {
    fn bind(&self) -> std::io::Result<Box<dyn UserTransport>> {
        Ok(Box::new(
            TorUserTransport::builder(self.local_id, self.io.clone()).build(),
        ))
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

impl UserTransport for TorUserTransport {
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

impl TorControl {
    /// Connect to the Tor control port and authenticate.
    pub async fn connect(addr: &str) -> Result<Self> {
        let stream = TcpStream::connect(addr)
            .await
            .context("Failed to connect to Tor control port")?;

        let mut conn = UnauthenticatedConn::new(stream);

        // Get authentication info
        let auth_data = conn
            .load_protocol_info()
            .await
            .context("Failed to load protocol info")?;

        // Try to authenticate (cookie auth or null auth)
        let auth_method = auth_data
            .make_auth_data()
            .context("Failed to determine auth method")?;

        if let Some(auth) = auth_method {
            conn.authenticate(&auth)
                .await
                .context("Failed to authenticate")?;
        }

        let conn: AuthenticatedConn<TcpStream, EventHandler> = conn.into_authenticated().await;

        Ok(Self { conn })
    }

    /// Create or reuse a hidden service using the given secret key.
    ///
    /// The hidden service will forward connections from `onion_port` to `local_addr`.
    ///
    /// Returns a tuple of (onion_address, already_existed). If `already_existed` is true,
    /// the service was already registered with Tor (likely from a previous run with
    /// deterministic keys), meaning the descriptor is probably already published and
    /// connections should be fast.
    ///
    /// Note: If the service is reused, the port mapping from the original creation
    /// is kept. The `onion_port` and `local_addr` parameters are only used for new services.
    pub async fn create_hidden_service(
        &mut self,
        key: &SecretKey,
        onion_port: u16,
        local_addr: std::net::SocketAddr,
    ) -> Result<(OnionAddressV3, bool)> {
        let tor_key = iroh_to_tor_secret_key(key);
        self.create_hidden_service_with_tor_key(&tor_key, onion_port, local_addr)
            .await
    }

    /// Create or reuse a hidden service using a native Tor secret key.
    /// This is useful for testing or when you have a TorSecretKeyV3 directly.
    pub async fn create_hidden_service_with_tor_key(
        &mut self,
        tor_key: &TorSecretKeyV3,
        onion_port: u16,
        local_addr: std::net::SocketAddr,
    ) -> Result<(OnionAddressV3, bool)> {
        let onion_addr = tor_key.public().get_onion_address();

        println!(
            "DEBUG: Creating hidden service {} -> {}:{}",
            onion_addr.get_address_without_dot_onion(),
            local_addr,
            onion_port
        );

        let listeners = [(onion_port, local_addr)];
        match self
            .conn
            .add_onion_v3(
                tor_key,
                false, // detach: false means the service will be removed when we disconnect
                false, // non_anonymous: false for full anonymity
                false, // max_streams_close_circuit
                None,  // max_num_streams
                &mut listeners.iter(),
            )
            .await
        {
            Ok(()) => {
                println!("DEBUG: add_onion_v3 returned Ok");
                Ok((onion_addr, false))
            }
            Err(e) => {
                println!("DEBUG: add_onion_v3 returned Err: {:?}", e);
                // Check if this is a "key collision" error (service already exists)
                // torut returns InvalidResponseCode(552) for this case
                if matches!(e, ConnError::InvalidResponseCode(552)) {
                    tracing::info!(
                        "Hidden service {} already exists, reusing it",
                        onion_addr.get_address_without_dot_onion()
                    );
                    Ok((onion_addr, true))
                } else {
                    Err(e).context("Failed to create hidden service")
                }
            }
        }
    }

    /// Wait for hidden service descriptor to be published.
    ///
    /// This is a simple delay-based approach. Tor doesn't provide a reliable way
    /// to query publication status via GETINFO, and torut has a bug that prevents
    /// subscribing to HS_DESC events (it rejects underscores in event names).
    ///
    /// For new services, we wait a fixed amount of time. For production use,
    /// consider using retry logic when connecting instead.
    pub async fn wait_for_publication(
        &mut self,
        _onion_addr: &OnionAddressV3,
        _timeout: Duration,
    ) -> Result<()> {
        // Just wait a fixed delay for the descriptor to propagate.
        // The actual time needed varies (30s-120s for first publish, faster with cached keys).
        // Connection retry logic should handle cases where this isn't enough.
        println!("Waiting 30s for descriptor to propagate to HSDir nodes...");
        tokio::time::sleep(Duration::from_secs(30)).await;
        Ok(())
    }

    /// Remove a hidden service by its onion address.
    pub async fn remove_hidden_service(&mut self, addr: &OnionAddressV3) -> Result<()> {
        // The service_id is the onion address without the .onion suffix
        let service_id = addr.get_address_without_dot_onion();
        self.conn
            .del_onion(&service_id)
            .await
            .context("Failed to remove hidden service")?;
        Ok(())
    }

    /// List hidden services owned by the current control connection.
    ///
    /// This uses the Tor control command `GETINFO onions/current`, which only
    /// returns services created on this connection and not detached services.
    pub async fn list_hidden_services(&mut self) -> Result<Vec<OnionAddressV3>> {
        let response = self.list_hidden_services_raw().await?;

        let mut services = Vec::new();
        for line in response.lines().map(str::trim).filter(|l| !l.is_empty()) {
            let addr = OnionAddressV3::from_str(line)
                .with_context(|| format!("Invalid onion address from Tor: {}", line))?;
            services.push(addr);
        }

        Ok(services)
    }

    /// Return the raw `GETINFO onions/current` response.
    pub async fn list_hidden_services_raw(&mut self) -> Result<String> {
        self.conn
            .get_info_unquote("onions/current")
            .await
            .context("Failed to query onions/current")
    }

    /// Wait until the hidden service shows up in Tor's list for this control connection.
    ///
    /// Returns true if the service appears before timeout, false otherwise.
    pub async fn wait_for_hidden_service(
        &mut self,
        addr: &OnionAddressV3,
        timeout: Duration,
        poll_interval: Duration,
    ) -> Result<bool> {
        let deadline = Instant::now() + timeout;
        loop {
            let services = self.list_hidden_services().await?;
            if services.iter().any(|service| service == addr) {
                return Ok(true);
            }
            if Instant::now() >= deadline {
                return Ok(false);
            }
            sleep(poll_interval).await;
        }
    }
}

#[cfg(test)]
mod tests;
