//! Integration test: Tor hidden service echo test using a native Tor key.
//!
//! This test requires a running Tor daemon with the control port enabled.
//! Run: `tor --ControlPort 9051 --CookieAuthentication 0`

use std::{io, net::SocketAddr, sync::Once, time::Duration};

use anyhow::{Context, Result};
use iroh::SecretKey;
use sha2::{Digest, Sha512};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::{Instant, timeout},
};
use tokio_socks::tcp::Socks5Stream;
use torut::{
    control::{AuthenticatedConn, ConnError, UnauthenticatedConn},
    onion::{OnionAddressV3, TorSecretKeyV3},
};
use tracing::{error, info, warn};

/// Convert an iroh SecretKey to a Tor v3 secret key.
fn iroh_to_tor_secret_key(key: &SecretKey) -> TorSecretKeyV3 {
    let seed = key.to_bytes();
    let hash = Sha512::digest(seed);
    let mut expanded_bytes: [u8; 64] = hash.into();
    expanded_bytes[0] &= 248;
    expanded_bytes[31] &= 63;
    expanded_bytes[31] |= 64;
    TorSecretKeyV3::from(expanded_bytes)
}

type EventHandler = Box<
    dyn Fn(
            torut::control::AsyncEvent<'static>,
        )
            -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), ConnError>> + Send>>
        + Send
        + Sync,
>;

struct TorControl {
    conn: AuthenticatedConn<TcpStream, EventHandler>,
}

impl TorControl {
    async fn connect(addr: &str) -> Result<Self> {
        let stream = TcpStream::connect(addr)
            .await
            .context("Failed to connect to Tor control port")?;
        let mut conn = UnauthenticatedConn::new(stream);
        let auth_data = conn
            .load_protocol_info()
            .await
            .context("Failed to load protocol info")?;
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

    async fn create_hidden_service_with_tor_key(
        &mut self,
        tor_key: &TorSecretKeyV3,
        onion_port: u16,
        local_addr: SocketAddr,
    ) -> Result<(OnionAddressV3, bool)> {
        let onion_addr = tor_key.public().get_onion_address();
        let listeners = [(onion_port, local_addr)];
        match self
            .conn
            .add_onion_v3(tor_key, false, false, false, None, &mut listeners.iter())
            .await
        {
            Ok(()) => Ok((onion_addr, false)),
            Err(ConnError::InvalidResponseCode(552)) => Ok((onion_addr, true)),
            Err(e) => Err(e).context("Failed to create hidden service"),
        }
    }

    async fn list_hidden_services(&mut self) -> Result<Vec<OnionAddressV3>> {
        let response = self
            .conn
            .get_info_unquote("onions/current")
            .await
            .context("Failed to query onions/current")?;
        let mut services = Vec::new();
        for line in response.lines().map(str::trim).filter(|l| !l.is_empty()) {
            let addr = std::str::FromStr::from_str(line)
                .with_context(|| format!("Invalid onion address from Tor: {}", line))?;
            services.push(addr);
        }
        Ok(services)
    }

    async fn wait_for_hidden_service(
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
            tokio::time::sleep(poll_interval).await;
        }
    }
}

const TEST_MESSAGE: &[u8] = b"Hello from Tor hidden service!";
const HIDDEN_SERVICE_PORT: u16 = 9999;

fn init_tracing() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .try_init()
            .ok();
    });
}

async fn connect_tor_control() -> Result<TorControl> {
    TorControl::connect("127.0.0.1:9051").await.context(
        "Tor control port unavailable. Start Tor with ControlPort 9051 enabled and try again.",
    )
}

/// Connect to a .onion address through the Tor SOCKS5 proxy with retries.
async fn connect_via_tor(onion_addr: &str, port: u16, timeout_dur: Duration) -> Result<TcpStream> {
    let socks_addr: SocketAddr = "127.0.0.1:9050".parse()?;
    let target = (onion_addr, port);

    // Retry logic - hidden services can take time to become reachable
    // First-time publish can take 60-120 seconds; subsequent runs are faster
    let deadline = Instant::now() + timeout_dur;
    let mut last_error = None;
    let mut attempt = 0usize;

    while Instant::now() < deadline {
        attempt += 1;
        let remaining = deadline.saturating_duration_since(Instant::now());
        info!(
            "  Connection attempt {} ({}s remaining)...",
            attempt,
            remaining.as_secs()
        );
        match tokio::time::timeout(
            Duration::from_secs(30),
            Socks5Stream::connect(socks_addr, target),
        )
        .await
        {
            Ok(Ok(stream)) => return Ok(stream.into_inner()),
            Ok(Err(e)) => {
                warn!("  Attempt {} failed: {}", attempt, e);
                last_error = Some(e);
            }
            Err(e) => {
                warn!("  Attempt {} timed out: {}", attempt, e);
                let timeout_err =
                    io::Error::new(io::ErrorKind::TimedOut, "SOCKS connect timed out");
                last_error = Some(tokio_socks::Error::from(timeout_err));
            }
        }
        if last_error.is_some() {
            // Wait before retrying - the service might still be propagating
            let backoff = 3u64.saturating_mul(2u64.saturating_pow((attempt - 1) as u32));
            let sleep_for = Duration::from_secs(backoff.min(15));
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining > Duration::from_secs(1) {
                tokio::time::sleep(sleep_for.min(remaining)).await;
            }
        }
    }

    Err(last_error.unwrap()).with_context(|| {
        format!(
            "Failed to connect through SOCKS5 proxy after {} attempts",
            attempt
        )
    })
}

/// Run an echo server that echoes back whatever it receives.
async fn run_echo_server(listener: TcpListener) -> Result<()> {
    let (mut socket, _addr) = listener.accept().await?;
    let mut buf = vec![0u8; 1024];

    loop {
        let n = socket.read(&mut buf).await?;
        info!("Received {} bytes", n);
        if n == 0 {
            break;
        }
        socket.write_all(&buf[..n]).await?;
    }

    Ok(())
}

async fn run_echo_server_n(listener: TcpListener, max_connections: usize) -> Result<()> {
    for _ in 0..max_connections {
        let (mut socket, _addr) = listener.accept().await?;
        let mut buf = vec![0u8; 1024];

        loop {
            let n = socket.read(&mut buf).await?;
            info!("Received {} bytes", n);
            if n == 0 {
                break;
            }
            socket.write_all(&buf[..n]).await?;
        }
    }

    Ok(())
}

async fn run_hidden_service_echo(tor_key: &TorSecretKeyV3, label: &str) -> Result<()> {
    init_tracing();

    let onion_addr = tor_key.public().get_onion_address();
    info!("Generated onion ({}): {}", label, onion_addr);

    // Bind local TCP listener
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let local_addr: SocketAddr = listener.local_addr()?;
    info!("Listening on: {}", local_addr);

    // Connect to Tor and list existing services before creating a new one
    let mut tor_control = connect_tor_control().await?;
    let existing_services = tor_control.list_hidden_services().await?;
    info!("Existing services before create: {:?}", existing_services);

    let (created_addr, existed) = tor_control
        .create_hidden_service_with_tor_key(tor_key, HIDDEN_SERVICE_PORT, local_addr)
        .await?;

    info!(
        "Hidden service {}: {}.onion:{}",
        if existed { "reused" } else { "created" },
        created_addr.get_address_without_dot_onion(),
        HIDDEN_SERVICE_PORT
    );

    // Wait adaptively: poll Tor for the new service to appear on this connection.
    info!("Waiting for hidden service to appear in control connection list...");
    let found = tor_control
        .wait_for_hidden_service(
            &created_addr,
            Duration::from_secs(60),
            Duration::from_secs(2),
        )
        .await?;
    if !found {
        warn!(
            "Hidden service did not appear in control list within {}s: {}.onion",
            60,
            created_addr.get_address_without_dot_onion()
        );
    }

    // Spawn echo server
    let server_handle = tokio::spawn(async move {
        if let Err(e) = run_echo_server(listener).await {
            error!("Echo server error: {}", e);
        }
    });

    // Try to connect
    let onion_addr_str = format!("{}.onion", created_addr.get_address_without_dot_onion());
    info!(
        "Connecting to {}:{}...",
        onion_addr_str, HIDDEN_SERVICE_PORT
    );

    let mut stream = connect_via_tor(
        &onion_addr_str,
        HIDDEN_SERVICE_PORT,
        Duration::from_secs(240),
    )
    .await
    .context("Failed to connect")?;

    info!("Connected! Sending message...");
    timeout(Duration::from_secs(10), stream.write_all(TEST_MESSAGE))
        .await
        .context("Write timed out")??;

    let mut response = vec![0u8; TEST_MESSAGE.len()];
    timeout(Duration::from_secs(30), stream.read_exact(&mut response))
        .await
        .context("Read timed out")??;

    assert_eq!(&response, TEST_MESSAGE);
    info!("Echo test with {} PASSED!", label);

    // List services before dropping the control connection.
    let services = tor_control.list_hidden_services().await?;
    info!("Active services on this control connection:");
    for service in services {
        info!("  {}.onion", service.get_address_without_dot_onion());
    }

    drop(stream);
    server_handle.abort();
    Ok(())
}

/// Simple test using torut's native key generation to verify the mechanism works.
#[tokio::test]
#[ignore]
async fn test_native_tor_key() -> Result<()> {
    let tor_key = TorSecretKeyV3::generate();
    run_hidden_service_echo(&tor_key, "native tor key").await
}

/// Test using an iroh key converted to a Tor keypair.
#[tokio::test]
#[ignore]
async fn test_iroh_key_converted_to_tor() -> Result<()> {
    let iroh_key = SecretKey::generate(&mut rand::rng());
    let tor_key = iroh_to_tor_secret_key(&iroh_key);
    run_hidden_service_echo(&tor_key, "iroh->tor key").await
}

#[tokio::test]
#[ignore]
async fn test_echo_latency_10x_single_service() -> Result<()> {
    init_tracing();

    let tor_key = TorSecretKeyV3::generate();
    let onion_addr = tor_key.public().get_onion_address();
    info!("Generated onion (latency test): {}", onion_addr);

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let local_addr: SocketAddr = listener.local_addr()?;
    info!("Listening on: {}", local_addr);

    let mut tor_control = connect_tor_control().await?;
    let existing_services = tor_control.list_hidden_services().await?;
    info!("Existing services before create: {:?}", existing_services);

    let (created_addr, existed) = tor_control
        .create_hidden_service_with_tor_key(&tor_key, HIDDEN_SERVICE_PORT, local_addr)
        .await?;

    info!(
        "Hidden service {}: {}.onion:{}",
        if existed { "reused" } else { "created" },
        created_addr.get_address_without_dot_onion(),
        HIDDEN_SERVICE_PORT
    );

    info!("Waiting for hidden service to appear in control connection list...");
    let found = tor_control
        .wait_for_hidden_service(
            &created_addr,
            Duration::from_secs(60),
            Duration::from_secs(2),
        )
        .await?;
    if !found {
        warn!(
            "Hidden service did not appear in control list within {}s: {}.onion",
            60,
            created_addr.get_address_without_dot_onion()
        );
    }

    let server_handle = tokio::spawn(async move {
        if let Err(e) = run_echo_server_n(listener, 10).await {
            error!("Echo server error: {}", e);
        }
    });

    let onion_addr_str = format!("{}.onion", created_addr.get_address_without_dot_onion());
    let mut samples = Vec::with_capacity(10);
    for i in 0..10 {
        info!("Latency attempt {}/10", i + 1);
        let mut stream = connect_via_tor(
            &onion_addr_str,
            HIDDEN_SERVICE_PORT,
            Duration::from_secs(240),
        )
        .await
        .context("Failed to connect")?;

        let start = Instant::now();
        timeout(Duration::from_secs(10), stream.write_all(TEST_MESSAGE))
            .await
            .context("Write timed out")??;

        let mut response = vec![0u8; TEST_MESSAGE.len()];
        timeout(Duration::from_secs(30), stream.read_exact(&mut response))
            .await
            .context("Read timed out")??;

        assert_eq!(&response, TEST_MESSAGE);
        let elapsed = start.elapsed();
        info!("Echo latency: {} ms", elapsed.as_millis());
        samples.push(elapsed);
        drop(stream);
    }

    if let Some(min) = samples.iter().min() {
        let max = samples.iter().max().unwrap();
        let total_ms: u128 = samples.iter().map(|d| d.as_millis()).sum();
        let avg_ms = total_ms as f64 / samples.len() as f64;
        info!(
            "Echo latency stats: min={}ms max={}ms avg={:.2}ms",
            min.as_millis(),
            max.as_millis(),
            avg_ms
        );
    }

    server_handle.abort();
    Ok(())
}

/// Test iroh user transport roundtrip over Tor.
///
/// This uses the public API only (TorUserTransport::builder).
#[tokio::test]
async fn test_user_transport_roundtrip_tor() -> Result<()> {
    use iroh::{
        Endpoint,
        endpoint::Connection,
        protocol::{AcceptError, ProtocolHandler, Router},
    };
    use iroh_tor::TorUserTransport;

    const ALPN: &[u8] = b"iroh-tor/user-transport/0";

    #[derive(Debug, Clone)]
    struct Echo;

    impl ProtocolHandler for Echo {
        async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
            let (mut send, mut recv) = connection.accept_bi().await?;
            let bytes_sent = tokio::io::copy(&mut recv, &mut send).await?;
            info!("echo copied {bytes_sent} bytes");
            send.finish()?;
            connection.closed().await;
            Ok(())
        }
    }

    init_tracing();
    info!("starting tor user-transport test");

    let sk1 = SecretKey::generate(&mut rand::rng());
    let sk2 = SecretKey::generate(&mut rand::rng());
    let id2 = sk2.public();

    // Build transports using the real Tor builder (creates hidden services)
    let transport1 = TorUserTransport::builder(sk1.clone())
        .build()
        .await
        .context("Failed to create transport1. Is Tor running with ControlPort 9051?")?;
    let transport2 = TorUserTransport::builder(sk2.clone())
        .build()
        .await
        .context("Failed to create transport2")?;

    let ep1 = Endpoint::builder()
        .secret_key(sk1)
        .clear_ip_transports()
        .clear_relay_transports()
        .clear_discovery()
        .preset(transport1.preset())
        .bind()
        .await?;

    let ep2 = Endpoint::builder()
        .secret_key(sk2)
        .clear_ip_transports()
        .clear_relay_transports()
        .clear_discovery()
        .preset(transport2.preset())
        .bind()
        .await?;

    info!("endpoints bound with tor hidden services");

    let _server = Router::builder(ep2).accept(ALPN, Echo).spawn();

    info!("dialing remote endpoint via tor");
    let conn = ep1.connect(id2, ALPN).await?;
    let (mut send, mut recv) = conn.open_bi().await?;
    send.write_all(b"hello tor user transport").await?;
    send.finish()?;
    let response = recv.read_to_end(1024).await?;
    assert_eq!(&response, b"hello tor user transport");
    info!("tor user-transport test completed");

    Ok(())
}
