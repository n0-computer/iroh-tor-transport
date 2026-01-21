//! Integration test: Tor hidden service echo test using a native Tor key.
//!
//! This test requires a running Tor daemon with the control port enabled.
//! Run: `tor --ControlPort 9051 --CookieAuthentication 0`

use std::{io, net::SocketAddr, sync::Once, time::Duration};

use anyhow::{Context, Result};
use iroh::SecretKey;
use iroh_tor::{
    DEFAULT_CONTROL_PORT, DEFAULT_SOCKS_PORT, TorControl, TorSecretKeyV3, generate_tor_key,
    iroh_to_tor_secret_key,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::{Instant, timeout},
};
use tokio_socks::tcp::Socks5Stream;
use tracing::{error, info, warn};

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
    let control_addr = format!("127.0.0.1:{}", DEFAULT_CONTROL_PORT);
    TorControl::connect(&control_addr).await.context(
        "Tor control port unavailable. Start Tor with ControlPort 9051 enabled and try again.",
    )
}

/// Connect to a .onion address through the Tor SOCKS5 proxy with retries.
async fn connect_via_tor(onion_addr: &str, port: u16, timeout: Duration) -> Result<TcpStream> {
    let socks_addr: SocketAddr = format!("127.0.0.1:{}", DEFAULT_SOCKS_PORT).parse()?;
    let target = (onion_addr, port);

    // Retry logic - hidden services can take time to become reachable
    // First-time publish can take 60-120 seconds; subsequent runs are faster
    let deadline = Instant::now() + timeout;
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
async fn test_native_tor_key() -> Result<()> {
    let tor_key = generate_tor_key();
    run_hidden_service_echo(&tor_key, "native tor key").await
}

/// Test using an iroh key converted to a Tor keypair.
#[tokio::test]
async fn test_iroh_key_converted_to_tor() -> Result<()> {
    let iroh_key = SecretKey::generate(&mut rand::rng());
    let tor_key = iroh_to_tor_secret_key(&iroh_key);
    run_hidden_service_echo(&tor_key, "iroh->tor key").await
}

#[tokio::test]
async fn test_echo_latency_10x_single_service() -> Result<()> {
    init_tracing();

    let tor_key = generate_tor_key();
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
