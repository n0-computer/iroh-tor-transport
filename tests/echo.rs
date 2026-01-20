//! Integration test: Tor hidden service echo test using a native Tor key.
//!
//! This test requires a running Tor daemon with the control port enabled.
//! Run `tor` with ControlPort 9051 enabled in your torrc.

use std::{net::SocketAddr, time::Duration};

use anyhow::{Context, Result, bail};
use iroh_tor::{DEFAULT_CONTROL_PORT, DEFAULT_SOCKS_PORT, TorControl, generate_tor_key};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::{Instant, timeout},
};
use tokio_socks::tcp::Socks5Stream;
use torut::onion::OnionAddressV3;

const TEST_MESSAGE: &[u8] = b"Hello from Tor hidden service!";
const HIDDEN_SERVICE_PORT: u16 = 9999;

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
        println!(
            "  Connection attempt {} ({}s remaining)...",
            attempt,
            remaining.as_secs()
        );
        match Socks5Stream::connect(socks_addr, target).await {
            Ok(stream) => return Ok(stream.into_inner()),
            Err(e) => {
                println!("  Attempt {} failed: {}", attempt, e);
                last_error = Some(e);
                // Wait before retrying - the service might still be propagating
                let backoff = 3u64.saturating_mul(2u64.saturating_pow((attempt - 1) as u32));
                let sleep_for = Duration::from_secs(backoff.min(15));
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining > Duration::from_secs(1) {
                    tokio::time::sleep(sleep_for.min(remaining)).await;
                }
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
        println!("Received {} bytes", n);
        if n == 0 {
            break;
        }
        socket.write_all(&buf[..n]).await?;
    }

    Ok(())
}

/// Wait until the hidden service shows up in Tor's list for this control connection.
async fn wait_for_hidden_service(
    tor_control: &mut TorControl,
    addr: &OnionAddressV3,
    timeout: Duration,
) -> Result<()> {
    let deadline = Instant::now() + timeout;
    loop {
        let services = tor_control.list_hidden_services().await?;
        if services.iter().any(|service| service == addr) {
            return Ok(());
        }
        if Instant::now() >= deadline {
            bail!(
                "Timed out waiting for hidden service to appear: {}.onion",
                addr.get_address_without_dot_onion()
            );
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

/// Simple test using torut's native key generation to verify the mechanism works.
#[tokio::test]
#[ignore = "requires running Tor daemon"]
async fn test_native_tor_key() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init()
        .ok();

    // Use torut's native key generation
    let tor_key = generate_tor_key();
    let onion_addr = tor_key.public().get_onion_address();
    println!("Generated onion: {}", onion_addr);

    // Bind local TCP listener
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let local_addr: SocketAddr = listener.local_addr()?;
    println!("Listening on: {}", local_addr);

    // Connect to Tor and create hidden service
    let control_addr = format!("127.0.0.1:{}", DEFAULT_CONTROL_PORT);
    let mut tor_control = TorControl::connect(&control_addr).await?;

    let (created_addr, existed) = tor_control
        .create_hidden_service_with_tor_key(&tor_key, HIDDEN_SERVICE_PORT, local_addr)
        .await?;

    println!(
        "Hidden service {}: {}.onion:{}",
        if existed { "reused" } else { "created" },
        created_addr.get_address_without_dot_onion(),
        HIDDEN_SERVICE_PORT
    );

    // Wait adaptively: poll Tor for the new service to appear on this connection.
    println!("Waiting for hidden service to appear in control connection list...");
    wait_for_hidden_service(&mut tor_control, &created_addr, Duration::from_secs(60)).await?;

    // Spawn echo server
    let server_handle = tokio::spawn(async move {
        if let Err(e) = run_echo_server(listener).await {
            eprintln!("Echo server error: {}", e);
        }
    });

    // Try to connect
    let onion_addr_str = format!("{}.onion", created_addr.get_address_without_dot_onion());
    println!(
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

    println!("Connected! Sending message...");
    timeout(Duration::from_secs(10), stream.write_all(TEST_MESSAGE))
        .await
        .context("Write timed out")??;

    let mut response = vec![0u8; TEST_MESSAGE.len()];
    timeout(Duration::from_secs(30), stream.read_exact(&mut response))
        .await
        .context("Read timed out")??;

    assert_eq!(&response, TEST_MESSAGE);
    println!("Echo test with native tor key PASSED!");

    // List services before dropping the control connection.
    let services = tor_control.list_hidden_services().await?;
    println!("Active services on this control connection:");
    for service in services {
        println!("  {}.onion", service.get_address_without_dot_onion());
    }

    drop(stream);
    server_handle.abort();
    Ok(())
}
