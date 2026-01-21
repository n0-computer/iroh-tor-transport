//! Example echo server/client using iroh over Tor hidden services.
//!
//! This example demonstrates how to use `iroh-tor` for bidirectional communication
//! over Tor. It requires a running Tor daemon with ControlPort enabled.

use std::{env, str::FromStr, sync::Arc};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use data_encoding::HEXLOWER;
use iroh::{
    Endpoint, EndpointId, SecretKey,
    endpoint::Connection,
    protocol::{AcceptError, ProtocolHandler, Router},
};
use iroh_tor::TorUserTransport;
use tokio::time::{sleep, timeout};

const ALPN: &[u8] = b"iroh-tor/user-transport/0";

#[derive(Parser, Debug)]
#[command(
    name = "tor-user-transport",
    about = "Run an iroh user transport over Tor"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Accept connections and echo back data.
    Accept,
    /// Connect to a remote endpoint and perform a single echo round.
    Connect {
        /// Remote endpoint id (base32-hex encoding used by iroh).
        #[arg(long)]
        remote: String,
    },
}

#[derive(Debug, Clone)]
struct Echo;

impl ProtocolHandler for Echo {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        let (mut send, mut recv) = connection.accept_bi().await?;
        let bytes_sent = tokio::io::copy(&mut recv, &mut send).await?;
        tracing::info!("echo copied {bytes_sent} bytes");
        send.finish()?;
        connection.closed().await;
        Ok(())
    }
}

fn init_tracing() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init()
        .ok();
}

fn load_secret() -> Result<(SecretKey, Option<String>)> {
    if let Ok(value) = env::var("IROH_SECRET") {
        let bytes = HEXLOWER
            .decode(value.as_bytes())
            .context("invalid IROH_SECRET (expected hex)")?;
        if bytes.len() != 32 {
            return Err(anyhow::anyhow!(
                "invalid IROH_SECRET length (expected 32 bytes)"
            ));
        }
        let key_bytes: [u8; 32] = bytes[..].try_into().expect("length checked");
        let key = SecretKey::from_bytes(&key_bytes);
        Ok((key, None))
    } else {
        let key = SecretKey::generate(&mut rand::rng());
        let encoded = HEXLOWER.encode(&key.to_bytes());
        Ok((key, Some(encoded)))
    }
}

async fn connect_with_retry(
    ep: &Endpoint,
    id: EndpointId,
    alpn: &[u8],
    timeout_per_attempt: std::time::Duration,
    max_attempts: usize,
) -> Result<iroh::endpoint::Connection> {
    let mut last_err: Option<anyhow::Error> = None;
    for attempt in 1..=max_attempts {
        tracing::info!("connect attempt {attempt}/{max_attempts}");
        match timeout(timeout_per_attempt, ep.connect(id, alpn)).await {
            Ok(Ok(conn)) => return Ok(conn),
            Ok(Err(err)) => last_err = Some(anyhow::Error::new(err)),
            Err(err) => last_err = Some(anyhow::anyhow!("connect timed out: {err}")),
        }
        if attempt < max_attempts {
            sleep(std::time::Duration::from_secs(5)).await;
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("connect failed")))
}

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();

    let cli = Cli::parse();
    let (secret, secret_hint) = load_secret()?;
    let endpoint_id = secret.public();

    println!("EndpointId: {}", endpoint_id);
    if let Some(hint) = &secret_hint {
        println!("Set IROH_SECRET={} to reuse this endpoint id.", hint);
    }

    // Build the transport - this creates the hidden service automatically
    let transport = TorUserTransport::builder(secret.clone())
        .build()
        .await
        .context("Failed to create Tor transport. Is Tor running with ControlPort 9051?")?;

    // Build the endpoint with the Tor transport
    let ep = Arc::new(
        Endpoint::builder()
            .secret_key(secret)
            .preset(transport.preset())
            .clear_ip_transports()
            .clear_relay_transports()
            .clear_discovery()
            .bind()
            .await?,
    );

    if matches!(cli.command, Command::Accept) {
        let _router = Router::builder((*ep).clone()).accept(ALPN, Echo).spawn();
        println!("Accepting connections (Ctrl-C to exit)...");
        tokio::signal::ctrl_c().await?;
        return Ok(());
    }

    let Command::Connect { remote } = cli.command else {
        unreachable!();
    };

    let remote_id = EndpointId::from_str(&remote).context("invalid --remote EndpointId")?;

    // Connect using discovery (the transport's discovery will provide the Tor address)
    let conn = connect_with_retry(
        ep.as_ref(),
        remote_id,
        ALPN,
        std::time::Duration::from_secs(30),
        10,
    )
    .await?;
    let (mut send, mut recv) = conn.open_bi().await?;
    send.write_all(b"hello tor user transport").await?;
    send.finish()?;
    let response = recv.read_to_end(1024).await?;
    println!("Echo response: {}", String::from_utf8_lossy(&response));

    Ok(())
}
