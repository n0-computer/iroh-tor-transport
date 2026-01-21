//! Example echo server/client using iroh over Tor hidden services.
//!
//! This example demonstrates how to use `iroh-tor` for bidirectional communication
//! over Tor. It requires a running Tor daemon with ControlPort enabled.

use std::{env, net::SocketAddr, str::FromStr, sync::Arc};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use data_encoding::HEXLOWER;
use iroh::{
    Endpoint, EndpointAddr, EndpointId, SecretKey, TransportAddr,
    endpoint::Connection,
    protocol::{AcceptError, ProtocolHandler, Router},
};
use iroh_base::UserAddr;
use iroh_tor::TorUserTransport;
use sha2::{Digest, Sha512};
use tokio::{
    net::{TcpListener, TcpStream},
    time::{sleep, timeout},
};
use torut::{
    control::{AuthenticatedConn, ConnError, UnauthenticatedConn},
    onion::{OnionAddressV3, TorSecretKeyV3},
};

const ALPN: &[u8] = b"iroh-tor/user-transport/0";
const ONION_PORT: u16 = 9999;
const TOR_USER_TRANSPORT_ID: u64 = 0x544f52;

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

/// Build a user transport address for the Tor transport.
fn tor_user_addr(endpoint: EndpointId) -> UserAddr {
    UserAddr::from_parts(TOR_USER_TRANSPORT_ID, endpoint.as_bytes())
}

type EventHandler = Box<
    dyn Fn(
            torut::control::AsyncEvent<'static>,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), ConnError>> + Send>>
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
}

#[derive(Parser, Debug)]
#[command(
    name = "tor-user-transport",
    about = "Run a one-shot iroh user transport over Tor"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Accept one connection and echo it.
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

async fn setup_endpoint(sk: SecretKey, listener: TcpListener) -> Result<Endpoint> {
    let transport = TorUserTransport::builder(sk.clone())
        .listener(listener)
        .build()
        .await;
    Ok(Endpoint::builder()
        .secret_key(sk)
        .preset(transport.preset())
        .clear_ip_transports()
        .clear_relay_transports()
        .clear_discovery()
        .bind()
        .await?)
}

async fn connect_with_retry(
    ep: &Endpoint,
    addr: EndpointAddr,
    alpn: &[u8],
    timeout_per_attempt: std::time::Duration,
    max_attempts: usize,
) -> Result<iroh::endpoint::Connection> {
    let mut last_err: Option<anyhow::Error> = None;
    for attempt in 1..=max_attempts {
        tracing::info!("connect attempt {attempt}/{max_attempts}");
        match timeout(timeout_per_attempt, ep.connect(addr.clone(), alpn)).await {
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

    let control_addr = "127.0.0.1:9051";
    let mut tor_control = TorControl::connect(control_addr).await.context(
        "Tor control port unavailable. Start Tor with ControlPort 9051 enabled and try again.",
    )?;

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let local_addr = listener.local_addr()?;
    let tor_key = iroh_to_tor_secret_key(&secret);
    let (onion, _) = tor_control
        .create_hidden_service_with_tor_key(&tor_key, ONION_PORT, local_addr)
        .await?;

    println!("EndpointId: {}", endpoint_id);
    if let Some(secret) = secret_hint {
        println!("Set IROH_SECRET={} to reuse this endpoint id.", secret);
    }
    println!("Onion: {}.onion", onion.get_address_without_dot_onion());

    let ep = Arc::new(setup_endpoint(secret.clone(), listener).await?);

    let ep_accept = ep.clone();
    if matches!(cli.command, Command::Accept) {
        let _router = Router::builder((*ep_accept).clone())
            .accept(ALPN, Echo)
            .spawn();
        println!("Accepting connections (Ctrl-C to exit)...");
        tokio::signal::ctrl_c().await?;
        return Ok(());
    }

    let Command::Connect { remote } = cli.command else {
        unreachable!();
    };

    let remote_id = EndpointId::from_str(&remote).context("invalid --remote EndpointId")?;

    let addr = EndpointAddr::from_parts(remote_id, [TransportAddr::User(tor_user_addr(remote_id))]);
    let conn = connect_with_retry(
        ep.as_ref(),
        addr,
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
