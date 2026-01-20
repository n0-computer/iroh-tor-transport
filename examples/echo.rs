use std::env;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use data_encoding::HEXLOWER;
use iroh::endpoint::Connection;
use iroh::protocol::{AcceptError, ProtocolHandler, Router};
use iroh::{Endpoint, EndpointAddr, EndpointId, SecretKey, TransportAddr};
use iroh_tor::{
    TorControl, TorStreamIo, TorUserAddrDiscovery, TorUserTransportFactory,
    DEFAULT_CONTROL_PORT, DEFAULT_SOCKS_PORT, iroh_to_tor_secret_key, tor_user_addr,
    onion_address_from_endpoint,
};
use tokio::net::TcpListener;
use tokio_socks::tcp::Socks5Stream;
use tokio::time::{sleep, timeout};

const ALPN: &[u8] = b"iroh-tor/user-transport/0";
const ONION_PORT: u16 = 9999;

#[derive(Parser, Debug)]
#[command(name = "tor-user-transport", about = "Run a one-shot iroh user transport over Tor")]
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

async fn build_tor_io(
    listener: TcpListener,
    socks_addr: SocketAddr,
) -> Arc<TorStreamIo> {
    Arc::new(TorStreamIo::new(
        {
            let listener = Arc::new(listener);
            move || {
                let listener = listener.clone();
                async move {
                    let (stream, _) = listener.accept().await?;
                    Ok(stream)
                }
            }
        },
        {
            move |endpoint| async move {
                let onion = onion_address_from_endpoint(endpoint)?;
                let onion_addr = format!("{}.onion", onion.get_address_without_dot_onion());
                let stream =
                    Socks5Stream::connect(socks_addr, (onion_addr.as_str(), ONION_PORT)).await?;
                Ok(stream.into_inner())
            }
        },
    ))
}

async fn setup_endpoint(
    sk: &SecretKey,
    io: Arc<TorStreamIo>,
) -> Result<Endpoint> {
    Ok(Endpoint::builder()
        .secret_key(sk.clone())
        .add_user_transport(Arc::new(TorUserTransportFactory::new(sk.public(), io, 64)))
        .clear_ip_transports()
        .clear_relay_transports()
        .clear_discovery()
        .discovery(TorUserAddrDiscovery)
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

    let control_addr = format!("127.0.0.1:{}", DEFAULT_CONTROL_PORT);
    let mut tor_control = TorControl::connect(&control_addr).await.context(
        "Tor control port unavailable. Start Tor with ControlPort 9051 enabled and try again.",
    )?;
    let socks_addr: SocketAddr = format!("127.0.0.1:{}", DEFAULT_SOCKS_PORT).parse()?;

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

    let io = build_tor_io(listener, socks_addr).await;
    let ep = Arc::new(setup_endpoint(&secret, io).await?);

    let ep_accept = ep.clone();
    if matches!(cli.command, Command::Accept) {
        let _router = Router::builder((*ep_accept).clone()).accept(ALPN, Echo).spawn();
        println!("Accepting connections (Ctrl-C to exit)...");
        tokio::signal::ctrl_c().await?;
        return Ok(());
    }

    let Command::Connect { remote } = cli.command else {
        unreachable!();
    };

    let remote_id = EndpointId::from_str(&remote).context("invalid --remote EndpointId")?;

    let addr = EndpointAddr::from_parts(remote_id, [TransportAddr::User(tor_user_addr(remote_id))]);
    let conn = connect_with_retry(ep.as_ref(), addr, ALPN, std::time::Duration::from_secs(30), 10)
        .await?;
    let (mut send, mut recv) = conn.open_bi().await?;
    send.write_all(b"hello tor user transport").await?;
    send.finish()?;
    let response = recv.read_to_end(1024).await?;
    println!("Echo response: {}", String::from_utf8_lossy(&response));

    Ok(())
}
