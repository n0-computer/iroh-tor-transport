# iroh-tor

Tor hidden-service utilities and a custom iroh transport for routing packets over Tor streams.

> **Experimental:** both iroh custom transports and this crate are experimental and may change.

## What is iroh-tor?

`iroh-tor` provides:

- helpers for Tor v3 hidden services (key conversion, control port helpers)
- a framed packet protocol for streaming packets over Tor
- a custom iroh user transport that uses Tor streams

## Getting started

### Tor control port

Most tests require a running Tor daemon with the control port enabled:

```
tor --ControlPort 9051 --CookieAuthentication 0
```

### Custom transport

At a high level, you provide `TorStreamIo` (accept/connect), and the transport
handles framing, packet I/O, and stream reuse:

```rust
use std::sync::Arc;
use iroh_tor::{TorStreamIo, TorUserTransportFactory};

let io = Arc::new(TorStreamIo::new(accept_fn, connect_fn));
let factory = TorUserTransportFactory::new(endpoint_id, io, 64);

// add_user_transport(factory) on the iroh Endpoint builder
```

## Packet framing

Each packet is framed as:

- `flags: u8` (bit 0 indicates `segment_size` present)
- `from: [u8; 32]` (iroh `EndpointId`)
- `segment_size: u16` (optional hint, not a payload limit)
- `data_len: u32`
- `data: [u8; data_len]`

## Example

`examples/echo.rs` provides a CLI to accept/connect a single echo round over Tor.
It uses only the remote `EndpointId` when connecting; the onion address is derived
from the public key.

## Tests

- `tests/echo.rs`: hidden-service echo tests (Tor required)
- `tests/packet_service.rs`: packet framing and service dispatch
- `tests/packet_sender.rs`: stream reuse in the sender
- `tests/user_transport.rs`: local and Tor-backed user transport tests
