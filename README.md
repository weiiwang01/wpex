# wpex: WireGuard Packet Relay

`wpex` is a relay server designed for WireGuard, facilitating NAT traversal
without compromising the E2E encryption of WireGuard.

## Features

- The relay server **can't** tamper the encryption.
- Works with vanilla WireGuard setups, no extra software required.
- Zero MTU overhead.

## Installation

### Using Docker:

Fetch and run the `wpex` Docker image with:

```bash
docker run -d -p 40000:40000:udp ghcr.io/weiiwang01/wpex:latest
```

### Using Pre-built Binaries:

You can download pre-built binaries directly from
the [releases page](https://github.com/weiiwang01/wpex/releases).

### Building from Source:

Ensure you have Go 1.21 or later, then run:

```bash
go install github.com/weiiwang01/wpex@latest
```

## Usage

If you wish to connect multiple WireGuard peers behind NAT via a `wpex` server
(e.g., at `wpex.test:40000`), follow these steps:

1. Update all WireGuard peers' endpoint configurations to point to the `wpex`
   server.
2. Enable the `PersistentKeepalive` setting.

**Example for Peer A**:

```
[Interface]
PrivateKey = aaaaa...

[Peer]
PublicKey = BBBBB...
Endpoint = wpex.test:40000
PersistentKeepalive = 25
```

**Example for Peer B**:

```
[Interface]
PrivateKey = bbbbb...

[Peer]
PublicKey = AAAAA...
Endpoint = wpex.test:40000
PersistentKeepalive = 25
```

And that's done, Peer A and Peer B should now connect, and `wpex` will
automatically relay their traffic.

## Known Limitations

The design principle behind `wpex` is to know as little as possible about the
WireGuard connections. If it knows nothing, it can't leak anything. By
default, `wpex` is unaware of any information regarding incoming connections,
making it vulnerable to DoS and amplification attacks.

To mitigate this, you can provide an allowed list of WireGuard public keys to
the `wpex` server. Connections attempted with public keys not on this list will
be ignored. This doesn't affect the integrity of the E2E encryption, as only the
public keys (not the associated private keys) are known to the wpex server.

Examples:

```bash
docker run -d -p 40000:40000:udp ghcr.io/weiiwang01/wpex:latest \
  --allow AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= \
  --allow BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=
```

```bash
wpex --allow AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= \
  --allow BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=
```
