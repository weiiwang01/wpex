# wpex: WireGuard Packet Relay

`wpex` is a relay server designed for WireGuard, facilitating NAT traversal
without compromising the end-to-end encryption of WireGuard.

## Features

- The relay server **can't** tamper the encryption by any means.
- Works with vanilla WireGuard setups, no extra software required.
- Zero MTU overhead.

## Installation

### Using Docker:

Fetch and run the `wpex` Docker image with:

```bash
docker run -d -p 40000:40000/udp ghcr.io/weiiwang01/wpex:latest --broadcast-rate 3
```

See [Protections](#protections-against-amplification-attacks) for more
information on the `--broadcast-rate` flag.

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
2. Enable the `PersistentKeepalive` setting, if the peer is behind a NAT.

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

## Protections Against Amplification Attacks

The design principle behind `wpex` is to know as little as possible about the
WireGuard connections. If it knows nothing, it can't leak anything. By
default, `wpex` is unaware of any information regarding incoming connections,
making it vulnerable to DoS and amplification attacks when operating in an
untrusted network.

The most rudimentary protection is the `--broadcast-limit`, which will limit the
rate of amplified packets.

To calculate an ideal broadcast rate limit, use the following formula: given `N`
represents the number of WireGuard peers connecting to the server, and `K`
denotes the number of WireGuard peer-to-peer pairs formed from all peers, the
theoretical maximum rate of broadcast is `(N - 1) * K * 2 / 5`. Set this value
as the broadcast rate for your `wpex` instance to ensure safe operation.

The effectiveness of the broadcast rate limit's protection will only be realized
if set to a sufficiently low value, for example, less than 5. This setting may
not be viable if a larger number of peers are interconnected.

In that case, for best protection, instead of a broadcast rate limit, you can
provide an allowed list of WireGuard public keys to the `wpex` server, which
will block any connection attempts from anyone not aware of the public keys.
This doesn't affect the integrity of the E2E encryption, as only the public
keys (not the associated private keys) are known to the `wpex` server.

Examples of using public keys:

```bash
docker run -d -p 40000:40000/udp ghcr.io/weiiwang01/wpex:latest \
  --allow AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= \
  --allow BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=
```

```bash
wpex --allow AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= \
  --allow BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=
```

## How `wpex` Works

Within each WireGuard session, every peer in the session selects a random 32-bit
index to identify themselves within that session. `wpex` operates by learning
the associated endpoint address of each index, and forwarding packet based on
the receiver index in the message.

For the initial handshake message, which lacks a receiver index, `wpex`
broadcasts the handshake initiation to all known endpoints. Only the correct
peer will respond with a handshake response message, while the others will just
discard the packet. This broadcasting mechanism, however, poses a significant
vulnerability as it can be exploited for amplification attacks. Attackers can
create fake handshake initiation messages with the source address spoofed to the
victim's, easily causing an attack with an amplification factor of thousands.

This is where public keys come to the rescue. By knowing the public keys of all
peers, it's possible to verify the `mac1` value within the handshake initiation
and handshake response messages. However, merely validating the `mac1` is
inadequate since it doesn't provide resistance to replay attacks as the
timestamp in handshake messages cannot be decrypted without the private key.

To mitigate this, whenever there's a handshake initiation from new
endpoint, `wpex` sends a pseudo cookie reply to the originating endpoint.
A structurally valid cookie reply can be generated using only the public key.
The new endpoint, based on WireGuard protocol, in turn, will react with a new
handshake initiation with the correct `mac2` value, derived from the cookie
reply sent earlier. Upon receipt of this, it's affirmed that the new endpoint is
legitimate, and it's then added to the list of known endpoints. This mechanism
effectively counters replay attacks as each cookie reply generated is unique.
The `mac2` value in that handshake initiation message will be striped before
forwarding since the cookie is generated by `wpex` and not by the actual peer.
