# Liteway

Rust rewrite of [nebula](https://github.com/slackhq/nebula) - a zero-plaintext L3 mesh VPN with post-quantum hybrid cryptography.

## Prerequisites

- **Rust** 1.75+
- **Linux**: `CAP_NET_ADMIN` capability or root; `tun` module loaded
- **macOS**: root or `sudo` for `SIOCAIFADDR` ioctl
- **Windows**: Administrator (checked via SAM metadata)

## Build

```sh
cargo build --release
```

Two binaries: `litewayd` and `liteway-cert`.

## 1. Certificate Management (`liteway-cert`)

### Generate CA

```sh
liteway-cert gen-ca -n my-ca -v 10 -o ca
```

Produces `ca.toml` and `ca-key.toml`. The command also prints a separate `network_secret` value — save the same value to every node config. It is network membership secret material, not CA key material.

Optional groups: `-g engineering -g web`.

## Recommended IP Ranges

Use one of the following private IPv4 ranges (RFC 1918) for the VPN network:

| Range | CIDR | Usable Hosts |
|-------|------|-------------|
| `10.0.0.0` – `10.255.255.255` | `10.0.0.0/8` | 16,777,214 |
| `172.16.0.0` – `172.31.255.255` | `172.16.0.0/12` | 1,048,574 |
| `192.168.0.0` – `192.168.255.255` | `192.168.0.0/16` | 65,534 |

Pick a `/24` (254 hosts) or smaller subnet for your mesh to avoid overlap with local networks. For example, `10.88.0.0/24`.

## 2. Public Node Setup

Generate Node Certificate

```sh
liteway-cert gen-node -n publicnode -i 10.0.0.1/24
```

- `-i` — TUN interface IP (CIDR)
- `-s` — advertised subnets for routing (repeatable, optional)
- `-g` — groups (repeatable, optional)

Advertised subnets require route grants as groups, for example
`-g route:10.0.0.0/24`; `route:*` allows all non-default subnets.

Produces public `publicnode-cert.toml` and private `publicnode-key.toml`.

Public Node Configuration (`liteway.toml`):

```toml
listen = "0.0.0.0:12345"
network_secret = "<hex from gen-ca>"
ca_cert_path = "/ca.toml"
node_cert_path = "/cert.toml"
node_key_path = "/key.toml"
am_lighthouse = true
am_relay = true

[interface]
name = "liteway0"
mtu = 1300
```

When `am_lighthouse = true`, the node acts as a peer discovery registry. Nodes that
handshake with it are registered by their certificate IP/subnets and UDP endpoint.
If another node has no route for a VPN IP, it asks connected lighthouses for the
peer behind that IP and then starts a direct handshake to the returned endpoint.
The lighthouse also tells the other peer about the requester, so both ends punch at
the same time. Lighthouse certificates are verified against the configured CA during
the normal handshake.

And use this docker-compose.yml:

```yaml
services:
  liteway:
    image: ghcr.io/nelonn/liteway:nightly
    restart: unless-stopped
    network_mode: host
    devices:
      - /dev/net/tun
    cap_add:
      - NET_ADMIN
    volumes:
      - ./liteway.toml:/liteway.toml
      - ./ca.toml:/ca.toml
      - ./mynode-cert.toml:/cert.toml
      - ./mynode-key.toml:/key.toml
```

Then run `docker compose up -d`

## 3. Private Node Setup

Generate Node Certificate

```sh
liteway-cert gen-node -n privatenode -i 10.0.0.2/24
```

Private Node Configuration (`liteway.toml`):

```toml
network_secret = "<hex from gen-ca>"
ca_cert_path = "ca.toml"
node_cert_path = "mynode-cert.toml"
node_key_path = "mynode-key.toml"

[interface]
name = "liteway0"
mtu = 1300

[[lighthouses]]
name = "lh1"
address = "lh1.example.com:5678" # or "1.2.3.4:5678"
```

Then run daemon:

```sh
# Linux (capability, no root needed)
sudo setcap cap_net_admin+ep target/release/litewayd
litewayd -c liteway.toml

# macOS / Linux (root)
sudo litewayd -c liteway.toml

# Windows (Admin prompt)
litewayd -c liteway.toml
```

## How a peer-to-peer session is built

1. The node asks its lighthouses which endpoint owns the destination VPN IP.
2. The lighthouse answers the asker **and** introduces the asker to the target, so
   both ends start handshaking at the same time and punch each other's NAT open.
3. The handshake is retransmitted with a backoff until it is answered. Each
   retransmission reuses the same fragment message id, so the receiver merges the
   copies: a handshake completes as long as every fragment arrives in *one* of the
   attempts, not all in the same one.
4. If the direct path has not answered after `relay_fallback_timeout_secs`, the
   same handshake is *also* sent through a connected relay. Whichever path answers
   first is used; the direct attempt keeps running.
5. A session that ended up on a relay is not stuck there. Both ends keep punching
   the peer's direct endpoint with a small probe, and the moment one gets through
   the session moves onto the direct path without a new handshake
   (`peer ... moved off the relay` in the log).
6. Idle sessions are kept alive in both directions, which also keeps NAT mappings
   open. A session that stops answering entirely is torn down and rebuilt instead
   of silently blackholing traffic.

## See full config reference

```toml
# the following line is needed only for a lighthouse or relay setup
listen = "0.0.0.0:12345"
network_secret = "<hex from gen-ca>"
ca_cert_path = "ca.toml"
node_cert_path = "mynode-cert.toml"
node_key_path = "mynode-key.toml"
am_lighthouse = false
am_relay = false

# how often a disconnected lighthouse is punched again
punch_interval_secs = 10
# send keepalives on idle sessions (also keeps NAT mappings open)
keepalive_punch = true
# keepalive cadence, and how long a session may stay silent before it is rebuilt
keepalive_interval_secs = 10
keepalive_timeout_secs = 30
# how long a handshake is retransmitted before it is given up on
handshake_timeout_secs = 20
# how long the direct path gets before the handshake is also sent via a relay
relay_fallback_timeout_secs = 5
# how often a relayed session probes the peer's direct endpoint (doubles up to 30s)
direct_probe_interval_secs = 5

[interface]
name = "liteway0"
mtu = 1300

[[lighthouses]]
name = "lh1"
address = "1.2.3.4:5678"
```

Unknown keys in the config file are rejected rather than ignored, so a misspelled
option fails at startup instead of silently keeping its default.

## Troubleshooting

Run with `RUST_LOG=debug` to see handshake retries, relay fallback and path probes.
Useful lines:

| Log line | Meaning |
|----------|---------|
| `handshake_1 retry N to <peer>` | the handshake is being retransmitted; the path is lossy or blocked |
| `also trying relay <name>` | the direct path did not answer in time; the relay is now being tried in parallel |
| `handshake complete with <peer> (<addr>, via relay)` | the session is up but relayed |
| `moved off the relay` | the direct path opened and the session switched to it |
| `removing peer <name> (...): keepalive timeout` | the session went silent in both directions and will be rebuilt |

## License

MIT
