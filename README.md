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

## Recommended IP Ranges

Use one of the following private IPv4 ranges (RFC 1918) for the VPN network:

| Range | CIDR | Usable Hosts |
|-------|------|-------------|
| `10.0.0.0` – `10.255.255.255` | `10.0.0.0/8` | 16,777,214 |
| `172.16.0.0` – `172.31.255.255` | `172.16.0.0/12` | 1,048,574 |
| `192.168.0.0` – `192.168.255.255` | `192.168.0.0/16` | 65,534 |

Pick a `/24` (254 hosts) or smaller subnet for your mesh to avoid overlap with local networks. For example, `10.88.0.0/24`.

## 1. Certificate Management (`liteway-cert`)

### Generate CA

```sh
liteway-cert gen-ca -n my-ca -y 10 -o ca
```

Produces `ca.toml` and `ca-key.toml`. The command also prints a separate `network_secret` value — save the same value to every node config. It is network membership secret material, not CA key material.

Optional groups: `-g engineering -g web`.

### Generate Node Certificate

```sh
liteway-cert gen-node -n mynode -i 10.0.0.1/24
```

- `-i` — TUN interface IP (CIDR)
- `-s` — advertised subnets for routing (repeatable, optional)
- `-g` — groups (repeatable, optional)

Advertised subnets require route grants as groups, for example
`-g route:10.0.0.0/24`; `route:*` allows all non-default subnets.

Produces public `mynode-cert.toml` and private `mynode-key.toml`.

## 2. Public Node Configuration (`liteway.toml`)

```toml
listen = "0.0.0.0:12345"
network_secret = "<hex from gen-ca>"
ca_cert_path = "ca.toml"
node_cert_path = "mynode-cert.toml"
node_key_path = "mynode-key.toml"
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
Lighthouse certificates are verified against the configured CA during the normal
handshake; `[[lighthouses]]` only pins the underlay address to contact.

## 3. Private Node Configuration (`liteway.toml`)

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
address = "1.2.3.4:5678"
```

## 4. Daemon (`litewayd`)

```sh
# Linux (capability, no root needed)
sudo setcap cap_net_admin+ep target/release/litewayd
litewayd -c liteway.toml

# macOS / Linux (root)
sudo litewayd -c liteway.toml

# Windows (Admin prompt)
litewayd -c liteway.toml
```

## 5. Docker compose

Add this to config:

```yaml
ca_cert_path = "/ca.toml"
node_cert_path = "/cert.toml"
node_key_path = "/key.toml"
```

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

## 6. Full config

```yaml
# keep following line is needed only for lighthouse or relay setup
listen = "0.0.0.0:12345"
network_secret = "<hex from gen-ca>"
ca_cert_path = "ca.toml"
node_cert_path = "mynode-cert.toml"
node_key_path = "mynode-key.toml"
punch_interval_secs = 10
keepalive_punch = true
keepalive_timeout_secs = 30
relay_fallback_timeout_secs = 5
am_lighthouse = false
am_relay = false

[interface]
name = "liteway0"
mtu = 1300

[[lighthouses]]
name = "lh1"
address = "1.2.3.4:5678"
```

## License

MIT
