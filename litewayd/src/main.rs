use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Context;
use clap::Parser;
use ipnetwork::IpNetwork;
use liteway_core::cert::{CaVerifyKey, Cert, NodeKeyFile};
use liteway_core::config::{AppConfig, LighthouseConfig};
use liteway_core::crypto::kdf;
use liteway_core::crypto::SESSION_KEY_LEN;
use liteway_core::frag::{self, FeedResult, FragmentAssembler};
use liteway_core::handshake;
use liteway_core::packet::{self, PacketBody};
use liteway_core::tunnel::TunDevice;
use rand::Rng;
use zeroize::{Zeroize, Zeroizing};

const PEER_EXPIRY_SECS: u64 = 300;
const CLEANUP_INTERVAL_SECS: u64 = 60;
const DISCOVERY_RETRY_SECS: u64 = 10;
const REPLAY_WINDOW_BITS: u64 = 64;
const ROUTE_ALL_GRANT: &str = "route:*";
const ROUTE_GRANT_PREFIX: &str = "route:";

struct KeepalivePending {
    token: u64,
    sent_at: u64,
}

struct PendingHandshake {
    initiate: handshake::HandshakeInitiate,
    addr: SocketAddr,
    peer_id: Option<u32>,
    peer_name: String,
    sent_at: u64,
    relay_attempted: bool,
}

struct RouteTable {
    routes: Vec<(IpNetwork, u32)>,
}

impl RouteTable {
    fn new() -> Self {
        RouteTable { routes: Vec::new() }
    }

    fn insert(&mut self, network: IpNetwork, peer_id: u32) {
        self.routes.retain(|(n, _)| n != &network);
        self.routes.push((network, peer_id));
    }

    fn lookup(&self, ip: IpAddr) -> Option<u32> {
        self.routes
            .iter()
            .filter(|(net, _)| net.contains(ip))
            .max_by_key(|(net, _)| net.prefix())
            .map(|(_, id)| *id)
    }

    fn remove_peer(&mut self, peer_id: u32) {
        self.routes.retain(|(_, id)| *id != peer_id);
    }
}

fn node_id_from_cert(cert: &Cert) -> u32 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"liteway-node-id-v1");
    hasher.update(&cert.body.keys.ed25519_pk);
    hasher.update(&cert.body.keys.ml_dsa_pk);
    let h = hasher.finalize();
    u32::from_be_bytes(h.as_bytes()[..4].try_into().unwrap())
}

fn main() -> anyhow::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let cli = Cli::parse();

    log::info!("reading config from {}", cli.config);
    let config = AppConfig::from_file(&cli.config)?;

    let ca_cert_bytes = std::fs::read_to_string(&config.ca_cert_path)
        .with_context(|| format!("read CA cert file '{}'", config.ca_cert_path))?;
    let full_ca: liteway_core::cert::CaCert = toml::from_str(&ca_cert_bytes)
        .with_context(|| format!("parse CA cert file '{}'", config.ca_cert_path))?;
    let ca_vk = CaVerifyKey {
        ed25519: full_ca.verify_key.ed25519,
        ml_dsa: full_ca.verify_key.ml_dsa,
    };

    let node_cert_bytes = std::fs::read_to_string(&config.node_cert_path)
        .with_context(|| format!("read node cert file '{}'", config.node_cert_path))?;
    let node_cert = parse_node_cert(&node_cert_bytes)
        .with_context(|| format!("parse node cert file '{}'", config.node_cert_path))?;

    let node_key = read_node_key(&config.node_key_path)?;

    let network_secret = Zeroizing::new(config.network_secret()?);
    let network_key = kdf::derive_network_key(&*network_secret);
    let our_id = node_id_from_cert(&node_cert);

    log::info!(
        "node '{}' ({}) starting on {}",
        node_cert.body.meta.name,
        our_id,
        config.listen
    );

    liteway_net::check_permissions()
        .map_err(|e| {
            log::error!("{}", e);
            anyhow::anyhow!("insufficient privileges: {}", e)
        })
        .context("check runtime privileges")?;

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        log::info!("shutdown requested");
        r.store(false, Ordering::SeqCst);
    })
    .context("install Ctrl-C handler")?;

    let mut overlay_networks = Vec::new();
    let (mut tun_reader, mut tun_writer): (Option<_>, Option<_>) = match config.interface.as_ref() {
        Some(iface) => {
            let mut tun = TunDevice::new(&iface.name, iface.mtu).with_context(|| {
                format!(
                    "create TUN interface '{}' with MTU {}",
                    iface.name, iface.mtu
                )
            })?;
            log::info!("tun interface '{}' created", tun.name());

            if let Some(ref addrs) = node_cert.body.addresses {
                tun.set_ip(&addrs.ip).with_context(|| {
                    format!("set TUN interface '{}' IP to {}", tun.name(), addrs.ip)
                })?;
                log::info!("set tun ip to {}", addrs.ip);

                match discovery_route_from_interface_addr(&addrs.ip) {
                    Ok(Some(route)) => {
                        let route_display = route.to_string();
                        if let Err(e) = liteway_net::add_route(&route_display, &iface.name) {
                            log::warn!(
                                "failed to add discovery route {} via {}: {}",
                                route_display,
                                iface.name,
                                e
                            );
                        } else {
                            log::info!("overlay network {} via {}", route_display, iface.name);
                        }
                        overlay_networks.push(route);
                    }
                    Ok(None) => {
                        if !config.lighthouses.is_empty() {
                            anyhow::bail!(
                                "node IP {} breaks lighthouse discovery; use a mesh prefix like 10.0.0.1/24",
                                addrs.ip
                            );
                        }
                    }
                    Err(e) => log::warn!("invalid interface address {}: {}", addrs.ip, e),
                }
            }

            tun.set_nonblock()
                .with_context(|| format!("set TUN interface '{}' nonblocking", tun.name()))?;
            let (r, w) = tun.split();
            (Some(r), Some(w))
        }
        None => (None, None),
    };

    let sock = {
        use socket2::{Domain, Protocol, Socket, Type};
        let domain = if config.listen.is_ipv6() {
            Domain::IPV6
        } else {
            Domain::IPV4
        };
        let sock = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))
            .with_context(|| format!("create UDP socket for {}", config.listen))?;
        if config.listen.is_ipv6() {
            sock.set_only_v6(false)
                .with_context(|| format!("allow IPv4-mapped addresses on {}", config.listen))?;
        }
        sock.set_nonblocking(true)
            .with_context(|| format!("set UDP socket {} nonblocking", config.listen))?;
        sock.bind(&config.listen.into())
            .with_context(|| format!("bind UDP socket to {}", config.listen))?;
        std::net::UdpSocket::from(sock)
    };
    liteway_net::configure_udp_socket(&sock).context("configure UDP socket")?;
    let actual_listen = sock.local_addr().context("read UDP socket local address")?;
    log::info!("listening on {}", actual_listen);
    if actual_listen.port() == 0 && (config.am_lighthouse || config.am_relay) {
        log::warn!(
            "ephemeral port detected but am_lighthouse/am_relay is set - lighthouse/relay nodes need a fixed port"
        );
    }
    let max_datagram = udp_payload_limit(&config, actual_listen);
    log::debug!("fragment UDP payload limit set to {} bytes", max_datagram);

    let peers: Arc<Mutex<HashMap<u32, PeerState>>> = Arc::new(Mutex::new(HashMap::new()));
    let pending: Arc<Mutex<HashMap<u32, PendingHandshake>>> = Arc::new(Mutex::new(HashMap::new()));
    let route_map: Arc<Mutex<RouteTable>> = Arc::new(Mutex::new(RouteTable::new()));
    let established: Arc<Mutex<HashSet<SocketAddr>>> = Arc::new(Mutex::new(HashSet::new()));
    let rx_sessions: Arc<Mutex<HashMap<u32, u32>>> = Arc::new(Mutex::new(HashMap::new()));
    let keepalive_pending: Arc<Mutex<HashMap<u32, KeepalivePending>>> =
        Arc::new(Mutex::new(HashMap::new()));

    // === Punch thread ===
    let pending_punch = pending.clone();
    let peers_punch = peers.clone();
    let established_punch = established.clone();
    let keepalive_pending_punch = keepalive_pending.clone();
    let nw_key_punch = network_key;
    let cfg_punch = config.clone();
    let sock_punch = sock.try_clone()?;
    let cert_punch: Cert = node_cert.clone();
    let sign_sk_punch = node_key.signing_secret_key.clone();
    let max_datagram_punch = max_datagram;

    let am_relay_punch = config.am_relay;
    let keepalive_punch = config.keepalive_punch;
    let keepalive_timeout_secs = config.keepalive_timeout_secs;
    thread::spawn(move || {
        let lighthouses = cfg_punch.lighthouses.clone();
        loop {
            for lh in &lighthouses {
                if let Ok(est) = established_punch.lock() {
                    if est.contains(&lh.address) {
                        if keepalive_punch {
                            send_lighthouse_keepalive(
                                lh,
                                &peers_punch,
                                &keepalive_pending_punch,
                                &sock_punch,
                                &nw_key_punch,
                                max_datagram_punch,
                                keepalive_timeout_secs,
                            );
                        } else {
                            log::debug!(
                                "skipping punch to {} - handshake already established",
                                lh.name
                            );
                        }
                        continue;
                    }
                }
                let init = handshake::create_handshake_1(
                    &cert_punch,
                    &sign_sk_punch,
                    &nw_key_punch,
                    am_relay_punch,
                );
                if let Err(e) = frag::send_fragmented(
                    &sock_punch,
                    &init.msg,
                    lh.address,
                    &nw_key_punch,
                    max_datagram_punch,
                ) {
                    log::warn!("punch to {} failed: {}", lh.name, e);
                    continue;
                }
                log::info!("punched to lighthouse {}", lh.name);

                if let Ok(mut pend) = pending_punch.lock() {
                    pend.insert(
                        init.my_rx_session_id,
                        PendingHandshake {
                            initiate: init,
                            addr: lh.address,
                            peer_id: None,
                            peer_name: lh.name.clone(),
                            sent_at: unix_now_secs(),
                            relay_attempted: false,
                        },
                    );
                }
            }
            if lighthouses.is_empty() {
                break;
            }
            thread::sleep(Duration::from_secs(cfg_punch.punch_interval_secs));
        }
    });

    // === Relay fallback thread ===
    let pending_fallback = pending.clone();
    let peers_fallback = peers.clone();
    let sock_fallback = sock.try_clone()?;
    let nw_key_fallback = network_key;
    let max_datagram_fallback = max_datagram;
    let relay_fallback_timeout_secs = config.relay_fallback_timeout_secs;
    let running_fallback = running.clone();
    thread::spawn(move || {
        while running_fallback.load(Ordering::SeqCst) {
            let now = unix_now_secs();
            let candidates = if let Ok(mut pending) = pending_fallback.lock() {
                let cleanup_after = relay_fallback_timeout_secs.saturating_mul(6).max(60);
                pending.retain(|_, p| now.saturating_sub(p.sent_at) <= cleanup_after);
                pending
                    .iter()
                    .filter_map(|(session_id, p)| {
                        let peer_id = p.peer_id?;
                        if p.relay_attempted
                            || now.saturating_sub(p.sent_at) < relay_fallback_timeout_secs
                        {
                            return None;
                        }
                        Some((
                            *session_id,
                            peer_id,
                            p.peer_name.clone(),
                            p.initiate.msg.clone(),
                        ))
                    })
                    .collect::<Vec<_>>()
            } else {
                Vec::new()
            };

            for (session_id, target_peer_id, target_name, msg) in candidates {
                let relay = if let Ok(peers) = peers_fallback.lock() {
                    if peers.contains_key(&target_peer_id) {
                        continue;
                    }
                    peers
                        .iter()
                        .find(|(id, peer)| peer.is_relay && **id != target_peer_id)
                        .map(|(id, peer)| (*id, peer.name.clone(), peer.addr))
                } else {
                    None
                };

                let Some((relay_id, relay_name, relay_addr)) = relay else {
                    log::debug!(
                        "relay fallback for {} ({}) delayed: no connected relay",
                        target_name,
                        target_peer_id
                    );
                    continue;
                };

                log::info!(
                    "direct handshake to {} ({}) timed out after {}s; trying relay {} ({})",
                    target_name,
                    target_peer_id,
                    relay_fallback_timeout_secs,
                    relay_name,
                    relay_id
                );
                log::debug!(
                    "sending relayed discovery handshake_1 to {} ({}) via {} ({})",
                    target_name,
                    target_peer_id,
                    relay_name,
                    relay_addr
                );
                if let Err(e) = frag::send_fragmented_to_peer(
                    &sock_fallback,
                    &msg,
                    relay_addr,
                    &nw_key_fallback,
                    max_datagram_fallback,
                    target_peer_id,
                ) {
                    log::warn!(
                        "relayed discovery handshake to {} ({}) via {} failed: {}",
                        target_name,
                        target_peer_id,
                        relay_name,
                        e
                    );
                    continue;
                }

                if let Ok(mut pending) = pending_fallback.lock() {
                    if let Some(p) = pending.get_mut(&session_id) {
                        if !p.relay_attempted {
                            p.addr = relay_addr;
                            p.sent_at = now;
                            p.relay_attempted = true;
                        }
                    }
                }
                log::debug!(
                    "sent relayed discovery handshake_1 to {} ({}) via {} ({})",
                    target_name,
                    target_peer_id,
                    relay_name,
                    relay_addr
                );
            }

            thread::sleep(Duration::from_millis(250));
        }
    });

    // === Cleanup thread ===
    let peers_clean = peers.clone();
    let route_clean = route_map.clone();
    let rx_sessions_clean = rx_sessions.clone();
    let running_clean = running.clone();
    thread::spawn(move || {
        while running_clean.load(Ordering::SeqCst) {
            thread::sleep(Duration::from_secs(CLEANUP_INTERVAL_SECS));
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            if let Ok(mut p) = peers_clean.lock() {
                let expired: Vec<u32> = p
                    .iter()
                    .filter(|(_, s)| now.saturating_sub(s.last_seen) > PEER_EXPIRY_SECS)
                    .map(|(id, _)| *id)
                    .collect();
                let mut expired_sessions = Vec::new();
                for id in &expired {
                    if let Some(peer) = p.remove(id) {
                        log::info!("removing expired peer {} ({})", id, peer.name);
                        expired_sessions.push(peer.rx_session_id);
                    }
                }
                if let Ok(mut r) = route_clean.lock() {
                    for id in &expired {
                        r.remove_peer(*id);
                    }
                }
                if let Ok(mut sessions) = rx_sessions_clean.lock() {
                    for session_id in expired_sessions {
                        sessions.remove(&session_id);
                    }
                }
            }
        }
    });

    // === Receive thread ===
    let peers_recv = peers.clone();
    let route_recv = route_map.clone();
    let rx_sessions_recv = rx_sessions.clone();
    let pending_recv = pending.clone();
    let established_recv = established.clone();
    let keepalive_pending_recv = keepalive_pending.clone();
    let iface_name = config.interface.as_ref().map(|i| i.name.clone());
    let nw_key_recv = network_key;
    let ca_vk_recv = ca_vk;
    let sock_recv = sock.try_clone()?;
    let cert_recv: Cert = node_cert.clone();
    let sign_sk_recv = node_key.signing_secret_key;
    let running_recv = running.clone();
    let am_lighthouse_recv = config.am_lighthouse;
    let am_relay_recv = config.am_relay;
    let max_datagram_recv = max_datagram;

    thread::spawn(move || {
        let mut recv_buf = [0u8; 65535];
        let mut frag_assembler = FragmentAssembler::new();

        let peers_add = peers_recv.clone();
        let route_add = route_recv.clone();
        let rx_sessions_add = rx_sessions_recv.clone();
        let add_peer = |id: u32,
                        mut sk: [u8; 32],
                        cert: &Cert,
                        addr: SocketAddr,
                        is_relay: bool,
                        tx_session_id: u32,
                        rx_session_id: u32| {
            let tx_key = packet::derive_traffic_key(&sk, our_id, id);
            let rx_key = packet::derive_traffic_key(&sk, id, our_id);
            sk.zeroize();
            let routes = authorized_peer_routes(cert);
            let mut old_rx_session_id = None;
            if let Ok(mut p) = peers_add.lock() {
                old_rx_session_id = p
                    .insert(
                        id,
                        PeerState {
                            name: cert.body.meta.name.clone(),
                            cert: cert.clone(),
                            tx_key,
                            rx_key,
                            addr,
                            is_relay,
                            tx_session_id,
                            rx_session_id,
                            tx_seq: 0,
                            rx_replay: ReplayWindow::new(),
                            last_seen: SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .unwrap()
                                .as_secs(),
                            routes: routes.clone(),
                        },
                    )
                    .map(|old| old.rx_session_id);
            }

            if let Ok(mut sessions) = rx_sessions_add.lock() {
                if let Some(old) = old_rx_session_id {
                    sessions.remove(&old);
                }
                if let Some(existing) = sessions.insert(rx_session_id, id) {
                    if existing != id {
                        log::warn!(
                            "rx session id collision: {} replaced peer {} with {}",
                            rx_session_id,
                            existing,
                            id
                        );
                    }
                }
            }

            if let Ok(mut r) = route_add.lock() {
                for route in &routes {
                    r.insert(*route, id);
                }
            }
            if let Some(ref iface) = iface_name {
                for route in &routes {
                    let route = route.to_string();
                    if let Err(e) = liteway_net::add_route(&route, iface) {
                        log::warn!("failed to add route {} via {}: {}", route, iface, e);
                    }
                }
            }
        };

        while running_recv.load(Ordering::SeqCst) {
            match sock_recv.recv_from(&mut recv_buf) {
                Ok((len, src)) => {
                    let data = &recv_buf[..len];
                    log::trace!("recv {} bytes from {}", len, src);
                    if data.is_empty() {
                        continue;
                    }

                    if let Some(header) = packet::network_header(data, &nw_key_recv) {
                        if header.dst_peer_id != 0 && header.dst_peer_id != our_id {
                            if am_relay_recv {
                                let relay_target = peers_recv.lock().ok().and_then(|peers| {
                                    peers
                                        .get(&header.dst_peer_id)
                                        .map(|peer| (peer.addr, peer.name.clone()))
                                });
                                if let Some((addr, name)) = relay_target {
                                    if let Err(e) = sock_recv.send_to(data, addr) {
                                        log::warn!(
                                            "relay to {} ({}) failed: {}",
                                            name,
                                            header.dst_peer_id,
                                            e
                                        );
                                    } else {
                                        log::trace!(
                                            "sent {} bytes to {} (relay to {} ({}) via masked header)",
                                            data.len(),
                                            addr,
                                            name,
                                            header.dst_peer_id
                                        );
                                    }
                                } else {
                                    log::debug!(
                                        "relay target {} unavailable for packet from {}",
                                        header.dst_peer_id,
                                        src
                                    );
                                }
                            } else {
                                log::debug!(
                                    "packet for {} ignored: relay mode disabled",
                                    header.dst_peer_id
                                );
                            }
                            continue;
                        }
                    }

                    let assembled = match frag_assembler.feed(src, data, &nw_key_recv) {
                        FeedResult::Complete(a) => {
                            log::debug!("reassembled fragmented message ({} bytes)", a.len());
                            Some(a)
                        }
                        FeedResult::Buffered => continue,
                        FeedResult::NotFragment => None,
                    };

                    let packet = assembled.as_deref().unwrap_or(data);
                    let packet_header = packet::network_header(packet, &nw_key_recv);

                    match packet_header.map(|header| header.kind) {
                        Some(handshake::KIND_HANDSHAKE_1) => {
                            match handshake::process_handshake_1(
                                packet,
                                &cert_recv,
                                &sign_sk_recv,
                                &nw_key_recv,
                                &ca_vk_recv,
                                am_relay_recv,
                            ) {
                                Ok(resp) => {
                                    let peer_id = node_id_from_cert(&resp.peer_cert);
                                    add_peer(
                                        peer_id,
                                        resp.session_key,
                                        &resp.peer_cert,
                                        src,
                                        resp.peer_is_relay,
                                        resp.peer_rx_session_id,
                                        resp.my_rx_session_id,
                                    );
                                    if let Ok(mut est) = established_recv.lock() {
                                        est.insert(src);
                                    }
                                    if let Err(e) = frag::send_fragmented_to_peer(
                                        &sock_recv,
                                        &resp.msg,
                                        src,
                                        &nw_key_recv,
                                        max_datagram_recv,
                                        peer_id,
                                    ) {
                                        log::warn!("send hs response failed: {}", e);
                                        continue;
                                    }
                                    log::info!(
                                        "handshake complete with {} ({})",
                                        resp.peer_cert.body.meta.name,
                                        src
                                    );
                                }
                                Err(e) => {
                                    log::debug!("handshake_1 from {} failed: {}", src, e);
                                }
                            }
                        }
                        Some(handshake::KIND_HANDSHAKE_2) => {
                            let initiate = {
                                if let Ok(mut pend) = pending_recv.lock() {
                                    packet_header.and_then(|header| {
                                        pend.remove(&header.session_id).map(|p| p.initiate)
                                    })
                                } else {
                                    None
                                }
                            };
                            match initiate {
                                Some(ih) => {
                                    match handshake::process_handshake_2(
                                        packet,
                                        ih,
                                        &nw_key_recv,
                                        &ca_vk_recv,
                                    ) {
                                        Ok(result) => {
                                            let peer_id = node_id_from_cert(&result.peer_cert);
                                            add_peer(
                                                peer_id,
                                                result.session_key,
                                                &result.peer_cert,
                                                src,
                                                result.peer_is_relay,
                                                result.peer_rx_session_id,
                                                result.my_rx_session_id,
                                            );
                                            if let Ok(mut est) = established_recv.lock() {
                                                est.insert(src);
                                            }
                                            log::info!(
                                                "handshake confirmed with {} ({})",
                                                result.peer_cert.body.meta.name,
                                                src
                                            );
                                        }
                                        Err(e) => {
                                            log::debug!("handshake_2 from {} failed: {}", src, e);
                                        }
                                    }
                                }
                                None => {
                                    log::warn!("no pending handshake for {}", src);
                                }
                            }
                        }
                        _ => {
                            let Some(header) = packet::network_header(packet, &nw_key_recv) else {
                                log::debug!("unknown encrypted packet from {}", src);
                                continue;
                            };

                            if header.dst_peer_id != 0 && header.dst_peer_id != our_id {
                                if am_relay_recv {
                                    let relay_target = peers_recv.lock().ok().and_then(|peers| {
                                        peers
                                            .get(&header.dst_peer_id)
                                            .map(|peer| (peer.addr, peer.name.clone()))
                                    });
                                    if let Some((addr, name)) = relay_target {
                                        if let Err(e) = sock_recv.send_to(packet, addr) {
                                            log::warn!(
                                                "relay to {} ({}) failed: {}",
                                                name,
                                                header.dst_peer_id,
                                                e
                                            );
                                        } else {
                                            log::trace!(
                                                "sent {} bytes to {} (relay to {} ({}) via masked header)",
                                                packet.len(),
                                                addr,
                                                name,
                                                header.dst_peer_id
                                            );
                                        }
                                    } else {
                                        log::debug!(
                                            "relay target {} unavailable for packet from {}",
                                            header.dst_peer_id,
                                            src
                                        );
                                    }
                                } else {
                                    log::debug!(
                                        "packet for {} ignored: relay mode disabled",
                                        header.dst_peer_id
                                    );
                                }
                                continue;
                            }

                            let peer_id = rx_sessions_recv
                                .lock()
                                .ok()
                                .and_then(|sessions| sessions.get(&header.session_id).copied());

                            let decoded = if let Some(peer_id) = peer_id {
                                if let Ok(mut peers) = peers_recv.lock() {
                                    let Some(peer) = peers.get_mut(&peer_id) else {
                                        log::debug!(
                                            "rx session {} points to missing peer {}",
                                            header.session_id,
                                            peer_id
                                        );
                                        continue;
                                    };
                                    let Some((decoded_header, body)) =
                                        packet::decrypt_packet(packet, &nw_key_recv, &peer.rx_key)
                                    else {
                                        log::debug!(
                                            "packet decrypt failed for {} ({})",
                                            peer.name,
                                            peer_id
                                        );
                                        continue;
                                    };
                                    if decoded_header != header {
                                        log::debug!("decoded header mismatch from {}", src);
                                        continue;
                                    }
                                    let seq = packet_seq(&body);
                                    if !peer.rx_replay.accept(seq) {
                                        log::warn!(
                                            "dropping replayed packet from {} ({}) seq {}",
                                            peer.name,
                                            peer_id,
                                            seq
                                        );
                                        continue;
                                    }
                                    peer.last_seen = unix_now_secs();
                                    Some((peer_id, body))
                                } else {
                                    None
                                }
                            } else {
                                log::debug!("no peer for rx session {}", header.session_id);
                                None
                            };

                            match decoded {
                                Some((peer_id, PacketBody::Data { ip_packet, .. })) => {
                                    let allowed = if let Ok(peers) = peers_recv.lock() {
                                        peers
                                            .get(&peer_id)
                                            .map(|peer| {
                                                peer_allows_ip_packet_source(peer, &ip_packet)
                                            })
                                            .unwrap_or(false)
                                    } else {
                                        false
                                    };
                                    if !allowed {
                                        log::warn!(
                                            "dropping data packet from {} with unauthorized source",
                                            peer_id
                                        );
                                        continue;
                                    }
                                    if let Some(ref mut tun_writer) = tun_writer {
                                        if let Err(e) = tun_writer.write(&ip_packet) {
                                            log::warn!("tun write failed: {}", e);
                                        }
                                    }
                                }
                                Some((peer_id, PacketBody::LighthouseQuery { target_ip, .. })) => {
                                    if !am_lighthouse_recv {
                                        log::debug!(
                                            "lighthouse query for {} ignored: lighthouse mode disabled",
                                            target_ip
                                        );
                                        continue;
                                    }

                                    let target_peer_id = route_recv
                                        .lock()
                                        .ok()
                                        .and_then(|routes| routes.lookup(target_ip));
                                    let responses = if let Ok(mut peers) = peers_recv.lock() {
                                        let target = target_peer_id.and_then(|id| {
                                            peers.get(&id).map(|peer| {
                                                (
                                                    id,
                                                    peer.addr,
                                                    peer.cert.clone(),
                                                    peer.is_relay,
                                                    peer.name.clone(),
                                                )
                                            })
                                        });

                                        let Some(requester_snapshot) =
                                            peers.get(&peer_id).map(|peer| {
                                                (
                                                    peer.addr,
                                                    peer.cert.clone(),
                                                    peer.is_relay,
                                                    peer.name.clone(),
                                                )
                                            })
                                        else {
                                            log::debug!(
                                                "lighthouse requester {} is no longer connected",
                                                peer_id
                                            );
                                            continue;
                                        };
                                        let (
                                            requester_addr,
                                            requester_cert,
                                            requester_is_relay,
                                            requester_name,
                                        ) = requester_snapshot;

                                        log::info!(
                                            "lighthouse query from peer {} ({}) for {}",
                                            peer_id,
                                            requester_name,
                                            target_ip
                                        );

                                        let mut responses = Vec::new();
                                        if let Some((
                                            found_id,
                                            found_addr,
                                            found_cert,
                                            found_is_relay,
                                            found_name,
                                        )) = target
                                        {
                                            log::info!(
                                                "lighthouse resolved query from {} ({}) for {} -> {} ({}) at {}",
                                                peer_id,
                                                requester_name,
                                                target_ip,
                                                found_name,
                                                found_id,
                                                found_addr
                                            );
                                            if let Some(requester) = peers.get_mut(&peer_id) {
                                                requester.tx_seq = requester.tx_seq.wrapping_add(1);
                                                let pkt =
                                                    packet::encrypt_lighthouse_response_packet(
                                                        requester.tx_seq,
                                                        peer_id,
                                                        requester.tx_session_id,
                                                        target_ip,
                                                        found_id,
                                                        found_addr,
                                                        &found_cert,
                                                        found_is_relay,
                                                        &nw_key_recv,
                                                        &requester.tx_key,
                                                    );
                                                responses.push((
                                                    requester.addr,
                                                    packet::serialize_packet(&pkt),
                                                ));
                                            }

                                            if found_id != peer_id {
                                                if let Some(requester_ip) =
                                                    primary_cert_ip(&requester_cert)
                                                {
                                                    if let Some(target_peer) =
                                                        peers.get_mut(&found_id)
                                                    {
                                                        target_peer.tx_seq =
                                                            target_peer.tx_seq.wrapping_add(1);
                                                        let pkt = packet::encrypt_lighthouse_response_packet(
                                                            target_peer.tx_seq,
                                                            found_id,
                                                            target_peer.tx_session_id,
                                                            requester_ip,
                                                            peer_id,
                                                            requester_addr,
                                                            &requester_cert,
                                                            requester_is_relay,
                                                            &nw_key_recv,
                                                            &target_peer.tx_key,
                                                        );
                                                        responses.push((
                                                            target_peer.addr,
                                                            packet::serialize_packet(&pkt),
                                                        ));
                                                        log::info!(
                                                            "lighthouse introduced {} ({}) to {} ({})",
                                                            requester_name,
                                                            peer_id,
                                                            found_name,
                                                            found_id
                                                        );
                                                    }
                                                } else {
                                                    log::warn!(
                                                        "lighthouse requester {} has no valid cert IP for reverse introduction",
                                                        peer_id
                                                    );
                                                }
                                            }
                                        } else {
                                            log::info!(
                                                "lighthouse has no route for {} requested by {} ({})",
                                                target_ip,
                                                peer_id,
                                                requester_name
                                            );
                                            if let Some(requester) = peers.get_mut(&peer_id) {
                                                requester.tx_seq = requester.tx_seq.wrapping_add(1);
                                                let pkt =
                                                    packet::encrypt_lighthouse_not_found_packet(
                                                        requester.tx_seq,
                                                        peer_id,
                                                        requester.tx_session_id,
                                                        target_ip,
                                                        &nw_key_recv,
                                                        &requester.tx_key,
                                                    );
                                                responses.push((
                                                    requester.addr,
                                                    packet::serialize_packet(&pkt),
                                                ));
                                            }
                                        }
                                        Some(responses)
                                    } else {
                                        None
                                    };

                                    for (addr, wire) in responses.unwrap_or_default() {
                                        if let Err(e) = frag::send_fragmented(
                                            &sock_recv,
                                            &wire,
                                            addr,
                                            &nw_key_recv,
                                            max_datagram_recv,
                                        ) {
                                            log::warn!(
                                                "lighthouse response to {} failed: {}",
                                                addr,
                                                e
                                            );
                                        }
                                    }
                                }
                                Some((
                                    _lighthouse_id,
                                    PacketBody::LighthouseResponse {
                                        target_ip,
                                        peer_id,
                                        peer_addr,
                                        peer_cert,
                                        peer_is_relay,
                                        ..
                                    },
                                )) => {
                                    if !peer_cert.verify(&ca_vk_recv) {
                                        log::warn!(
                                            "lighthouse returned invalid cert for {} at {}",
                                            target_ip,
                                            peer_addr
                                        );
                                        continue;
                                    }

                                    let cert_peer_id = node_id_from_cert(&peer_cert);
                                    if cert_peer_id != peer_id {
                                        log::warn!(
                                            "lighthouse returned peer id mismatch for {}: {} != {}",
                                            peer_cert.body.meta.name,
                                            peer_id,
                                            cert_peer_id
                                        );
                                        continue;
                                    }

                                    let peer_routes = authorized_peer_routes(&peer_cert);
                                    if !peer_routes.iter().any(|route| route.contains(target_ip)) {
                                        log::warn!(
                                            "lighthouse returned peer {} for {}, but its cert does not authorize that IP",
                                            peer_cert.body.meta.name,
                                            target_ip
                                        );
                                        continue;
                                    }

                                    log::info!(
                                        "lighthouse resolved {} -> {} ({}) at {}; starting handshake",
                                        target_ip,
                                        peer_cert.body.meta.name,
                                        peer_id,
                                        peer_addr
                                    );
                                    let init = handshake::create_handshake_1(
                                        &cert_recv,
                                        &sign_sk_recv,
                                        &nw_key_recv,
                                        am_relay_recv,
                                    );
                                    log::debug!(
                                        "sending direct discovery handshake_1 to {} ({}) at {}",
                                        peer_cert.body.meta.name,
                                        peer_id,
                                        peer_addr
                                    );
                                    if let Err(e) = frag::send_fragmented_to_peer(
                                        &sock_recv,
                                        &init.msg,
                                        peer_addr,
                                        &nw_key_recv,
                                        max_datagram_recv,
                                        peer_id,
                                    ) {
                                        log::warn!(
                                            "direct discovery handshake to {} failed: {}",
                                            peer_addr,
                                            e
                                        );
                                        continue;
                                    }
                                    log::debug!(
                                        "sent direct discovery handshake_1 to {} ({}) at {}",
                                        peer_cert.body.meta.name,
                                        peer_id,
                                        peer_addr
                                    );
                                    if let Ok(mut pend) = pending_recv.lock() {
                                        pend.insert(
                                            init.my_rx_session_id,
                                            PendingHandshake {
                                                initiate: init,
                                                addr: peer_addr,
                                                peer_id: Some(peer_id),
                                                peer_name: peer_cert.body.meta.name.clone(),
                                                sent_at: unix_now_secs(),
                                                relay_attempted: false,
                                            },
                                        );
                                    }
                                    if peer_is_relay {
                                        log::debug!(
                                            "discovered peer {} advertised relay capability",
                                            peer_id
                                        );
                                    }
                                }
                                Some((
                                    _lighthouse_id,
                                    PacketBody::LighthouseNotFound { target_ip, .. },
                                )) => {
                                    log::info!("lighthouse has no peer for {}", target_ip);
                                }
                                Some((peer_id, PacketBody::Keepalive { token, .. })) => {
                                    let response = if let Ok(mut peers) = peers_recv.lock() {
                                        peers.get_mut(&peer_id).map(|peer| {
                                            peer.tx_seq = peer.tx_seq.wrapping_add(1);
                                            let pkt = packet::encrypt_keepalive_ack_packet(
                                                peer.tx_seq,
                                                peer_id,
                                                peer.tx_session_id,
                                                token,
                                                &nw_key_recv,
                                                &peer.tx_key,
                                            );
                                            (peer.addr, packet::serialize_packet(&pkt))
                                        })
                                    } else {
                                        None
                                    };
                                    if let Some((addr, wire)) = response {
                                        if let Err(e) = frag::send_fragmented(
                                            &sock_recv,
                                            &wire,
                                            addr,
                                            &nw_key_recv,
                                            max_datagram_recv,
                                        ) {
                                            log::warn!(
                                                "keepalive ack to {} failed: {}",
                                                peer_id,
                                                e
                                            );
                                        } else {
                                            log::debug!(
                                                "keepalive ack to {} token {}",
                                                peer_id,
                                                token
                                            );
                                        }
                                    }
                                }
                                Some((peer_id, PacketBody::KeepaliveAck { token, .. })) => {
                                    if let Ok(mut pending) = keepalive_pending_recv.lock() {
                                        match pending.get(&peer_id) {
                                            Some(waiting) if waiting.token == token => {
                                                pending.remove(&peer_id);
                                                log::debug!(
                                                    "keepalive ack from {} token {}",
                                                    peer_id,
                                                    token
                                                );
                                            }
                                            Some(waiting) => {
                                                log::debug!(
                                                    "stale keepalive ack from {} token {} expected {}",
                                                    peer_id,
                                                    token,
                                                    waiting.token
                                                );
                                            }
                                            None => {
                                                log::debug!(
                                                    "unexpected keepalive ack from {} token {}",
                                                    peer_id,
                                                    token
                                                );
                                            }
                                        }
                                    }
                                }
                                Some((
                                    _peer_id,
                                    PacketBody::RelayForward {
                                        next_peer_id,
                                        inner_packet,
                                        ..
                                    },
                                )) => {
                                    if am_relay_recv {
                                        if let Ok(peers) = peers_recv.lock() {
                                            if let Some(peer) = peers.get(&next_peer_id) {
                                                if let Err(e) =
                                                    sock_recv.send_to(&inner_packet, peer.addr)
                                                {
                                                    log::warn!(
                                                        "relay to {} failed: {}",
                                                        next_peer_id,
                                                        e
                                                    );
                                                } else {
                                                    log::trace!(
                                                        "sent {} bytes to {} (relay-forward to {})",
                                                        inner_packet.len(),
                                                        peer.addr,
                                                        next_peer_id
                                                    );
                                                }
                                            }
                                        }
                                    } else {
                                        log::debug!(
                                            "relay-forward packet ignored: relay mode disabled"
                                        );
                                    }
                                }
                                Some((peer_id, PacketBody::Disconnect { .. })) => {
                                    let peer_info = if let Ok(p) = peers_recv.lock() {
                                        p.get(&peer_id).map(|s| {
                                            (s.name.clone(), s.routes.clone(), s.rx_session_id)
                                        })
                                    } else {
                                        None
                                    };
                                    log::info!(
                                        "peer {} ({}) disconnected",
                                        peer_info
                                            .as_ref()
                                            .map(|(n, _, _)| n.as_str())
                                            .unwrap_or("unknown"),
                                        peer_id
                                    );
                                    if let Ok(mut p) = peers_recv.lock() {
                                        p.remove(&peer_id);
                                    }
                                    if let Some((_, _, rx_session_id)) = peer_info.as_ref() {
                                        if let Ok(mut sessions) = rx_sessions_recv.lock() {
                                            sessions.remove(rx_session_id);
                                        }
                                    }
                                    if let Ok(mut r) = route_recv.lock() {
                                        r.remove_peer(peer_id);
                                    }
                                    if let Ok(mut est) = established_recv.lock() {
                                        est.remove(&src);
                                    }
                                    if let Some((_, routes, _)) = peer_info {
                                        if let Some(ref iface) = iface_name {
                                            for route in &routes {
                                                let route = route.to_string();
                                                if let Err(e) =
                                                    liteway_net::del_route(&route, iface)
                                                {
                                                    log::warn!(
                                                        "failed to delete route {} via {}: {}",
                                                        route,
                                                        iface,
                                                        e
                                                    );
                                                }
                                            }
                                        }
                                    }
                                }
                                None => {
                                    log::debug!("unknown encrypted packet from {}", src);
                                }
                            }
                        }
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                    frag_assembler.cleanup();
                }
                Err(e) => {
                    log::error!("recv error: {}", e);
                    thread::sleep(Duration::from_secs(1));
                }
            }
        }
    });

    // === Send path (main thread) ===
    let mut tun_buf = [0u8; 65535];
    let mut discovery_pending: HashMap<IpAddr, u64> = HashMap::new();
    let lighthouses_send = config.lighthouses.clone();
    while running.load(Ordering::SeqCst) {
        if let Some(ref mut tun_reader) = tun_reader {
            match tun_reader.read(&mut tun_buf) {
                Ok(n) if n > 0 => {
                    let ip_packet = &tun_buf[..n];
                    let dst_ip = parse_dest_ip(ip_packet);
                    log::trace!(
                        "tun packet dst {}",
                        dst_ip.map_or("?".into(), |ip| ip.to_string())
                    );
                    let Some(dst_ip) = dst_ip else {
                        log::debug!("unparsable ip in tun packet");
                        continue;
                    };
                    if dst_ip.is_multicast() {
                        log::trace!("skipping multicast dst {}", dst_ip);
                        continue;
                    }
                    if is_link_local(dst_ip) {
                        log::trace!("skipping link-local dst {}", dst_ip);
                        continue;
                    }
                    if is_overlay_broadcast(dst_ip, &overlay_networks) {
                        log::debug!("skipping overlay broadcast dst {}", dst_ip);
                        continue;
                    }
                    let peer_id = {
                        let Ok(route) = route_map.lock() else {
                            log::debug!("route_map lock failed");
                            continue;
                        };
                        route.lookup(dst_ip)
                    };
                    let Some(peer_id) = peer_id else {
                        log::debug!("no route for dst {}", dst_ip);
                        request_lighthouse_discovery(
                            dst_ip,
                            &lighthouses_send,
                            &peers,
                            &sock,
                            &network_key,
                            max_datagram,
                            &mut discovery_pending,
                        );
                        continue;
                    };
                    let Ok(mut peers) = peers.lock() else {
                        log::debug!("peers lock failed");
                        continue;
                    };
                    let Some(peer) = peers.get_mut(&peer_id) else {
                        log::debug!("no peer {} in peers map", peer_id);
                        continue;
                    };

                    log::debug!("routing {} -> {} ({})", dst_ip, peer.name, peer_id);
                    peer.tx_seq = peer.tx_seq.wrapping_add(1);
                    let pkt = packet::encrypt_data_packet(
                        peer.tx_seq,
                        peer_id,
                        peer.tx_session_id,
                        ip_packet,
                        &network_key,
                        &peer.tx_key,
                    );
                    let serialized = packet::serialize_packet(&pkt);
                    if let Err(e) = sock.send_to(&serialized, peer.addr) {
                        log::warn!("send_to {} failed: {}", peer_id, e);
                    } else {
                        log::trace!(
                            "sent {} bytes to {} (data to {} ({}) for {})",
                            serialized.len(),
                            peer.addr,
                            peer.name,
                            peer_id,
                            dst_ip
                        );
                    }
                }
                Ok(_) => {} // zero-length read, ignore
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(e) => {
                    log::error!("tun read error: {}", e);
                    thread::sleep(Duration::from_secs(1));
                }
            }
        } else {
            thread::sleep(Duration::from_millis(100));
        }
    }

    // Notify all peers of shutdown
    let disconnect_targets: Vec<DisconnectTarget> = if let Ok(peers) = peers.lock() {
        peers
            .iter()
            .map(|(id, p)| {
                log::info!("sending disconnect to peer {} ({})", p.name, id);
                DisconnectTarget {
                    peer_id: *id,
                    addr: p.addr,
                    tx_session_id: p.tx_session_id,
                    tx_key: p.tx_key,
                    seq: p.tx_seq.wrapping_add(1),
                }
            })
            .collect()
    } else {
        Vec::new()
    };
    for target in &disconnect_targets {
        let pkt = packet::encrypt_disconnect_packet(
            target.seq,
            target.peer_id,
            target.tx_session_id,
            &network_key,
            &target.tx_key,
        );
        let wire = packet::serialize_packet(&pkt);
        if let Ok(sent) = sock.send_to(&wire, target.addr) {
            log::trace!(
                "sent {} bytes to {} (disconnect to {})",
                sent,
                target.addr,
                target.peer_id
            );
        }
    }
    thread::sleep(Duration::from_millis(100));

    log::info!("shutting down");
    Ok(())
}

fn request_lighthouse_discovery(
    dst_ip: IpAddr,
    lighthouses: &[LighthouseConfig],
    peers: &Arc<Mutex<HashMap<u32, PeerState>>>,
    sock: &std::net::UdpSocket,
    network_key: &[u8; 32],
    max_datagram: usize,
    discovery_pending: &mut HashMap<IpAddr, u64>,
) {
    if lighthouses.is_empty() {
        return;
    }

    let now = unix_now_secs();
    if discovery_pending
        .get(&dst_ip)
        .is_some_and(|last| now.saturating_sub(*last) < DISCOVERY_RETRY_SECS)
    {
        return;
    }

    let mut packets = Vec::new();
    if let Ok(mut peers) = peers.lock() {
        for lighthouse in lighthouses {
            let Some((peer_id, peer)) = peers
                .iter_mut()
                .find(|(_, peer)| peer.addr == lighthouse.address)
            else {
                continue;
            };

            peer.tx_seq = peer.tx_seq.wrapping_add(1);
            let pkt = packet::encrypt_lighthouse_query_packet(
                peer.tx_seq,
                *peer_id,
                peer.tx_session_id,
                dst_ip,
                network_key,
                &peer.tx_key,
            );
            packets.push((
                lighthouse.name.clone(),
                peer.addr,
                packet::serialize_packet(&pkt),
            ));
        }
    }

    if packets.is_empty() {
        log::debug!("no connected lighthouse available for {}", dst_ip);
        return;
    }

    discovery_pending.insert(dst_ip, now);
    for (name, addr, wire) in packets {
        if let Err(e) = frag::send_fragmented(sock, &wire, addr, network_key, max_datagram) {
            log::warn!("lighthouse lookup {} via {} failed: {}", dst_ip, name, e);
        } else {
            log::info!(
                "requested lighthouse lookup {} via {} ({})",
                dst_ip,
                name,
                addr
            );
        }
    }
}

fn send_lighthouse_keepalive(
    lighthouse: &LighthouseConfig,
    peers: &Arc<Mutex<HashMap<u32, PeerState>>>,
    keepalive_pending: &Arc<Mutex<HashMap<u32, KeepalivePending>>>,
    sock: &std::net::UdpSocket,
    network_key: &[u8; 32],
    max_datagram: usize,
    timeout_secs: u64,
) {
    let now = unix_now_secs();
    let mut token_bytes = [0u8; 8];
    rand::rngs::ThreadRng::default().fill_bytes(&mut token_bytes);
    let token = u64::from_be_bytes(token_bytes);

    let packet = if let Ok(mut peers) = peers.lock() {
        let Some((peer_id, peer)) = peers
            .iter_mut()
            .find(|(_, peer)| peer.addr == lighthouse.address)
        else {
            log::debug!("no connected lighthouse peer for {}", lighthouse.name);
            return;
        };

        if let Ok(mut pending) = keepalive_pending.lock() {
            if let Some(old) = pending.get(peer_id) {
                if now.saturating_sub(old.sent_at) >= timeout_secs {
                    log::warn!(
                        "lighthouse keepalive timeout via {} ({}) token {}",
                        lighthouse.name,
                        lighthouse.address,
                        old.token
                    );
                }
            }
            pending.insert(
                *peer_id,
                KeepalivePending {
                    token,
                    sent_at: now,
                },
            );
        }

        peer.tx_seq = peer.tx_seq.wrapping_add(1);
        let pkt = packet::encrypt_keepalive_packet(
            peer.tx_seq,
            *peer_id,
            peer.tx_session_id,
            token,
            network_key,
            &peer.tx_key,
        );
        Some((packet::serialize_packet(&pkt), peer.addr))
    } else {
        None
    };

    let Some((wire, addr)) = packet else {
        return;
    };
    if let Err(e) = frag::send_fragmented(sock, &wire, addr, network_key, max_datagram) {
        log::warn!(
            "lighthouse keepalive via {} ({}) failed: {}",
            lighthouse.name,
            addr,
            e
        );
    } else {
        log::debug!(
            "sent lighthouse keepalive via {} ({}) token {}",
            lighthouse.name,
            addr,
            token
        );
    }
}

fn udp_payload_limit(config: &AppConfig, listen: SocketAddr) -> usize {
    let Some(iface) = config.interface.as_ref() else {
        return frag::DEFAULT_MAX_DATAGRAM;
    };

    let ip_udp_overhead = if listen.is_ipv6() { 48 } else { 28 };
    let mtu_payload = usize::from(iface.mtu).saturating_sub(ip_udp_overhead);
    mtu_payload.clamp(frag::MIN_DATAGRAM, frag::DEFAULT_MAX_DATAGRAM)
}

fn host_route(addr: &str) -> anyhow::Result<IpNetwork> {
    let network: IpNetwork = addr.parse()?;
    let route = match network.ip() {
        IpAddr::V4(ip) => IpNetwork::new(IpAddr::V4(ip), 32)?,
        IpAddr::V6(ip) => IpNetwork::new(IpAddr::V6(ip), 128)?,
    };
    Ok(route)
}

fn primary_cert_ip(cert: &Cert) -> Option<IpAddr> {
    cert.body
        .addresses
        .as_ref()
        .and_then(|addrs| addrs.ip.parse::<IpNetwork>().ok())
        .map(|network| network.ip())
}

fn discovery_route_from_interface_addr(addr: &str) -> anyhow::Result<Option<IpNetwork>> {
    let network: IpNetwork = addr.parse()?;
    let host_prefix = match network.ip() {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };
    if network.prefix() == 0 || network.prefix() >= host_prefix {
        return Ok(None);
    }
    Ok(Some(IpNetwork::new(network.network(), network.prefix())?))
}

fn authorized_peer_routes(cert: &Cert) -> Vec<IpNetwork> {
    let mut routes = Vec::new();
    let Some(ref addrs) = cert.body.addresses else {
        return routes;
    };

    match host_route(&addrs.ip) {
        Ok(route) => routes.push(route),
        Err(e) => log::warn!(
            "peer {} has invalid host route {}: {}",
            cert.body.meta.name,
            addrs.ip,
            e
        ),
    }

    for subnet in &addrs.subnets {
        let Ok(route) = subnet.parse::<IpNetwork>() else {
            log::warn!(
                "peer {} has invalid advertised subnet {}",
                cert.body.meta.name,
                subnet
            );
            continue;
        };
        if is_default_route(route) {
            log::warn!(
                "peer {} advertised default route {}; ignoring",
                cert.body.meta.name,
                route
            );
            continue;
        }
        if !route_granted_by_cert(cert, route) {
            log::warn!(
                "peer {} advertised unauthorized subnet {}; add group '{}{}' to allow it",
                cert.body.meta.name,
                route,
                ROUTE_GRANT_PREFIX,
                route
            );
            continue;
        }
        routes.push(route);
    }

    routes.sort_by_key(|route| (route.ip(), route.prefix()));
    routes.dedup();
    routes
}

fn route_granted_by_cert(cert: &Cert, route: IpNetwork) -> bool {
    for group in &cert.body.meta.groups {
        if group == ROUTE_ALL_GRANT {
            return true;
        }
        let Some(grant) = group.strip_prefix(ROUTE_GRANT_PREFIX) else {
            continue;
        };
        let Ok(granted_route) = grant.parse::<IpNetwork>() else {
            continue;
        };
        if granted_route.contains(route.ip()) && granted_route.prefix() <= route.prefix() {
            return true;
        }
    }
    false
}

fn is_default_route(route: IpNetwork) -> bool {
    route.prefix() == 0
}

fn packet_seq(body: &PacketBody) -> u64 {
    match body {
        PacketBody::Data { seq, .. }
        | PacketBody::RelayForward { seq, .. }
        | PacketBody::Disconnect { seq }
        | PacketBody::LighthouseQuery { seq, .. }
        | PacketBody::LighthouseResponse { seq, .. }
        | PacketBody::LighthouseNotFound { seq, .. }
        | PacketBody::Keepalive { seq, .. }
        | PacketBody::KeepaliveAck { seq, .. } => *seq,
    }
}

fn peer_allows_ip_packet_source(peer: &PeerState, packet: &[u8]) -> bool {
    let Some(src_ip) = parse_source_ip(packet) else {
        return false;
    };
    peer.routes.iter().any(|route| route.contains(src_ip))
}

fn parse_source_ip(packet: &[u8]) -> Option<IpAddr> {
    let version = packet.first()? >> 4;
    match version {
        4 if packet.len() >= 20 => {
            let mut octets = [0u8; 4];
            octets.copy_from_slice(&packet[12..16]);
            Some(IpAddr::V4(Ipv4Addr::from(octets)))
        }
        6 if packet.len() >= 40 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&packet[8..24]);
            Some(IpAddr::V6(Ipv6Addr::from(octets)))
        }
        _ => None,
    }
}

fn parse_node_cert(toml_str: &str) -> anyhow::Result<Cert> {
    Ok(toml::from_str::<Cert>(toml_str)?)
}

fn read_node_key(path: &str) -> anyhow::Result<NodeKeyFile> {
    let key_toml =
        std::fs::read_to_string(path).with_context(|| format!("read node key file '{path}'"))?;
    Ok(toml::from_str::<NodeKeyFile>(&key_toml)
        .with_context(|| format!("parse node key file '{path}'"))?)
}

fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn parse_dest_ip(packet: &[u8]) -> Option<IpAddr> {
    let version = packet.first()? >> 4;
    match version {
        4 if packet.len() >= 20 => {
            let mut octets = [0u8; 4];
            octets.copy_from_slice(&packet[16..20]);
            Some(IpAddr::V4(Ipv4Addr::from(octets)))
        }
        6 if packet.len() >= 40 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&packet[24..40]);
            Some(IpAddr::V6(Ipv6Addr::from(octets)))
        }
        _ => None,
    }
}

fn is_link_local(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.is_link_local(),
        IpAddr::V6(ip) => ip.is_unicast_link_local(),
    }
}

fn is_overlay_broadcast(ip: IpAddr, overlay_networks: &[IpNetwork]) -> bool {
    let IpAddr::V4(dst) = ip else {
        return false;
    };
    overlay_networks.iter().any(|network| {
        let IpAddr::V4(network_ip) = network.network() else {
            return false;
        };
        if network.prefix() >= 32 {
            return false;
        }
        let host_mask = u32::MAX >> network.prefix();
        let broadcast = Ipv4Addr::from(u32::from(network_ip) | host_mask);
        dst == broadcast
    })
}

#[derive(Parser)]
#[command(
    name = "litewayd",
    about = "Liteway L3 VPN daemon with PQC hybrid crypto"
)]
struct Cli {
    #[arg(short, long, default_value = "liteway.toml")]
    config: String,
}

struct PeerState {
    name: String,
    cert: Cert,
    tx_key: [u8; SESSION_KEY_LEN],
    rx_key: [u8; SESSION_KEY_LEN],
    addr: SocketAddr,
    is_relay: bool,
    tx_session_id: u32,
    rx_session_id: u32,
    tx_seq: u64,
    rx_replay: ReplayWindow,
    last_seen: u64,
    routes: Vec<IpNetwork>,
}

impl Drop for PeerState {
    fn drop(&mut self) {
        self.tx_key.zeroize();
        self.rx_key.zeroize();
    }
}

struct DisconnectTarget {
    peer_id: u32,
    addr: SocketAddr,
    tx_session_id: u32,
    tx_key: [u8; SESSION_KEY_LEN],
    seq: u64,
}

impl Drop for DisconnectTarget {
    fn drop(&mut self) {
        self.tx_key.zeroize();
    }
}

struct ReplayWindow {
    initialized: bool,
    highest: u64,
    seen: u64,
}

impl ReplayWindow {
    fn new() -> Self {
        Self {
            initialized: false,
            highest: 0,
            seen: 0,
        }
    }

    fn accept(&mut self, seq: u64) -> bool {
        if !self.initialized {
            self.initialized = true;
            self.highest = seq;
            self.seen = 1;
            return true;
        }

        if seq > self.highest {
            let shift = seq - self.highest;
            self.seen = if shift >= REPLAY_WINDOW_BITS {
                1
            } else {
                (self.seen << shift) | 1
            };
            self.highest = seq;
            return true;
        }

        let behind = self.highest - seq;
        if behind >= REPLAY_WINDOW_BITS {
            return false;
        }
        let bit = 1u64 << behind;
        if self.seen & bit != 0 {
            return false;
        }
        self.seen |= bit;
        true
    }
}
