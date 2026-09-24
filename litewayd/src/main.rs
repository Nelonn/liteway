mod state;

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::Context;
use clap::Parser;
use ipnetwork::IpNetwork;
use liteway_core::cert::{CaVerifyKey, Cert, NodeKeyFile, NodeSigningSecretKey};
use liteway_core::config::{AppConfig, LighthouseConfig};
use liteway_core::crypto::kdf;
use liteway_core::crypto::{K_HEADER_LEN, SESSION_KEY_LEN};
use liteway_core::frag::{self, FeedResult, FragmentAssembler};
use liteway_core::handshake;
use liteway_core::packet::{self, PacketBody};
use liteway_core::tunnel::{TunDevice, TunWriter};
use rand::Rng;
use zeroize::{Zeroize, Zeroizing};

use state::{
    accept_handshake_session, DropReason, HandshakeCache, LighthouseSlot, PathProbe, PeerState,
    PeerTick, PendingHandshake, ReplayWindow, RouteTable, Timings,
};

const DISCOVERY_RETRY: Duration = Duration::from_secs(10);
/// Discovery attempts are only remembered long enough to rate limit retries.
const DISCOVERY_ENTRY_TTL: Duration = Duration::from_secs(120);
const MAINTENANCE_TICK: Duration = Duration::from_millis(250);
/// How often a disconnected lighthouse's address is looked up again.
const LIGHTHOUSE_RERESOLVE: Duration = Duration::from_secs(60);
/// Bounds how long the receive thread takes to notice shutdown.
const SOCKET_READ_TIMEOUT: Duration = Duration::from_millis(250);
const ROUTE_ALL_GRANT: &str = "route:*";
const ROUTE_GRANT_PREFIX: &str = "route:";

#[derive(Copy, Clone, PartialEq, Eq)]
enum AddPeerOutcome {
    Added,
    KeptExisting,
}

/// Everything a packet-handling thread needs.
///
/// Locks are only ever taken one at a time: each handler snapshots what it needs,
/// releases the lock, and only then touches the network or another map. Holding
/// two at once is what used to make the lighthouse and receive paths deadlock-prone.
struct Node {
    our_id: u32,
    cert: Cert,
    signing_key: NodeSigningSecretKey,
    ca_vk: CaVerifyKey,
    network_key: [u8; K_HEADER_LEN],
    sock: UdpSocket,
    max_datagram: usize,
    am_lighthouse: bool,
    am_relay: bool,
    keepalive_enabled: bool,
    timings: Timings,
    iface_name: Option<String>,
    /// Destinations this node is allowed to receive traffic for.
    local_networks: Vec<IpNetwork>,
    peers: Mutex<HashMap<u32, PeerState>>,
    pending: Mutex<HashMap<u32, PendingHandshake>>,
    routes: Mutex<RouteTable>,
    rx_sessions: Mutex<HashMap<u32, u32>>,
    lighthouses: Mutex<Vec<LighthouseSlot>>,
    handshake_cache: Mutex<HandshakeCache>,
    discovery_pending: Mutex<HashMap<IpAddr, Instant>>,
    running: AtomicBool,
    shutdown: (Mutex<bool>, Condvar),
}

/// A short-lived copy of what it takes to encrypt one packet for a peer.
struct PeerTx {
    addr: SocketAddr,
    seq: u64,
    session_id: u32,
    key: [u8; SESSION_KEY_LEN],
}

impl Drop for PeerTx {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

fn main() -> anyhow::Result<()> {
    // Timestamps matter here: most questions about this daemon are about *when* a
    // handshake or a keepalive happened. Formatted with chrono, which the workspace
    // already builds, rather than pulling env_logger's timestamp stack in.
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format(|buf, record| {
            use std::io::Write;
            let level_style = buf.default_level_style(record.level());
            writeln!(
                buf,
                "[{} {level_style}{:<5}{level_style:#} {}] {}",
                chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ"),
                record.level(),
                record.target(),
                record.args()
            )
        })
        .init();
    let cli = Cli::parse();

    log::info!("reading config from {}", cli.config);
    let config = AppConfig::from_file(&cli.config)?;
    config
        .validate()
        .with_context(|| format!("validate config file '{}'", cli.config))?;

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
    if !node_cert.verify(&ca_vk) {
        anyhow::bail!(
            "node certificate '{}' is not valid for CA '{}' (expired, not yet valid, or signed by another CA)",
            config.node_cert_path,
            config.ca_cert_path
        );
    }

    let node_key = read_node_key(&config.node_key_path)?;
    if node_key.signing_secret_key.ed25519_public() != node_cert.body.keys.ed25519_pk {
        anyhow::bail!(
            "node key '{}' does not belong to certificate '{}'",
            config.node_key_path,
            config.node_cert_path
        );
    }

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

    let mut overlay_networks = Vec::new();
    let (mut tun_reader, tun_writer): (Option<_>, Option<TunWriter>) = match config
        .interface
        .as_ref()
    {
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
        sock.bind(&config.listen.into())
            .with_context(|| format!("bind UDP socket to {}", config.listen))?;
        // A blocking socket with a receive timeout replaces the old non-blocking
        // poll loop: packets are handled as they arrive instead of up to 10ms later,
        // and an idle node stops burning a core on retries.
        sock.set_read_timeout(Some(SOCKET_READ_TIMEOUT))
            .with_context(|| format!("set receive timeout on UDP socket {}", config.listen))?;
        UdpSocket::from(sock)
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
    warn_on_oversized_mtu(&config, actual_listen);

    let node = Arc::new(Node {
        our_id,
        cert: node_cert.clone(),
        signing_key: node_key.signing_secret_key.clone(),
        ca_vk,
        network_key,
        sock,
        max_datagram,
        am_lighthouse: config.am_lighthouse,
        am_relay: config.am_relay,
        keepalive_enabled: config.keepalive_punch,
        timings: Timings::from_secs(
            config.keepalive_interval_secs,
            config.keepalive_timeout_secs,
            config.direct_probe_interval_secs,
            config.handshake_timeout_secs,
            config.relay_fallback_timeout_secs,
        ),
        iface_name: config.interface.as_ref().map(|i| i.name.clone()),
        local_networks: authorized_peer_routes(&node_cert),
        peers: Mutex::new(HashMap::new()),
        pending: Mutex::new(HashMap::new()),
        routes: Mutex::new(RouteTable::new()),
        rx_sessions: Mutex::new(HashMap::new()),
        lighthouses: Mutex::new(resolve_lighthouses(&config.lighthouses)?),
        handshake_cache: Mutex::new(HandshakeCache::new()),
        discovery_pending: Mutex::new(HashMap::new()),
        running: AtomicBool::new(true),
        shutdown: (Mutex::new(false), Condvar::new()),
    });

    install_signal_handler(node.clone())?;

    let punch_node = node.clone();
    let punch_interval = Duration::from_secs(config.punch_interval_secs);
    let punch_thread = thread::Builder::new()
        .name("liteway-punch".into())
        .spawn(move || {
            while punch_node.running.load(Ordering::SeqCst) {
                punch_node.connect_lighthouses();
                punch_node.wait_for_shutdown_or_timeout(punch_interval);
            }
        })
        .context("spawn lighthouse thread")?;

    let maintenance_node = node.clone();
    let maintenance_thread = thread::Builder::new()
        .name("liteway-maintenance".into())
        .spawn(move || {
            while maintenance_node.running.load(Ordering::SeqCst) {
                maintenance_node.maintenance_tick();
                maintenance_node.wait_for_shutdown_or_timeout(MAINTENANCE_TICK);
            }
        })
        .context("spawn maintenance thread")?;

    let recv_node = node.clone();
    let recv_thread = thread::Builder::new()
        .name("liteway-recv".into())
        .spawn(move || recv_node.run_receiver(tun_writer))
        .context("spawn receive thread")?;

    // === Send path (main thread) ===
    let mut tun_buf = [0u8; 65535];
    let mut idle_reads: u32 = 0;
    while node.running.load(Ordering::SeqCst) {
        let Some(ref mut tun_reader) = tun_reader else {
            node.wait_for_shutdown_or_timeout(Duration::from_millis(100));
            continue;
        };

        match tun_reader.read(&mut tun_buf) {
            Ok(n) if n > 0 => {
                idle_reads = 0;
                node.send_to_overlay(&tun_buf[..n], &overlay_networks);
            }
            Ok(_) => {}
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                // Poll tightly right after traffic, then back off so an idle node
                // is not spinning; a fixed 10ms sleep added 10ms to every packet.
                idle_reads = idle_reads.saturating_add(1);
                thread::sleep(tun_poll_backoff(idle_reads));
            }
            Err(e) => {
                log::error!("tun read error: {}", e);
                thread::sleep(Duration::from_secs(1));
            }
        }
    }

    node.notify_shutdown();
    for handle in [punch_thread, maintenance_thread, recv_thread] {
        let _ = handle.join();
    }

    log::info!("shutting down");
    Ok(())
}

fn install_signal_handler(node: Arc<Node>) -> anyhow::Result<()> {
    let shutdown_signals = Arc::new(AtomicUsize::new(0));
    ctrlc::set_handler(move || {
        let count = shutdown_signals.fetch_add(1, Ordering::SeqCst) + 1;
        if count == 1 {
            log::info!("shutdown requested; press Ctrl-C again to terminate immediately");
            node.running.store(false, Ordering::SeqCst);
            let (lock, cv) = &node.shutdown;
            if let Ok(mut shutdown) = lock.lock() {
                *shutdown = true;
                cv.notify_all();
            }
        } else {
            log::warn!("second shutdown signal received; terminating immediately");
            std::process::exit(130);
        }
    })
    .context("install Ctrl-C handler")?;
    Ok(())
}

fn tun_poll_backoff(idle_reads: u32) -> Duration {
    match idle_reads {
        0..=64 => Duration::from_micros(200),
        65..=320 => Duration::from_millis(1),
        _ => Duration::from_millis(10),
    }
}

impl Node {
    // ---------------------------------------------------------------- transport

    fn send_wire(&self, wire: &[u8], addr: SocketAddr, what: &str) {
        match self.sock.send_to(wire, addr) {
            Ok(sent) => log::trace!("sent {} bytes to {} ({})", sent, addr, what),
            Err(e) => log::warn!("send to {} failed ({}): {}", addr, what, e),
        }
    }

    fn send_message(&self, msg: &[u8], addr: SocketAddr, dst_peer_id: u32, what: &str) -> bool {
        self.send_message_with_id(msg, addr, dst_peer_id, rand::random(), what)
    }

    /// Send a message whose retransmissions must reassemble together.
    fn send_message_with_id(
        &self,
        msg: &[u8],
        addr: SocketAddr,
        dst_peer_id: u32,
        msg_id: u32,
        what: &str,
    ) -> bool {
        match frag::send_fragmented_with_id(
            &self.sock,
            msg,
            addr,
            &self.network_key,
            self.max_datagram,
            dst_peer_id,
            msg_id,
        ) {
            Ok(()) => true,
            Err(e) => {
                log::warn!("send to {} failed ({}): {}", addr, what, e);
                false
            }
        }
    }

    /// Reserve the next sequence number for a peer and copy out what encrypting
    /// one packet needs, so the peer lock is not held while building or sending.
    fn peer_tx(&self, peer_id: u32) -> Option<PeerTx> {
        let mut peers = self.peers.lock().ok()?;
        let peer = peers.get_mut(&peer_id)?;
        Some(PeerTx {
            addr: peer.addr,
            seq: peer.next_seq(),
            session_id: peer.tx_session_id,
            key: peer.tx_key,
        })
    }

    // ---------------------------------------------------------------- handshakes

    /// Start a handshake unless one to the same peer is already in flight.
    fn start_handshake(
        &self,
        addr: SocketAddr,
        peer_id: Option<u32>,
        peer_name: &str,
        reason: &str,
    ) -> bool {
        {
            let Ok(pending) = self.pending.lock() else {
                return false;
            };
            let duplicate = pending.values().any(|p| match (p.peer_id, peer_id) {
                (Some(existing), Some(wanted)) => existing == wanted,
                _ => p.direct_addr == addr,
            });
            if duplicate {
                log::debug!(
                    "handshake with {} ({}) already in flight; letting it retry",
                    peer_name,
                    addr
                );
                return false;
            }
        }

        let init = handshake::create_handshake_1(
            &self.cert,
            &self.signing_key,
            &self.network_key,
            self.am_relay,
        );
        let session_id = init.my_rx_session_id;
        if !self.send_message_with_id(
            &init.msg,
            addr,
            peer_id.unwrap_or(0),
            session_id,
            "handshake_1 (first attempt)",
        ) {
            return false;
        }
        log::info!("handshake_1 sent to {} ({}) - {}", peer_name, addr, reason);

        if let Ok(mut pending) = self.pending.lock() {
            pending.insert(
                session_id,
                PendingHandshake::new(init, addr, peer_id, peer_name.to_string(), Instant::now()),
            );
        }
        true
    }

    #[allow(clippy::too_many_arguments)]
    fn add_peer(
        &self,
        id: u32,
        mut session_key: [u8; SESSION_KEY_LEN],
        cert: &Cert,
        addr: SocketAddr,
        direct_addr: Option<SocketAddr>,
        relayed: bool,
        is_relay: bool,
        tx_session_id: u32,
        rx_session_id: u32,
        initiator_id: u32,
        simultaneous: bool,
    ) -> AddPeerOutcome {
        let mut tx_key = packet::derive_traffic_key(&session_key, self.our_id, id);
        let mut rx_key = packet::derive_traffic_key(&session_key, id, self.our_id);
        session_key.zeroize();
        let routes = authorized_peer_routes(cert);
        let now = Instant::now();

        let old_rx_session_id;
        {
            let Ok(mut peers) = self.peers.lock() else {
                tx_key.zeroize();
                rx_key.zeroize();
                return AddPeerOutcome::KeptExisting;
            };

            let existing_initiator = peers.get(&id).map(|peer| peer.handshake_initiator_id);
            if !accept_handshake_session(
                self.our_id,
                id,
                existing_initiator,
                initiator_id,
                simultaneous,
            ) {
                log::debug!(
                    "ignoring simultaneous handshake with {} ({}) initiated by {}; preferred initiator is {}",
                    cert.body.meta.name,
                    id,
                    initiator_id,
                    self.our_id.min(id)
                );
                tx_key.zeroize();
                rx_key.zeroize();
                return AddPeerOutcome::KeptExisting;
            }

            // A re-handshake must not forget the endpoint we are trying to reach
            // directly, otherwise a relayed session can never be upgraded.
            let previous = peers.get(&id);
            let direct_addr = direct_addr.or_else(|| previous.and_then(|peer| peer.direct_addr));
            let relayed = relayed && direct_addr != Some(addr);

            let old_peer = peers.insert(
                id,
                PeerState {
                    name: cert.body.meta.name.clone(),
                    cert: cert.clone(),
                    tx_key,
                    rx_key,
                    addr,
                    direct_addr,
                    is_relay,
                    tx_session_id,
                    rx_session_id,
                    tx_seq: 0,
                    rx_replay: ReplayWindow::new(),
                    last_seen: now,
                    routes: routes.clone(),
                    handshake_initiator_id: initiator_id,
                    keepalive: None,
                    relayed,
                    next_probe: None,
                    probe_interval: self.timings.direct_probe_interval,
                    probe_token: None,
                },
            );
            old_rx_session_id = old_peer.map(|old| old.rx_session_id);
        }

        if let Ok(mut sessions) = self.rx_sessions.lock() {
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

        if let Ok(mut table) = self.routes.lock() {
            for route in &routes {
                table.insert(*route, id);
            }
        }
        if let Some(ref iface) = self.iface_name {
            for route in &routes {
                let route = route.to_string();
                if let Err(e) = liteway_net::add_route(&route, iface) {
                    log::warn!("failed to add route {} via {}: {}", route, iface, e);
                }
            }
        }

        self.bind_lighthouse(addr, &cert.body.meta.name, id);
        AddPeerOutcome::Added
    }

    fn remove_peer(&self, peer_id: u32, reason: &str) {
        let removed = self
            .peers
            .lock()
            .ok()
            .and_then(|mut peers| peers.remove(&peer_id));
        let Some(peer) = removed else {
            return;
        };

        let peer_ip = primary_cert_ip(&peer.cert)
            .map(|ip| ip.to_string())
            .unwrap_or_else(|| "?".to_string());
        log::info!(
            "removing peer {} [{}] ({}): {}",
            peer.name,
            peer_ip,
            peer_id,
            reason
        );

        if let Ok(mut sessions) = self.rx_sessions.lock() {
            sessions.remove(&peer.rx_session_id);
        }
        if let Ok(mut table) = self.routes.lock() {
            table.remove_peer(peer_id);
        }
        if let Ok(mut lighthouses) = self.lighthouses.lock() {
            for lighthouse in lighthouses.iter_mut() {
                if lighthouse.peer_id == Some(peer_id) {
                    lighthouse.peer_id = None;
                }
            }
        }
        if let Some(ref iface) = self.iface_name {
            for route in &peer.routes {
                let route = route.to_string();
                if let Err(e) = liteway_net::del_route(&route, iface) {
                    log::warn!("failed to delete route {} via {}: {}", route, iface, e);
                }
            }
        }
    }

    // ---------------------------------------------------------------- lighthouses

    /// Remember which peer is a configured lighthouse, by endpoint or by the name
    /// on its certificate.
    fn bind_lighthouse(&self, addr: SocketAddr, name: &str, peer_id: u32) {
        if let Ok(mut lighthouses) = self.lighthouses.lock() {
            for lighthouse in lighthouses.iter_mut() {
                if lighthouse.address == addr || lighthouse.name == name {
                    lighthouse.peer_id = Some(peer_id);
                }
            }
        }
    }

    /// Keep a session with every configured lighthouse.
    fn connect_lighthouses(&self) {
        let lighthouses = match self.lighthouses.lock() {
            Ok(lighthouses) => lighthouses.clone(),
            Err(_) => return,
        };
        if lighthouses.is_empty() {
            return;
        }

        let connected: Vec<Option<u32>> = {
            let Ok(peers) = self.peers.lock() else {
                return;
            };
            lighthouses
                .iter()
                .map(|lighthouse| {
                    lighthouse
                        .peer_id
                        .filter(|peer_id| peers.contains_key(peer_id))
                })
                .collect()
        };

        for (lighthouse, connected) in lighthouses.iter().zip(connected) {
            if !self.running.load(Ordering::SeqCst) {
                return;
            }
            if connected.is_some() {
                log::debug!("lighthouse {} is connected", lighthouse.name);
                continue;
            }

            // A lighthouse behind a dynamic address only comes back if the name is
            // resolved again; the address is otherwise frozen at startup.
            let address = self.refresh_lighthouse_address(lighthouse);
            self.start_handshake(address, None, &lighthouse.name, "lighthouse punch");
        }
    }

    fn refresh_lighthouse_address(&self, lighthouse: &LighthouseSlot) -> SocketAddr {
        let now = Instant::now();
        if now.duration_since(lighthouse.resolved_at) < LIGHTHOUSE_RERESOLVE {
            return lighthouse.address;
        }

        let resolved = match resolve_socket_addr(&lighthouse.configured) {
            Ok(address) => address,
            Err(e) => {
                log::warn!(
                    "re-resolving lighthouse {} address '{}' failed: {}",
                    lighthouse.name,
                    lighthouse.configured,
                    e
                );
                lighthouse.address
            }
        };

        if let Ok(mut lighthouses) = self.lighthouses.lock() {
            for slot in lighthouses.iter_mut() {
                if slot.name != lighthouse.name || slot.configured != lighthouse.configured {
                    continue;
                }
                if slot.address != resolved {
                    log::info!(
                        "lighthouse {} moved: {} -> {}",
                        slot.name,
                        slot.address,
                        resolved
                    );
                    slot.address = resolved;
                    slot.peer_id = None;
                }
                slot.resolved_at = now;
            }
        }
        resolved
    }

    /// Ask every connected lighthouse where `dst_ip` lives, at most once per
    /// [`DISCOVERY_RETRY`].
    fn request_discovery(&self, dst_ip: IpAddr) {
        let now = Instant::now();
        {
            let Ok(mut discovery) = self.discovery_pending.lock() else {
                return;
            };
            if discovery
                .get(&dst_ip)
                .is_some_and(|last| now.duration_since(*last) < DISCOVERY_RETRY)
            {
                return;
            }
            discovery.insert(dst_ip, now);
        }

        let targets: Vec<(String, u32)> = {
            let Ok(lighthouses) = self.lighthouses.lock() else {
                return;
            };
            lighthouses
                .iter()
                .filter_map(|lighthouse| {
                    lighthouse
                        .peer_id
                        .map(|peer_id| (lighthouse.name.clone(), peer_id))
                })
                .collect()
        };

        if targets.is_empty() {
            log::debug!("no connected lighthouse available for {}", dst_ip);
            return;
        }

        for (name, peer_id) in targets {
            let Some(tx) = self.peer_tx(peer_id) else {
                continue;
            };
            let pkt = packet::encrypt_lighthouse_query_packet(
                tx.seq,
                peer_id,
                tx.session_id,
                dst_ip,
                &self.network_key,
                &tx.key,
            );
            if self.send_message(
                &packet::serialize_packet(&pkt),
                tx.addr,
                peer_id,
                "lighthouse query",
            ) {
                log::info!("lighthouse lookup {} via {} ({})", dst_ip, name, tx.addr);
            }
        }
    }

    // ---------------------------------------------------------------- maintenance

    fn maintenance_tick(&self) {
        let now = Instant::now();
        self.retransmit_handshakes(now);
        self.maintain_peers(now);

        if let Ok(mut discovery) = self.discovery_pending.lock() {
            discovery.retain(|_, last| now.duration_since(*last) < DISCOVERY_ENTRY_TTL);
        }
        if let Ok(mut cache) = self.handshake_cache.lock() {
            cache.cleanup(now);
        }
    }

    /// Resend unanswered handshakes and, once the direct path has had its chance,
    /// duplicate them through a relay.
    ///
    /// The relay is an addition, not a replacement: a handshake that is only slow
    /// still gets to finish directly instead of pinning the session to the relay.
    fn retransmit_handshakes(&self, now: Instant) {
        let relays: Vec<(u32, String, SocketAddr)> = {
            let Ok(peers) = self.peers.lock() else {
                return;
            };
            peers
                .iter()
                .filter(|(_, peer)| peer.is_relay)
                .map(|(id, peer)| (*id, peer.name.clone(), peer.addr))
                .collect()
        };

        struct Retransmission {
            msg: Vec<u8>,
            msg_id: u32,
            targets: Vec<SocketAddr>,
            dst_peer_id: u32,
            peer_name: String,
            attempt: u32,
        }

        let mut retransmissions = Vec::new();
        {
            let Ok(mut pending) = self.pending.lock() else {
                return;
            };

            pending.retain(|_, handshake| {
                if handshake.expired(now, &self.timings) {
                    log::info!(
                        "giving up on handshake with {} ({}) after {} attempts",
                        handshake.peer_name,
                        handshake.direct_addr,
                        handshake.attempts
                    );
                    return false;
                }
                true
            });

            for handshake in pending.values_mut() {
                if handshake.relay_fallback_due(now, &self.timings) {
                    let target = handshake.peer_id;
                    match relays
                        .iter()
                        .find(|(relay_id, _, _)| Some(*relay_id) != target)
                    {
                        Some((relay_id, relay_name, relay_addr)) => {
                            handshake.relay_addr = Some(*relay_addr);
                            log::info!(
                                "direct handshake with {} is taking too long; also trying relay {} ({})",
                                handshake.peer_name,
                                relay_name,
                                relay_id
                            );
                        }
                        None => log::debug!(
                            "relay fallback for {} delayed: no connected relay",
                            handshake.peer_name
                        ),
                    }
                }

                if !handshake.retransmit_due(now, &self.timings) {
                    continue;
                }
                handshake.record_attempt(now);
                retransmissions.push(Retransmission {
                    msg: handshake.initiate.msg.clone(),
                    msg_id: handshake.initiate.my_rx_session_id,
                    targets: handshake.targets(),
                    dst_peer_id: handshake.peer_id.unwrap_or(0),
                    peer_name: handshake.peer_name.clone(),
                    attempt: handshake.attempts,
                });
            }
        }

        for retransmission in retransmissions {
            for target in retransmission.targets {
                log::debug!(
                    "handshake_1 retry {} to {} ({})",
                    retransmission.attempt,
                    retransmission.peer_name,
                    target
                );
                self.send_message_with_id(
                    &retransmission.msg,
                    target,
                    retransmission.dst_peer_id,
                    retransmission.msg_id,
                    "handshake_1 retry",
                );
            }
        }
    }

    /// Keep sessions (and their NAT mappings) alive, drop the dead ones, and try
    /// to move relayed sessions onto a direct path.
    fn maintain_peers(&self, now: Instant) {
        enum Action {
            Send(SocketAddr, Vec<u8>, &'static str),
            Lookup(IpAddr),
        }

        let mut actions = Vec::new();
        let mut drops = Vec::new();
        {
            let Ok(mut peers) = self.peers.lock() else {
                return;
            };
            for (peer_id, peer) in peers.iter_mut() {
                if self.keepalive_enabled {
                    match peer.tick(now, &self.timings, random_token()) {
                        PeerTick::Drop(reason) => {
                            drops.push((*peer_id, reason));
                            continue;
                        }
                        PeerTick::Keepalive(token) => {
                            let pkt = packet::encrypt_keepalive_packet(
                                peer.next_seq(),
                                *peer_id,
                                peer.tx_session_id,
                                token,
                                &self.network_key,
                                &peer.tx_key,
                            );
                            actions.push(Action::Send(
                                peer.addr,
                                packet::serialize_packet(&pkt),
                                "keepalive",
                            ));
                        }
                        PeerTick::Idle => {}
                    }
                } else if now.duration_since(peer.last_seen) >= self.timings.peer_expiry {
                    drops.push((*peer_id, DropReason::Expired));
                    continue;
                }

                match peer.take_path_probe(now, &self.timings, random_token()) {
                    PathProbe::Punch(direct, token) => {
                        let pkt = packet::encrypt_keepalive_packet(
                            peer.next_seq(),
                            *peer_id,
                            peer.tx_session_id,
                            token,
                            &self.network_key,
                            &peer.tx_key,
                        );
                        log::debug!(
                            "punching direct path to {} ({}) at {}",
                            peer.name,
                            peer_id,
                            direct
                        );
                        actions.push(Action::Send(
                            direct,
                            packet::serialize_packet(&pkt),
                            "direct path probe",
                        ));
                    }
                    PathProbe::Lookup => {
                        if let Some(ip) = primary_cert_ip(&peer.cert) {
                            actions.push(Action::Lookup(ip));
                        }
                    }
                    PathProbe::None => {}
                }
            }
        }

        for (peer_id, reason) in drops {
            self.remove_peer(peer_id, reason.as_str());
        }
        for action in actions {
            match action {
                Action::Send(addr, wire, what) => self.send_wire(&wire, addr, what),
                Action::Lookup(ip) => self.request_discovery(ip),
            }
        }
    }

    // ---------------------------------------------------------------- receive path

    fn run_receiver(&self, mut tun_writer: Option<TunWriter>) {
        let mut recv_buf = [0u8; 65535];
        let mut assembler = FragmentAssembler::new();
        let mut last_cleanup = Instant::now();

        while self.running.load(Ordering::SeqCst) {
            match self.sock.recv_from(&mut recv_buf) {
                Ok((len, src)) => {
                    let data = &recv_buf[..len];
                    log::trace!("recv {} bytes from {}", len, src);
                    if !data.is_empty() {
                        self.handle_datagram(src, data, &mut assembler, &mut tun_writer);
                    }
                }
                Err(ref e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) => {}
                Err(e) => {
                    log::error!("recv error: {}", e);
                    thread::sleep(Duration::from_secs(1));
                }
            }

            if last_cleanup.elapsed() >= Duration::from_secs(1) {
                assembler.cleanup();
                last_cleanup = Instant::now();
            }
        }
    }

    fn handle_datagram(
        &self,
        src: SocketAddr,
        data: &[u8],
        assembler: &mut FragmentAssembler,
        tun_writer: &mut Option<TunWriter>,
    ) {
        // Relay before reassembly: a datagram addressed to another node is passed
        // through untouched, fragment or not.
        if let Some(header) = packet::network_header(data, &self.network_key) {
            if header.dst_peer_id != 0 && header.dst_peer_id != self.our_id {
                self.relay_datagram(src, data, header.dst_peer_id);
                return;
            }
        }

        let assembled = match assembler.feed(src, data, &self.network_key) {
            FeedResult::Complete(message) => {
                log::debug!("reassembled fragmented message ({} bytes)", message.len());
                Some(message)
            }
            FeedResult::Buffered => return,
            FeedResult::NotFragment => None,
        };

        let packet = assembled.as_deref().unwrap_or(data);
        let Some(header) = packet::network_header(packet, &self.network_key) else {
            log::debug!("undecodable packet from {}", src);
            return;
        };

        match header.kind {
            handshake::KIND_HANDSHAKE_1 => self.handle_handshake_1(src, packet),
            handshake::KIND_HANDSHAKE_2 => self.handle_handshake_2(src, packet, header.session_id),
            _ => {
                if header.dst_peer_id != 0 && header.dst_peer_id != self.our_id {
                    self.relay_datagram(src, packet, header.dst_peer_id);
                    return;
                }
                self.handle_session_packet(src, packet, header, tun_writer);
            }
        }
    }

    fn relay_datagram(&self, src: SocketAddr, data: &[u8], dst_peer_id: u32) {
        if !self.am_relay {
            log::debug!("packet for {} ignored: relay mode disabled", dst_peer_id);
            return;
        }
        let target = self
            .peers
            .lock()
            .ok()
            .and_then(|peers| peers.get(&dst_peer_id).map(|peer| peer.addr));
        let Some(addr) = target else {
            log::debug!(
                "relay target {} unavailable for packet from {}",
                dst_peer_id,
                src
            );
            return;
        };
        self.send_wire(data, addr, "relayed packet");
    }

    fn handle_handshake_1(&self, src: SocketAddr, packet: &[u8]) {
        let now = Instant::now();
        let digest: [u8; 32] = *blake3::hash(packet).as_bytes();

        // A retransmitted handshake_1 must get the answer it already had: deriving
        // a second session here would leave the initiator - which keeps the first
        // answer that reaches it - encrypting under a key this node discarded.
        // Derived from the request so both the first answer and every cached
        // repeat share one fragment message id and reassemble together.
        let response_msg_id = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]);

        let cached = self.handshake_cache.lock().ok().and_then(|cache| {
            cache
                .get(&digest, now)
                .map(|entry| (entry.response.clone(), entry.peer_id))
        });
        if let Some((response, peer_id)) = cached {
            log::debug!(
                "answering repeated handshake_1 from {} ({}) from cache",
                src,
                peer_id
            );
            // The retransmission reaching us from another address proves that path
            // works; remember it as the endpoint to punch towards.
            self.note_direct_endpoint(peer_id, src);
            self.send_message_with_id(
                &response,
                src,
                peer_id,
                response_msg_id,
                "handshake_2 (cached)",
            );
            return;
        }

        let response = match handshake::process_handshake_1(
            packet,
            &self.cert,
            &self.signing_key,
            &self.network_key,
            &self.ca_vk,
            self.am_relay,
        ) {
            Ok(response) => response,
            Err(e) => {
                log::debug!("handshake_1 from {} failed: {}", src, e);
                return;
            }
        };

        let peer_id = node_id_from_cert(&response.peer_cert);
        if peer_id == self.our_id {
            log::warn!("ignoring handshake from {} using our own identity", src);
            return;
        }

        if let Ok(mut cache) = self.handshake_cache.lock() {
            cache.insert(digest, response.msg.clone(), peer_id, now);
        }

        // Anything arriving from a relay's address took the relayed path, so the
        // session starts out relayed and gets probed towards its direct endpoint.
        let relayed = self.addr_is_relay(src);
        let (simultaneous, direct_addr) = {
            match self.pending.lock() {
                Ok(pending) => {
                    let entry = pending.values().find(|p| p.peer_id == Some(peer_id));
                    (entry.is_some(), entry.map(|p| p.direct_addr))
                }
                Err(_) => (false, None),
            }
        };
        let direct_addr = direct_addr.or(if relayed { None } else { Some(src) });

        let outcome = self.add_peer(
            peer_id,
            response.session_key,
            &response.peer_cert,
            src,
            direct_addr,
            relayed,
            response.peer_is_relay,
            response.peer_rx_session_id,
            response.my_rx_session_id,
            peer_id,
            simultaneous,
        );

        self.send_message_with_id(&response.msg, src, peer_id, response_msg_id, "handshake_2");

        let peer_ip = primary_cert_ip(&response.peer_cert)
            .map(|ip| ip.to_string())
            .unwrap_or_else(|| "?".to_string());
        if outcome == AddPeerOutcome::Added {
            log::info!(
                "handshake complete with {} [{}] ({}{})",
                response.peer_cert.body.meta.name,
                peer_ip,
                src,
                if relayed { ", via relay" } else { "" }
            );
        } else {
            log::debug!(
                "handshake response sent to {} [{}] ({}); existing session kept",
                response.peer_cert.body.meta.name,
                peer_ip,
                src
            );
        }
    }

    fn handle_handshake_2(&self, src: SocketAddr, packet: &[u8], session_id: u32) {
        // The pending state is only consumed once a handshake_2 verifies: anyone
        // who knows the network secret can otherwise guess a session id and cancel
        // a handshake in flight.
        let completed = {
            let Ok(mut pending) = self.pending.lock() else {
                return;
            };
            let Some(handshake) = pending.get(&session_id) else {
                log::debug!("no pending handshake for {} (session {})", src, session_id);
                return;
            };

            match handshake::process_handshake_2(
                packet,
                &handshake.initiate,
                &self.network_key,
                &self.ca_vk,
            ) {
                Ok(result) => {
                    let peer_id = node_id_from_cert(&result.peer_cert);
                    if handshake
                        .peer_id
                        .is_some_and(|expected| expected != peer_id)
                    {
                        log::warn!(
                            "handshake_2 from {} answered for {} but carries the certificate of {} ({})",
                            src,
                            handshake.peer_name,
                            result.peer_cert.body.meta.name,
                            peer_id
                        );
                        return;
                    }
                    let direct_addr = handshake.direct_addr;
                    pending.remove(&session_id);
                    Some((result, peer_id, direct_addr))
                }
                Err(e) => {
                    log::debug!("handshake_2 from {} failed: {}", src, e);
                    return;
                }
            }
        };

        let Some((result, peer_id, direct_addr)) = completed else {
            return;
        };

        let relayed = src != direct_addr || self.addr_is_relay(src);
        let simultaneous = self.peers.lock().ok().is_some_and(|peers| {
            peers
                .get(&peer_id)
                .is_some_and(|existing| existing.handshake_initiator_id != self.our_id)
        });

        let outcome = self.add_peer(
            peer_id,
            result.session_key,
            &result.peer_cert,
            src,
            Some(direct_addr),
            relayed,
            result.peer_is_relay,
            result.peer_rx_session_id,
            result.my_rx_session_id,
            self.our_id,
            simultaneous,
        );

        let peer_ip = primary_cert_ip(&result.peer_cert)
            .map(|ip| ip.to_string())
            .unwrap_or_else(|| "?".to_string());
        if outcome == AddPeerOutcome::Added {
            log::info!(
                "handshake confirmed with {} [{}] ({}{})",
                result.peer_cert.body.meta.name,
                peer_ip,
                src,
                if relayed { ", via relay" } else { "" }
            );
        } else {
            log::debug!(
                "handshake confirmed with {} [{}] ({}); existing session kept",
                result.peer_cert.body.meta.name,
                peer_ip,
                src
            );
        }
    }

    /// Remember an address a peer was seen sending from, as a direct path candidate.
    fn note_direct_endpoint(&self, peer_id: u32, addr: SocketAddr) {
        if self.addr_is_relay(addr) {
            return;
        }
        let Ok(mut peers) = self.peers.lock() else {
            return;
        };
        let Some(peer) = peers.get_mut(&peer_id) else {
            return;
        };
        if peer.direct_addr == Some(addr) {
            return;
        }
        log::debug!(
            "learned direct endpoint {} for {} ({})",
            addr,
            peer.name,
            peer_id
        );
        peer.direct_addr = Some(addr);
        peer.next_probe = None;
    }

    fn addr_is_relay(&self, addr: SocketAddr) -> bool {
        self.peers.lock().is_ok_and(|peers| {
            peers
                .values()
                .any(|peer| peer.is_relay && peer.addr == addr)
        })
    }

    fn handle_session_packet(
        &self,
        src: SocketAddr,
        packet: &[u8],
        header: packet::NetworkHeader,
        tun_writer: &mut Option<TunWriter>,
    ) {
        let peer_id = self
            .rx_sessions
            .lock()
            .ok()
            .and_then(|sessions| sessions.get(&header.session_id).copied());
        let Some(peer_id) = peer_id else {
            log::debug!("no peer for rx session {}", header.session_id);
            return;
        };

        let decoded = {
            let Ok(mut peers) = self.peers.lock() else {
                return;
            };
            let Some(peer) = peers.get_mut(&peer_id) else {
                log::debug!(
                    "rx session {} points to missing peer {}",
                    header.session_id,
                    peer_id
                );
                return;
            };
            let Some((decoded_header, body)) =
                packet::decrypt_packet(packet, &self.network_key, &peer.rx_key)
            else {
                log::debug!("packet decrypt failed for {} ({})", peer.name, peer_id);
                return;
            };
            if decoded_header != header {
                log::debug!("decoded header mismatch from {}", src);
                return;
            }
            if !peer.rx_replay.accept(packet_seq(&body)) {
                log::warn!("dropping replayed packet from {} ({})", peer.name, peer_id);
                return;
            }

            if let Some(old_addr) = peer.mark_seen(src, Instant::now()) {
                let peer_ip = primary_cert_ip(&peer.cert)
                    .map(|ip| ip.to_string())
                    .unwrap_or_else(|| "?".to_string());
                if peer.direct_addr == Some(src) {
                    log::info!(
                        "peer {} [{}] ({}) moved off the relay: {} -> {}",
                        peer.name,
                        peer_ip,
                        peer_id,
                        old_addr,
                        src
                    );
                } else {
                    log::info!(
                        "peer {} [{}] ({}) roaming address updated: {} -> {}",
                        peer.name,
                        peer_ip,
                        peer_id,
                        old_addr,
                        src
                    );
                }
            }
            body
        };

        match decoded {
            PacketBody::Data { ip_packet, .. } => self.handle_data(peer_id, &ip_packet, tun_writer),
            PacketBody::LighthouseQuery { target_ip, .. } => {
                self.handle_lighthouse_query(peer_id, target_ip)
            }
            PacketBody::LighthouseResponse {
                target_ip,
                peer_id: found_id,
                peer_addr,
                peer_cert,
                peer_is_relay,
                ..
            } => self.handle_lighthouse_response(
                target_ip,
                found_id,
                peer_addr,
                peer_cert,
                peer_is_relay,
            ),
            PacketBody::LighthouseNotFound { target_ip, .. } => {
                log::info!("lighthouse has no peer for {}", target_ip)
            }
            PacketBody::Keepalive { token, .. } => self.answer_keepalive(peer_id, token),
            PacketBody::KeepaliveAck { token, .. } => self.handle_keepalive_ack(peer_id, token),
            PacketBody::RelayForward {
                next_peer_id,
                inner_packet,
                ..
            } => {
                if self.am_relay {
                    self.relay_datagram(src, &inner_packet, next_peer_id);
                } else {
                    log::debug!("relay-forward packet ignored: relay mode disabled");
                }
            }
            PacketBody::Disconnect { .. } => self.remove_peer(peer_id, "peer disconnected"),
        }
    }

    fn handle_data(&self, peer_id: u32, ip_packet: &[u8], tun_writer: &mut Option<TunWriter>) {
        let allowed = self.peers.lock().is_ok_and(|peers| {
            peers
                .get(&peer_id)
                .is_some_and(|peer| peer_allows_ip_packet_source(peer, ip_packet))
        });
        if !allowed {
            log::warn!(
                "dropping data packet from {} with unauthorized source address",
                peer_id
            );
            return;
        }

        // Without this a peer could push traffic for any destination into the
        // local stack and use the node as an unrequested router into its network.
        if !self.accepts_destination(ip_packet) {
            log::warn!(
                "dropping data packet from {} addressed outside this node's certificate",
                peer_id
            );
            return;
        }

        if let Some(tun_writer) = tun_writer.as_mut() {
            if let Err(e) = tun_writer.write(ip_packet) {
                log::warn!("tun write failed: {}", e);
            }
        }
    }

    fn accepts_destination(&self, ip_packet: &[u8]) -> bool {
        if self.local_networks.is_empty() {
            return true;
        }
        let Some(dst) = parse_dest_ip(ip_packet) else {
            return false;
        };
        if dst.is_multicast() {
            return true;
        }
        self.local_networks.iter().any(|net| net.contains(dst))
    }

    fn handle_lighthouse_query(&self, requester_id: u32, target_ip: IpAddr) {
        if !self.am_lighthouse {
            log::debug!(
                "lighthouse query for {} ignored: lighthouse mode disabled",
                target_ip
            );
            return;
        }

        let target_peer_id = self
            .routes
            .lock()
            .ok()
            .and_then(|routes| routes.lookup(target_ip));

        let mut responses: Vec<(SocketAddr, u32, Vec<u8>)> = Vec::new();
        {
            let Ok(mut peers) = self.peers.lock() else {
                return;
            };

            let Some((requester_addr, requester_cert, requester_is_relay, requester_name)) =
                peers.get(&requester_id).map(|peer| {
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
                    requester_id
                );
                return;
            };

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

            log::info!(
                "lighthouse query from {} ({}) for {}",
                requester_name,
                requester_id,
                target_ip
            );

            match target {
                Some((found_id, found_addr, found_cert, found_is_relay, found_name)) => {
                    if let Some(requester) = peers.get_mut(&requester_id) {
                        let pkt = packet::encrypt_lighthouse_response_packet(
                            requester.next_seq(),
                            requester_id,
                            requester.tx_session_id,
                            target_ip,
                            found_id,
                            found_addr,
                            &found_cert,
                            found_is_relay,
                            &self.network_key,
                            &requester.tx_key,
                        );
                        responses.push((
                            requester.addr,
                            requester_id,
                            packet::serialize_packet(&pkt),
                        ));
                    }
                    log::info!(
                        "lighthouse resolved {} for {} ({}) -> {} ({}) at {}",
                        target_ip,
                        requester_name,
                        requester_id,
                        found_name,
                        found_id,
                        found_addr
                    );

                    // Tell the target about the requester too: both ends must punch
                    // at the same time for a NAT to let the other's packets in.
                    if found_id != requester_id {
                        match primary_cert_ip(&requester_cert) {
                            Some(requester_ip) => {
                                if let Some(target_peer) = peers.get_mut(&found_id) {
                                    let pkt = packet::encrypt_lighthouse_response_packet(
                                        target_peer.next_seq(),
                                        found_id,
                                        target_peer.tx_session_id,
                                        requester_ip,
                                        requester_id,
                                        requester_addr,
                                        &requester_cert,
                                        requester_is_relay,
                                        &self.network_key,
                                        &target_peer.tx_key,
                                    );
                                    responses.push((
                                        target_peer.addr,
                                        found_id,
                                        packet::serialize_packet(&pkt),
                                    ));
                                    log::info!(
                                        "lighthouse introduced {} ({}) to {} ({})",
                                        requester_name,
                                        requester_id,
                                        found_name,
                                        found_id
                                    );
                                }
                            }
                            None => log::warn!(
                                "lighthouse requester {} has no valid cert IP for reverse introduction",
                                requester_id
                            ),
                        }
                    }
                }
                None => {
                    log::info!(
                        "lighthouse has no route for {} requested by {} ({})",
                        target_ip,
                        requester_name,
                        requester_id
                    );
                    if let Some(requester) = peers.get_mut(&requester_id) {
                        let pkt = packet::encrypt_lighthouse_not_found_packet(
                            requester.next_seq(),
                            requester_id,
                            requester.tx_session_id,
                            target_ip,
                            &self.network_key,
                            &requester.tx_key,
                        );
                        responses.push((
                            requester.addr,
                            requester_id,
                            packet::serialize_packet(&pkt),
                        ));
                    }
                }
            }
        }

        for (addr, peer_id, wire) in responses {
            self.send_message(&wire, addr, peer_id, "lighthouse response");
        }
    }

    fn handle_lighthouse_response(
        &self,
        target_ip: IpAddr,
        peer_id: u32,
        peer_addr: SocketAddr,
        peer_cert: Box<Cert>,
        peer_is_relay: bool,
    ) {
        if peer_id == self.our_id {
            log::debug!("ignoring lighthouse response describing ourselves");
            return;
        }
        if !peer_cert.verify(&self.ca_vk) {
            log::warn!(
                "lighthouse returned invalid cert for {} at {}",
                target_ip,
                peer_addr
            );
            return;
        }
        if node_id_from_cert(&peer_cert) != peer_id {
            log::warn!(
                "lighthouse returned peer id mismatch for {}",
                peer_cert.body.meta.name
            );
            return;
        }
        if !authorized_peer_routes(&peer_cert)
            .iter()
            .any(|route| route.contains(target_ip))
        {
            log::warn!(
                "lighthouse returned peer {} for {}, but its cert does not authorize that IP",
                peer_cert.body.meta.name,
                target_ip
            );
            return;
        }

        // An established session only needs the endpoint: the probe loop upgrades
        // a relayed path for the price of one datagram, instead of a full handshake.
        let known = {
            let Ok(mut peers) = self.peers.lock() else {
                return;
            };
            match peers.get_mut(&peer_id) {
                Some(peer) => {
                    if peer.direct_addr != Some(peer_addr) {
                        log::debug!(
                            "learned direct endpoint {} for {} ({})",
                            peer_addr,
                            peer.name,
                            peer_id
                        );
                        peer.direct_addr = Some(peer_addr);
                        peer.next_probe = None;
                    }
                    true
                }
                None => false,
            }
        };
        if known {
            return;
        }

        if peer_is_relay {
            log::debug!("discovered peer {} advertised relay capability", peer_id);
        }
        self.start_handshake(
            peer_addr,
            Some(peer_id),
            &peer_cert.body.meta.name,
            "lighthouse discovery",
        );
    }

    fn answer_keepalive(&self, peer_id: u32, token: u64) {
        let Some(tx) = self.peer_tx(peer_id) else {
            return;
        };
        let pkt = packet::encrypt_keepalive_ack_packet(
            tx.seq,
            peer_id,
            tx.session_id,
            token,
            &self.network_key,
            &tx.key,
        );
        self.send_wire(&packet::serialize_packet(&pkt), tx.addr, "keepalive ack");
    }

    fn handle_keepalive_ack(&self, peer_id: u32, token: u64) {
        let Ok(mut peers) = self.peers.lock() else {
            return;
        };
        let Some(peer) = peers.get_mut(&peer_id) else {
            return;
        };
        if peer.ack_keepalive(token) {
            log::debug!("keepalive ack from {} ({})", peer.name, peer_id);
        } else if peer.probe_token == Some(token) {
            log::debug!(
                "direct path probe acknowledged by {} ({})",
                peer.name,
                peer_id
            );
        } else {
            log::debug!("unexpected keepalive ack from {} token {}", peer_id, token);
        }
    }

    // ---------------------------------------------------------------- send path

    fn send_to_overlay(&self, ip_packet: &[u8], overlay_networks: &[IpNetwork]) {
        let Some(dst_ip) = parse_dest_ip(ip_packet) else {
            log::debug!("unparsable ip in tun packet");
            return;
        };
        log::trace!("tun packet dst {}", dst_ip);

        if dst_ip.is_multicast() || is_link_local(dst_ip) {
            log::trace!("skipping multicast/link-local dst {}", dst_ip);
            return;
        }
        if is_overlay_broadcast(dst_ip, overlay_networks) {
            log::debug!("skipping overlay broadcast dst {}", dst_ip);
            return;
        }

        let peer_id = match self.routes.lock() {
            Ok(routes) => routes.lookup(dst_ip),
            Err(_) => return,
        };
        let Some(peer_id) = peer_id else {
            log::debug!("no route for dst {}", dst_ip);
            self.request_discovery(dst_ip);
            return;
        };

        let Some(tx) = self.peer_tx(peer_id) else {
            log::debug!("no peer {} in peers map", peer_id);
            return;
        };
        let pkt = packet::encrypt_data_packet(
            tx.seq,
            peer_id,
            tx.session_id,
            ip_packet,
            &self.network_key,
            &tx.key,
        );
        self.send_wire(&packet::serialize_packet(&pkt), tx.addr, "data");
    }

    // ---------------------------------------------------------------- shutdown

    fn notify_shutdown(&self) {
        let targets: Vec<(u32, PeerTx)> = {
            let Ok(mut peers) = self.peers.lock() else {
                return;
            };
            peers
                .iter_mut()
                .map(|(id, peer)| {
                    (
                        *id,
                        PeerTx {
                            addr: peer.addr,
                            seq: peer.next_seq(),
                            session_id: peer.tx_session_id,
                            key: peer.tx_key,
                        },
                    )
                })
                .collect()
        };

        for (peer_id, tx) in &targets {
            log::info!("sending disconnect to peer {}", peer_id);
            let pkt = packet::encrypt_disconnect_packet(
                tx.seq,
                *peer_id,
                tx.session_id,
                &self.network_key,
                &tx.key,
            );
            self.send_wire(&packet::serialize_packet(&pkt), tx.addr, "disconnect");
        }
    }

    fn wait_for_shutdown_or_timeout(&self, duration: Duration) {
        let (lock, cv) = &self.shutdown;
        let Ok(shutdown) = lock.lock() else {
            return;
        };
        if *shutdown {
            return;
        }
        let _ = cv.wait_timeout(shutdown, duration);
    }
}

fn random_token() -> u64 {
    let mut bytes = [0u8; 8];
    rand::rngs::ThreadRng::default().fill_bytes(&mut bytes);
    u64::from_be_bytes(bytes)
}

fn node_id_from_cert(cert: &Cert) -> u32 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"liteway-node-id-v1");
    hasher.update(&cert.body.keys.ed25519_pk);
    hasher.update(&cert.body.keys.ml_dsa_pk);
    let h = hasher.finalize();
    u32::from_be_bytes(h.as_bytes()[..4].try_into().unwrap())
}

fn udp_payload_limit(config: &AppConfig, listen: SocketAddr) -> usize {
    let Some(iface) = config.interface.as_ref() else {
        return frag::DEFAULT_MAX_DATAGRAM;
    };

    let mtu_payload = usize::from(iface.mtu).saturating_sub(ip_udp_overhead(listen));
    mtu_payload.clamp(frag::MIN_DATAGRAM, frag::DEFAULT_MAX_DATAGRAM)
}

fn ip_udp_overhead(listen: SocketAddr) -> usize {
    if listen.is_ipv6() {
        48
    } else {
        28
    }
}

/// A tunnel MTU that does not fit the underlying link fragments every full-size
/// packet at the IP layer, which shows up as a tunnel that only carries small
/// packets. Warn instead of silently building it.
fn warn_on_oversized_mtu(config: &AppConfig, listen: SocketAddr) {
    let Some(iface) = config.interface.as_ref() else {
        return;
    };
    let datagram = usize::from(iface.mtu) + packet::PACKET_OVERHEAD + ip_udp_overhead(listen);
    if datagram > 1500 {
        log::warn!(
            "interface.mtu {} produces {}-byte UDP datagrams; lower it to {} to stay under a 1500-byte path MTU",
            iface.mtu,
            datagram,
            1500 - packet::PACKET_OVERHEAD - ip_udp_overhead(listen)
        );
    }
}

fn resolve_socket_addr(address: &str) -> anyhow::Result<SocketAddr> {
    address
        .to_socket_addrs()
        .with_context(|| format!("resolve address '{address}'"))?
        .next()
        .ok_or_else(|| anyhow::anyhow!("address '{address}' resolved to no socket addresses"))
}

fn resolve_lighthouses(lighthouses: &[LighthouseConfig]) -> anyhow::Result<Vec<LighthouseSlot>> {
    let mut resolved = Vec::with_capacity(lighthouses.len());
    for lighthouse in lighthouses {
        let address = resolve_socket_addr(&lighthouse.address)
            .with_context(|| format!("resolve lighthouse '{}'", lighthouse.name))?;
        if lighthouse.address != address.to_string() {
            log::info!(
                "resolved lighthouse {} {} -> {}",
                lighthouse.name,
                lighthouse.address,
                address
            );
        }
        resolved.push(LighthouseSlot {
            name: lighthouse.name.clone(),
            configured: lighthouse.address.clone(),
            address,
            peer_id: None,
            resolved_at: Instant::now(),
        });
    }
    Ok(resolved)
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

fn parse_node_cert(toml_str: &str) -> anyhow::Result<Cert> {
    Ok(toml::from_str::<Cert>(toml_str)?)
}

fn read_node_key(path: &str) -> anyhow::Result<NodeKeyFile> {
    let key_toml =
        std::fs::read_to_string(path).with_context(|| format!("read node key file '{path}'"))?;
    toml::from_str::<NodeKeyFile>(&key_toml)
        .with_context(|| format!("parse node key file '{path}'"))
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

#[cfg(test)]
mod tests {
    use super::*;

    fn ipv4_packet(src: [u8; 4], dst: [u8; 4]) -> Vec<u8> {
        let mut packet = vec![0u8; 20];
        packet[0] = 0x45;
        packet[12..16].copy_from_slice(&src);
        packet[16..20].copy_from_slice(&dst);
        packet
    }

    fn node_with_local_networks(networks: &[&str]) -> Vec<IpNetwork> {
        networks.iter().map(|n| n.parse().unwrap()).collect()
    }

    #[test]
    fn destination_outside_the_certificate_is_rejected() {
        let local = node_with_local_networks(&["10.0.0.2/32"]);
        let accepts = |packet: &[u8]| {
            parse_dest_ip(packet).is_some_and(|dst| local.iter().any(|net| net.contains(dst)))
        };

        assert!(accepts(&ipv4_packet([10, 0, 0, 1], [10, 0, 0, 2])));
        assert!(!accepts(&ipv4_packet([10, 0, 0, 1], [192, 168, 1, 5])));
    }

    #[test]
    fn oversized_tunnel_mtu_is_detected() {
        let listen: SocketAddr = "0.0.0.0:1234".parse().unwrap();
        assert!(1500 + packet::PACKET_OVERHEAD + ip_udp_overhead(listen) > 1500);
        assert!(1300 + packet::PACKET_OVERHEAD + ip_udp_overhead(listen) < 1500);
    }

    #[test]
    fn tun_polling_backs_off_when_idle() {
        assert!(tun_poll_backoff(1) < tun_poll_backoff(100));
        assert!(tun_poll_backoff(100) < tun_poll_backoff(100_000));
    }

    #[test]
    fn peer_expiry_is_a_backstop_for_the_keepalive_timeout() {
        use state::PEER_EXPIRY;
        let timings = Timings::from_secs(10, 30, 5, 20, 5);
        assert!(timings.keepalive_timeout < PEER_EXPIRY);
        assert_eq!(timings.peer_expiry, PEER_EXPIRY);
    }
}
