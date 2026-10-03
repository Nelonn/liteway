//! Peer, route and handshake bookkeeping.
//!
//! Everything in here is state plus the timing decisions taken on it. Keeping the
//! decisions away from the sockets is what makes the connection logic testable:
//! the daemon threads only turn the returned actions into packets.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use ipnetwork::IpNetwork;
use liteway_core::cert::Cert;
use liteway_core::crypto::SESSION_KEY_LEN;
use liteway_core::handshake::HandshakeInitiate;
use zeroize::Zeroize;

/// A handshake is 14 UDP fragments in each direction, so a single lost datagram
/// used to cost the whole session. Retransmission starts fast and backs off.
const HANDSHAKE_RETRY_BASE: Duration = Duration::from_millis(500);
const HANDSHAKE_RETRY_MAX: Duration = Duration::from_secs(3);
/// Caps the bandwidth one handshake can spend (~15 KiB per attempt).
const HANDSHAKE_MAX_ATTEMPTS: u32 = 10;

/// Upper bound on how long a peer that answers nothing is kept around.
pub const PEER_EXPIRY: Duration = Duration::from_secs(300);

const HANDSHAKE_CACHE_TTL: Duration = Duration::from_secs(60);
const HANDSHAKE_CACHE_MAX_ENTRIES: usize = 256;

/// Probe backoff ceiling for peers whose direct path never opens up.
const DIRECT_PROBE_MAX_INTERVAL: Duration = Duration::from_secs(30);

#[derive(Copy, Clone, Debug)]
pub struct Timings {
    pub keepalive_interval: Duration,
    pub keepalive_timeout: Duration,
    pub direct_probe_interval: Duration,
    pub handshake_timeout: Duration,
    pub relay_fallback: Duration,
    pub peer_expiry: Duration,
}

impl Timings {
    pub fn from_secs(
        keepalive_interval: u64,
        keepalive_timeout: u64,
        direct_probe_interval: u64,
        handshake_timeout: u64,
        relay_fallback: u64,
    ) -> Self {
        Timings {
            keepalive_interval: Duration::from_secs(keepalive_interval),
            keepalive_timeout: Duration::from_secs(keepalive_timeout),
            direct_probe_interval: Duration::from_secs(direct_probe_interval),
            handshake_timeout: Duration::from_secs(handshake_timeout),
            relay_fallback: Duration::from_secs(relay_fallback),
            peer_expiry: PEER_EXPIRY,
        }
    }
}

pub struct RouteTable {
    routes: Vec<(IpNetwork, u32)>,
}

impl Default for RouteTable {
    fn default() -> Self {
        Self::new()
    }
}

impl RouteTable {
    pub fn new() -> Self {
        RouteTable { routes: Vec::new() }
    }

    pub fn insert(&mut self, network: IpNetwork, peer_id: u32) {
        self.routes.retain(|(n, _)| n != &network);
        self.routes.push((network, peer_id));
    }

    pub fn lookup(&self, ip: IpAddr) -> Option<u32> {
        self.routes
            .iter()
            .filter(|(net, _)| net.contains(ip))
            .max_by_key(|(net, _)| net.prefix())
            .map(|(_, id)| *id)
    }

    pub fn remove_peer(&mut self, peer_id: u32) {
        self.routes.retain(|(_, id)| *id != peer_id);
    }
}

pub const REPLAY_WINDOW_BITS: u64 = 64;

pub struct ReplayWindow {
    initialized: bool,
    highest: u64,
    seen: u64,
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}

impl ReplayWindow {
    pub fn new() -> Self {
        Self {
            initialized: false,
            highest: 0,
            seen: 0,
        }
    }

    pub fn accept(&mut self, seq: u64) -> bool {
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

pub struct KeepalivePending {
    pub token: u64,
    pub first_sent_at: Instant,
    pub last_sent_at: Instant,
}

/// What a maintenance tick wants done for one peer.
#[derive(Debug, PartialEq, Eq)]
pub enum PeerTick {
    Idle,
    /// Session is idle; send a keepalive carrying this token to `peer.addr`.
    Keepalive(u64),
    /// Session is gone; drop the peer so a fresh handshake can replace it.
    Drop(DropReason),
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum DropReason {
    KeepaliveTimeout,
    Expired,
}

impl DropReason {
    pub fn as_str(self) -> &'static str {
        match self {
            DropReason::KeepaliveTimeout => "keepalive timeout",
            DropReason::Expired => "no traffic",
        }
    }
}

pub struct PeerState {
    pub name: String,
    pub cert: Cert,
    pub tx_key: [u8; SESSION_KEY_LEN],
    pub rx_key: [u8; SESSION_KEY_LEN],
    /// Endpoint packets are currently sent to; a relay address while relayed.
    pub addr: SocketAddr,
    /// Endpoint the peer is reachable at without a relay, when one is known.
    pub direct_addr: Option<SocketAddr>,
    pub is_relay: bool,
    pub tx_session_id: u32,
    pub rx_session_id: u32,
    pub tx_seq: u64,
    pub rx_replay: ReplayWindow,
    pub last_seen: Instant,
    pub routes: Vec<IpNetwork>,
    pub handshake_initiator_id: u32,
    pub keepalive: Option<KeepalivePending>,
    /// Set when the session was built through a relay instead of end to end.
    pub relayed: bool,
    pub next_probe: Option<Instant>,
    pub probe_interval: Duration,
    pub probe_token: Option<u64>,
}

impl Drop for PeerState {
    fn drop(&mut self) {
        self.tx_key.zeroize();
        self.rx_key.zeroize();
    }
}

impl PeerState {
    pub fn next_seq(&mut self) -> u64 {
        self.tx_seq = self.tx_seq.wrapping_add(1);
        self.tx_seq
    }

    /// Record that the session is alive, and adopt a new source address if the
    /// peer moved (NAT rebind, roaming, or a relayed path that just went direct).
    ///
    /// Liveness of *our* sending direction is proven by keepalive acks only, so a
    /// packet arriving here does not clear an outstanding keepalive.
    pub fn mark_seen(&mut self, src: SocketAddr, now: Instant) -> Option<SocketAddr> {
        self.last_seen = now;
        if self.addr == src {
            return None;
        }
        let old = self.addr;
        self.addr = src;
        if self.direct_addr == Some(src) {
            self.relayed = false;
            self.next_probe = None;
            self.probe_token = None;
        }
        Some(old)
    }

    pub fn ack_keepalive(&mut self, token: u64) -> bool {
        if self.keepalive.as_ref().is_some_and(|k| k.token == token) {
            self.keepalive = None;
            return true;
        }
        false
    }

    /// Decide what this peer needs on a maintenance tick.
    ///
    /// `token` is only consumed when a new keepalive is started; an unanswered one
    /// is repeated with its original token so a single lost datagram cannot cost
    /// the session.
    pub fn tick(&mut self, now: Instant, timings: &Timings, token: u64) -> PeerTick {
        if let Some(pending) = self.keepalive.as_mut() {
            // Only a session that has gone quiet in *both* directions is dead. A
            // peer whose acks keep getting lost on a lossy link is still talking,
            // and tearing that session down would only add a re-handshake to it.
            if now.duration_since(pending.first_sent_at) >= timings.keepalive_timeout
                && now.duration_since(self.last_seen) >= timings.keepalive_timeout
            {
                return PeerTick::Drop(DropReason::KeepaliveTimeout);
            }
            if now.duration_since(pending.last_sent_at) >= timings.keepalive_interval {
                pending.last_sent_at = now;
                return PeerTick::Keepalive(pending.token);
            }
            return PeerTick::Idle;
        }

        if now.duration_since(self.last_seen) >= timings.peer_expiry {
            return PeerTick::Drop(DropReason::Expired);
        }

        if now.duration_since(self.last_seen) >= timings.keepalive_interval {
            self.keepalive = Some(KeepalivePending {
                token,
                first_sent_at: now,
                last_sent_at: now,
            });
            return PeerTick::Keepalive(token);
        }

        PeerTick::Idle
    }

    /// What to do about a session that is still riding a relay.
    ///
    /// With the peer's direct endpoint known, both ends punch towards it on the
    /// same schedule: the two probes cross, open each other's NAT mapping, and the
    /// reply then arrives from the direct address so [`PeerState::mark_seen`]
    /// switches the session over. Without it, the lighthouse is asked first.
    pub fn take_path_probe(&mut self, now: Instant, timings: &Timings, token: u64) -> PathProbe {
        if !self.relayed {
            return PathProbe::None;
        }
        if self.direct_addr == Some(self.addr) {
            return PathProbe::None;
        }
        if self.next_probe.is_some_and(|next| now < next) {
            return PathProbe::None;
        }

        if self.next_probe.is_none() {
            self.probe_interval = timings.direct_probe_interval;
        } else {
            self.probe_interval = (self.probe_interval * 2).min(DIRECT_PROBE_MAX_INTERVAL);
        }
        self.next_probe = Some(now + self.probe_interval);

        match self.direct_addr {
            Some(direct) => {
                self.probe_token = Some(token);
                PathProbe::Punch(direct, token)
            }
            None => PathProbe::Lookup,
        }
    }
}

/// How to try to get a relayed session onto a direct path.
#[derive(Debug, PartialEq, Eq)]
pub enum PathProbe {
    None,
    /// Hole-punch towards this endpoint with a keepalive carrying the token.
    Punch(SocketAddr, u64),
    /// The peer's direct endpoint is unknown; ask the lighthouses for it.
    Lookup,
}

/// An outgoing handshake that has not been answered yet.
pub struct PendingHandshake {
    pub initiate: HandshakeInitiate,
    /// Endpoint learned from the lighthouse (or the configured lighthouse itself).
    pub direct_addr: SocketAddr,
    /// Relay to duplicate the handshake through once the direct path looks dead.
    pub relay_addr: Option<SocketAddr>,
    pub peer_id: Option<u32>,
    pub peer_name: String,
    pub created_at: Instant,
    pub next_attempt: Instant,
    pub attempts: u32,
}

impl PendingHandshake {
    pub fn new(
        initiate: HandshakeInitiate,
        direct_addr: SocketAddr,
        peer_id: Option<u32>,
        peer_name: String,
        now: Instant,
    ) -> Self {
        PendingHandshake {
            initiate,
            direct_addr,
            relay_addr: None,
            peer_id,
            peer_name,
            created_at: now,
            next_attempt: now + retry_delay(1),
            attempts: 1,
        }
    }

    /// Time to stop waiting for an answer and free the state.
    pub fn expired(&self, now: Instant, timings: &Timings) -> bool {
        now.duration_since(self.created_at) >= timings.handshake_timeout
    }

    pub fn retransmit_due(&self, now: Instant, timings: &Timings) -> bool {
        !self.expired(now, timings)
            && self.attempts < HANDSHAKE_MAX_ATTEMPTS
            && now >= self.next_attempt
    }

    pub fn record_attempt(&mut self, now: Instant) {
        self.attempts += 1;
        self.next_attempt = now + retry_delay(self.attempts);
    }

    /// A relay is only worth trying once the direct path has had its chance, and
    /// only for peers we can address by id through the relay.
    pub fn relay_fallback_due(&self, now: Instant, timings: &Timings) -> bool {
        self.relay_addr.is_none()
            && self.peer_id.is_some()
            && now.duration_since(self.created_at) >= timings.relay_fallback
    }

    /// Every endpoint the next retransmission should go to.
    pub fn targets(&self) -> Vec<SocketAddr> {
        let mut targets = vec![self.direct_addr];
        if let Some(relay) = self.relay_addr {
            if relay != self.direct_addr {
                targets.push(relay);
            }
        }
        targets
    }
}

fn retry_delay(attempts: u32) -> Duration {
    let exponent = attempts.saturating_sub(1).min(8);
    let scaled = HANDSHAKE_RETRY_BASE.saturating_mul(1u32 << exponent.min(3));
    scaled.min(HANDSHAKE_RETRY_MAX)
}

/// Responses already sent for a handshake_1, keyed by its hash.
///
/// A retransmitted handshake_1 must be answered with the *same* handshake_2:
/// processing it again would derive a second session key, and the initiator —
/// which keeps whichever answer reached it first — would end up encrypting with
/// a key the responder has already replaced. Caching also keeps duplicate
/// handshakes off the expensive ML-DSA/ML-KEM path.
#[derive(Default)]
pub struct HandshakeCache {
    entries: HashMap<[u8; 32], CachedHandshake>,
}

pub struct CachedHandshake {
    pub response: Vec<u8>,
    pub peer_id: u32,
    pub created_at: Instant,
}

impl HandshakeCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self, key: &[u8; 32], now: Instant) -> Option<&CachedHandshake> {
        self.entries
            .get(key)
            .filter(|entry| now.duration_since(entry.created_at) < HANDSHAKE_CACHE_TTL)
    }

    pub fn insert(&mut self, key: [u8; 32], response: Vec<u8>, peer_id: u32, now: Instant) {
        if self.entries.len() >= HANDSHAKE_CACHE_MAX_ENTRIES {
            self.cleanup(now);
        }
        if self.entries.len() >= HANDSHAKE_CACHE_MAX_ENTRIES {
            let oldest = self
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.created_at)
                .map(|(key, _)| *key);
            if let Some(oldest) = oldest {
                self.entries.remove(&oldest);
            }
        }
        self.entries.insert(
            key,
            CachedHandshake {
                response,
                peer_id,
                created_at: now,
            },
        );
    }

    pub fn cleanup(&mut self, now: Instant) {
        self.entries
            .retain(|_, entry| now.duration_since(entry.created_at) < HANDSHAKE_CACHE_TTL);
    }

    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// A configured lighthouse and what we currently know about reaching it.
#[derive(Clone)]
pub struct LighthouseSlot {
    pub name: String,
    /// Address as written in the config, re-resolved while disconnected.
    pub configured: String,
    pub address: SocketAddr,
    /// Set once a handshake with this lighthouse completes.
    pub peer_id: Option<u32>,
    pub resolved_at: Instant,
}

/// Decide whether a freshly completed handshake should replace the session we have.
///
/// When both ends dial each other at once the two handshakes must not settle on
/// different keys, so a tie-break picks the session initiated by the lower node
/// id. The tie-break only applies once a session exists: refusing the only
/// handshake that got through would leave a reachable peer unreachable, which is
/// exactly how a punched-through path ends up on a relay instead.
pub fn accept_handshake_session(
    our_id: u32,
    peer_id: u32,
    existing_initiator_id: Option<u32>,
    initiator_id: u32,
    simultaneous: bool,
) -> bool {
    if !simultaneous {
        return true;
    }

    let Some(existing_initiator_id) = existing_initiator_id else {
        return true;
    };

    let preferred_initiator = our_id.min(peer_id);
    if initiator_id != preferred_initiator {
        return false;
    }

    existing_initiator_id != preferred_initiator
}

#[cfg(test)]
mod tests {
    use super::*;

    fn timings() -> Timings {
        Timings::from_secs(10, 30, 5, 20, 5)
    }

    fn test_addr(port: u16) -> SocketAddr {
        SocketAddr::from(([198, 51, 100, 7], port))
    }

    #[test]
    fn simultaneous_handshake_prefers_lower_node_id_when_a_session_exists() {
        let low_id = 10;
        let high_id = 20;

        assert!(accept_handshake_session(
            low_id,
            high_id,
            Some(high_id),
            low_id,
            true
        ));
        assert!(!accept_handshake_session(
            low_id,
            high_id,
            Some(low_id),
            high_id,
            true
        ));
        assert!(!accept_handshake_session(
            high_id,
            low_id,
            Some(low_id),
            high_id,
            true
        ));
    }

    #[test]
    fn simultaneous_handshake_keeps_existing_preferred_session() {
        let low_id = 10;
        let high_id = 20;

        assert!(!accept_handshake_session(
            low_id,
            high_id,
            Some(low_id),
            low_id,
            true
        ));
        assert!(!accept_handshake_session(
            low_id,
            high_id,
            Some(low_id),
            high_id,
            true
        ));
    }

    #[test]
    fn simultaneous_handshake_is_accepted_when_no_session_exists() {
        // The non-preferred direction is the only one that got through: taking it
        // beats having no session at all, and the tie-break still converges once
        // the preferred handshake arrives.
        assert!(accept_handshake_session(10, 20, None, 20, true));
        assert!(accept_handshake_session(20, 10, None, 20, true));
    }

    #[test]
    fn non_simultaneous_handshake_allows_reconnect_from_either_side() {
        let low_id = 10;
        let high_id = 20;

        assert!(accept_handshake_session(
            low_id,
            high_id,
            Some(low_id),
            high_id,
            false
        ));
        assert!(accept_handshake_session(
            high_id,
            low_id,
            Some(high_id),
            low_id,
            false
        ));
    }

    #[test]
    fn replay_window_rejects_duplicates_and_old_sequences() {
        let mut window = ReplayWindow::new();
        assert!(window.accept(5));
        assert!(!window.accept(5));
        assert!(window.accept(4));
        assert!(window.accept(200));
        assert!(!window.accept(5));
    }

    #[test]
    fn route_table_prefers_the_longest_prefix() {
        let mut routes = RouteTable::new();
        routes.insert("10.0.0.0/8".parse().unwrap(), 1);
        routes.insert("10.1.0.0/16".parse().unwrap(), 2);
        assert_eq!(routes.lookup("10.1.2.3".parse().unwrap()), Some(2));
        assert_eq!(routes.lookup("10.2.2.3".parse().unwrap()), Some(1));
        routes.remove_peer(2);
        assert_eq!(routes.lookup("10.1.2.3".parse().unwrap()), Some(1));
    }

    #[test]
    fn handshake_retries_back_off_and_stop() {
        assert!(retry_delay(1) < retry_delay(3));
        assert_eq!(retry_delay(9), HANDSHAKE_RETRY_MAX);
    }

    /// A CA plus one node certificate, generated once for the whole test module.
    fn test_identity() -> &'static (Cert, liteway_core::cert::NodeKeyFile, [u8; 32]) {
        use std::sync::OnceLock;
        static IDENTITY: OnceLock<(Cert, liteway_core::cert::NodeKeyFile, [u8; 32])> =
            OnceLock::new();
        IDENTITY.get_or_init(|| {
            let ca = liteway_core::cert::generate_ca("test-ca", 1, &[]);
            let (cert, key) = liteway_core::cert::generate_node(
                "test",
                "10.0.0.1/24",
                &[],
                &[],
                &ca.signing_key,
                1,
            );
            let network_key = liteway_core::crypto::kdf::derive_network_key(&[3u8; 32]);
            (cert, key, network_key)
        })
    }

    fn test_initiate() -> HandshakeInitiate {
        let (cert, key, network_key) = test_identity();
        liteway_core::handshake::create_handshake_1(
            cert,
            &key.signing_secret_key,
            network_key,
            false,
        )
    }

    fn test_peer(now: Instant, direct: Option<SocketAddr>, relayed: bool) -> PeerState {
        let cert = test_identity().0.clone();
        PeerState {
            name: "peer".to_string(),
            cert,
            tx_key: [1u8; SESSION_KEY_LEN],
            rx_key: [2u8; SESSION_KEY_LEN],
            addr: test_addr(1000),
            direct_addr: direct,
            is_relay: false,
            tx_session_id: 1,
            rx_session_id: 2,
            tx_seq: 0,
            rx_replay: ReplayWindow::new(),
            last_seen: now,
            routes: Vec::new(),
            handshake_initiator_id: 1,
            keepalive: None,
            relayed,
            next_probe: None,
            probe_interval: Duration::from_secs(5),
            probe_token: None,
        }
    }

    #[test]
    fn idle_peer_is_kept_alive_and_dropped_only_after_the_timeout() {
        let timings = timings();
        let start = Instant::now();
        let mut peer = test_peer(start, None, false);

        assert_eq!(peer.tick(start, &timings, 1), PeerTick::Idle);

        let idle = start + timings.keepalive_interval;
        assert_eq!(peer.tick(idle, &timings, 7), PeerTick::Keepalive(7));
        // Still waiting for the ack: repeat the same token instead of a new probe.
        assert_eq!(peer.tick(idle, &timings, 8), PeerTick::Idle);
        assert_eq!(
            peer.tick(idle + timings.keepalive_interval, &timings, 8),
            PeerTick::Keepalive(7)
        );

        let dead = idle + timings.keepalive_timeout;
        assert_eq!(
            peer.tick(dead, &timings, 9),
            PeerTick::Drop(DropReason::KeepaliveTimeout)
        );
    }

    #[test]
    fn a_peer_that_still_sends_traffic_survives_lost_acks() {
        let timings = timings();
        let start = Instant::now();
        let mut peer = test_peer(start, None, false);

        let mut now = start + timings.keepalive_interval;
        assert_eq!(peer.tick(now, &timings, 7), PeerTick::Keepalive(7));

        // Acks never arrive, but the peer keeps sending: the session stays up.
        for _ in 0..6 {
            now += timings.keepalive_interval;
            peer.mark_seen(peer.addr, now);
            assert!(!matches!(peer.tick(now, &timings, 8), PeerTick::Drop(_)));
        }

        // Now it goes quiet in both directions.
        now += timings.keepalive_timeout;
        assert_eq!(
            peer.tick(now, &timings, 9),
            PeerTick::Drop(DropReason::KeepaliveTimeout)
        );
    }

    #[test]
    fn answered_keepalive_clears_the_pending_probe() {
        let timings = timings();
        let start = Instant::now();
        let mut peer = test_peer(start, None, false);
        let idle = start + timings.keepalive_interval;

        assert_eq!(peer.tick(idle, &timings, 7), PeerTick::Keepalive(7));
        assert!(!peer.ack_keepalive(6));
        assert!(peer.ack_keepalive(7));
        peer.mark_seen(peer.addr, idle);
        assert_eq!(peer.tick(idle, &timings, 9), PeerTick::Idle);
    }

    #[test]
    fn relayed_peer_punches_its_direct_endpoint_with_backoff() {
        let timings = timings();
        let start = Instant::now();
        let direct = test_addr(2000);
        let mut peer = test_peer(start, Some(direct), true);

        assert_eq!(
            peer.take_path_probe(start, &timings, 3),
            PathProbe::Punch(direct, 3)
        );
        assert_eq!(peer.take_path_probe(start, &timings, 4), PathProbe::None);

        let next = start + timings.direct_probe_interval;
        assert_eq!(
            peer.take_path_probe(next, &timings, 5),
            PathProbe::Punch(direct, 5)
        );
        // Backoff doubled, so the following probe is not due at the old interval.
        assert_eq!(
            peer.take_path_probe(next + timings.direct_probe_interval, &timings, 6),
            PathProbe::None
        );
    }

    #[test]
    fn relayed_peer_without_a_direct_endpoint_asks_the_lighthouse() {
        let timings = timings();
        let start = Instant::now();
        let mut peer = test_peer(start, None, true);
        assert_eq!(peer.take_path_probe(start, &timings, 1), PathProbe::Lookup);
    }

    #[test]
    fn traffic_from_the_direct_endpoint_ends_the_relayed_state() {
        let timings = timings();
        let start = Instant::now();
        let direct = test_addr(2000);
        let mut peer = test_peer(start, Some(direct), true);

        assert!(matches!(
            peer.take_path_probe(start, &timings, 1),
            PathProbe::Punch(_, _)
        ));
        assert_eq!(peer.mark_seen(direct, start), Some(test_addr(1000)));
        assert!(!peer.relayed);
        assert_eq!(peer.addr, direct);
        assert_eq!(peer.take_path_probe(start, &timings, 2), PathProbe::None);
    }

    #[test]
    fn pending_handshake_retransmits_then_falls_back_to_a_relay() {
        let timings = timings();
        let start = Instant::now();
        let mut pending = PendingHandshake::new(
            test_initiate(),
            test_addr(1000),
            Some(42),
            "peer".to_string(),
            start,
        );

        assert!(!pending.retransmit_due(start, &timings));
        assert!(pending.retransmit_due(start + Duration::from_secs(1), &timings));
        pending.record_attempt(start + Duration::from_secs(1));
        assert_eq!(pending.targets(), vec![test_addr(1000)]);

        assert!(!pending.relay_fallback_due(start, &timings));
        let late = start + timings.relay_fallback;
        assert!(pending.relay_fallback_due(late, &timings));
        pending.relay_addr = Some(test_addr(3000));
        assert!(!pending.relay_fallback_due(late, &timings));
        // Both paths stay in play: the relay is a duplicate, not a replacement.
        assert_eq!(pending.targets(), vec![test_addr(1000), test_addr(3000)]);

        assert!(pending.expired(start + timings.handshake_timeout, &timings));
        assert!(!pending.retransmit_due(start + timings.handshake_timeout, &timings));
    }

    #[test]
    fn handshake_cache_evicts_expired_entries() {
        let mut cache = HandshakeCache::new();
        let now = Instant::now();
        cache.insert([1u8; 32], vec![0xAA], 7, now);
        assert!(cache.get(&[1u8; 32], now).is_some());
        assert!(cache.get(&[2u8; 32], now).is_none());

        let later = now + HANDSHAKE_CACHE_TTL + Duration::from_secs(1);
        assert!(cache.get(&[1u8; 32], later).is_none());
        cache.cleanup(later);
        assert!(cache.is_empty());
    }
}
