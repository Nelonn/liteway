use std::collections::HashMap;
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::time::Instant;

use crate::crypto::K_HEADER_LEN;
use crate::handshake::{self, KIND_HANDSHAKE_FRAG};
use crate::packet::PACKET_OVERHEAD;

/// Fallback max UDP payload bytes, below typical IPv6 minimum path MTU.
pub const DEFAULT_MAX_DATAGRAM: usize = 1200;

/// Minimum useful UDP payload: encrypted fragment overhead plus one data byte.
pub const MIN_DATAGRAM: usize = PACKET_OVERHEAD + 1;

const CLEANUP_AGE_SECS: u64 = 30;
const MAX_PENDING_MESSAGES: usize = 1024;
const MAX_PENDING_MESSAGES_PER_SOURCE: usize = 32;
const MAX_BUFFERED_BYTES: usize = 4 * 1024 * 1024;
const MAX_BUFFERED_BYTES_PER_SOURCE: usize = 512 * 1024;
const MAX_FRAGMENTED_MESSAGE_BYTES: usize = 512 * 1024;

pub enum FeedResult {
    Complete(Vec<u8>),
    Buffered,
    NotFragment,
}

struct PendingMessage {
    chunks: Vec<Option<Vec<u8>>>,
    started: Instant,
    bytes: usize,
}

/// Split `data` into sealed fragments and send each over UDP.
pub fn send_fragmented(
    sock: &UdpSocket,
    data: &[u8],
    addr: SocketAddr,
    network_key: &[u8; K_HEADER_LEN],
    max_datagram: usize,
) -> io::Result<()> {
    send_fragmented_to_peer(sock, data, addr, network_key, max_datagram, 0)
}

pub fn send_fragmented_to_peer(
    sock: &UdpSocket,
    data: &[u8],
    addr: SocketAddr,
    network_key: &[u8; K_HEADER_LEN],
    max_datagram: usize,
    dst_peer_id: u32,
) -> io::Result<()> {
    if max_datagram < MIN_DATAGRAM {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "fragment datagram limit is too small",
        ));
    }

    let chunk_size = max_datagram - PACKET_OVERHEAD;
    let total = data.len().div_ceil(chunk_size).max(1);
    if total > u8::MAX as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "fragmented message exceeds 255 chunks",
        ));
    }
    let msg_id: u32 = rand::random();

    if data.is_empty() {
        let mut plain = Vec::with_capacity(7);
        plain.push(KIND_HANDSHAKE_FRAG);
        plain.extend_from_slice(&msg_id.to_be_bytes());
        plain.push(0);
        plain.push(1);
        let packet = handshake::seal_handshake_to_peer(network_key, &plain, dst_peer_id);
        let sent = sock.send_to(&packet, addr)?;
        log::trace!(
            "sent {} bytes to {} (fragment 1/1, dst_peer_id {})",
            sent,
            addr,
            dst_peer_id
        );
        return Ok(());
    }

    for (i, chunk) in data.chunks(chunk_size).enumerate() {
        let mut plain = Vec::with_capacity(7 + chunk.len());
        plain.push(KIND_HANDSHAKE_FRAG);
        plain.extend_from_slice(&msg_id.to_be_bytes());
        plain.push(i as u8);
        plain.push(total as u8);
        plain.extend_from_slice(chunk);

        let packet = handshake::seal_handshake_to_peer(network_key, &plain, dst_peer_id);
        let sent = sock.send_to(&packet, addr)?;
        log::trace!(
            "sent {} bytes to {} (fragment {}/{}, dst_peer_id {})",
            sent,
            addr,
            i + 1,
            total,
            dst_peer_id
        );
    }

    Ok(())
}

#[derive(Default)]
pub struct FragmentAssembler {
    pending: HashMap<(SocketAddr, u32), PendingMessage>,
    buffered_bytes: usize,
}

impl FragmentAssembler {
    pub fn new() -> Self {
        Self {
            pending: HashMap::new(),
            buffered_bytes: 0,
        }
    }

    /// Decrypt with `network_key`.
    /// - If kind != 0x13 → `NotFragment`
    /// - If kind == 0x13, buffer the chunk → `Buffered` or `Complete(assembled)`
    pub fn feed(
        &mut self,
        src: SocketAddr,
        data: &[u8],
        network_key: &[u8; K_HEADER_LEN],
    ) -> FeedResult {
        let Some(plain) = handshake::open_handshake(network_key, data) else {
            return FeedResult::NotFragment;
        };

        if plain.is_empty() || plain[0] != KIND_HANDSHAKE_FRAG {
            return FeedResult::NotFragment;
        }

        if plain.len() < 7 {
            return FeedResult::NotFragment;
        }

        let msg_id = u32::from_be_bytes([plain[1], plain[2], plain[3], plain[4]]);
        let idx = plain[5] as usize;
        let total = plain[6] as usize;

        if idx >= total || total == 0 {
            return FeedResult::Buffered;
        }

        let chunk = &plain[7..];
        if chunk.len() > MAX_FRAGMENTED_MESSAGE_BYTES {
            return FeedResult::Buffered;
        }

        let key = (src, msg_id);
        if !self.pending.contains_key(&key) {
            let (source_messages, _) = self.source_usage(src);
            if self.pending.len() >= MAX_PENDING_MESSAGES
                || source_messages >= MAX_PENDING_MESSAGES_PER_SOURCE
            {
                return FeedResult::Buffered;
            }

            self.pending.insert(
                key,
                PendingMessage {
                    chunks: (0..total).map(|_| None).collect(),
                    started: Instant::now(),
                    bytes: 0,
                },
            );
        }

        let Some(entry) = self.pending.get(&key) else {
            return FeedResult::Buffered;
        };

        if entry.chunks.len() != total {
            self.remove_pending(&key);
            return FeedResult::Buffered;
        }

        let old_len = entry.chunks[idx].as_ref().map_or(0, Vec::len);
        let delta = chunk.len().saturating_sub(old_len);
        let message_bytes = entry.bytes.saturating_add(delta);
        if message_bytes > MAX_FRAGMENTED_MESSAGE_BYTES {
            self.remove_pending(&key);
            return FeedResult::Buffered;
        }

        let (_, source_bytes) = self.source_usage(src);
        if self.buffered_bytes.saturating_add(delta) > MAX_BUFFERED_BYTES
            || source_bytes.saturating_add(delta) > MAX_BUFFERED_BYTES_PER_SOURCE
        {
            return FeedResult::Buffered;
        }

        let Some(entry) = self.pending.get_mut(&key) else {
            return FeedResult::Buffered;
        };

        if old_len > chunk.len() {
            self.buffered_bytes = self.buffered_bytes.saturating_sub(old_len - chunk.len());
            entry.bytes = entry.bytes.saturating_sub(old_len - chunk.len());
        } else {
            self.buffered_bytes = self.buffered_bytes.saturating_add(delta);
            entry.bytes = entry.bytes.saturating_add(delta);
        }

        entry.chunks[idx] = Some(chunk.to_vec());

        let complete = entry.chunks.iter().all(|c| c.is_some());
        if complete {
            let Some(mut entry) = self.pending.remove(&key) else {
                return FeedResult::Buffered;
            };
            self.buffered_bytes = self.buffered_bytes.saturating_sub(entry.bytes);

            let mut assembled = Vec::new();
            for slot in entry.chunks.drain(..) {
                if let Some(data) = slot {
                    assembled.extend_from_slice(&data);
                }
            }
            return FeedResult::Complete(assembled);
        }

        FeedResult::Buffered
    }

    pub fn cleanup(&mut self) {
        let now = Instant::now();
        let mut removed_bytes = 0usize;
        self.pending.retain(|_, msg| {
            let keep = now.duration_since(msg.started).as_secs() < CLEANUP_AGE_SECS;
            if !keep {
                removed_bytes = removed_bytes.saturating_add(msg.bytes);
            }
            keep
        });
        self.buffered_bytes = self.buffered_bytes.saturating_sub(removed_bytes);
    }

    fn source_usage(&self, src: SocketAddr) -> (usize, usize) {
        self.pending
            .iter()
            .filter(|((pending_src, _), _)| pending_src == &src)
            .fold((0usize, 0usize), |(messages, bytes), (_, msg)| {
                (messages + 1, bytes.saturating_add(msg.bytes))
            })
    }

    fn remove_pending(&mut self, key: &(SocketAddr, u32)) {
        if let Some(msg) = self.pending.remove(key) {
            self.buffered_bytes = self.buffered_bytes.saturating_sub(msg.bytes);
        }
    }
}
