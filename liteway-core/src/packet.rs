use std::net::{IpAddr, SocketAddr};

use rand::rngs::ThreadRng;
use rand_core::Rng;
use zeroize::Zeroizing;

use crate::cert::Cert;
use crate::crypto::aead;
use crate::crypto::kdf;
use crate::crypto::{AEAD_TAG_LEN, K_HEADER_LEN, NONCE_LEN, SESSION_KEY_LEN};

pub const MASK_NONCE_LEN: usize = 8;
pub const NETWORK_HEADER_LEN: usize = 16;
pub const PACKET_OVERHEAD: usize = MASK_NONCE_LEN + NETWORK_HEADER_LEN + NONCE_LEN + AEAD_TAG_LEN;
pub const MIN_PACKET_LEN: usize = PACKET_OVERHEAD;

pub const KIND_DATA: u8 = 0x21;
pub const KIND_RELAY_FORWARD: u8 = 0x22;
pub const KIND_DISCONNECT: u8 = 0x23;
pub const KIND_LIGHTHOUSE_QUERY: u8 = 0x24;
pub const KIND_LIGHTHOUSE_RESPONSE: u8 = 0x25;
pub const KIND_LIGHTHOUSE_NOT_FOUND: u8 = 0x26;
pub const KIND_KEEPALIVE: u8 = 0x27;
pub const KIND_KEEPALIVE_ACK: u8 = 0x28;
pub const KIND_HANDSHAKE_1: u8 = 0x11;
pub const KIND_HANDSHAKE_2: u8 = 0x12;
pub const KIND_HANDSHAKE_FRAG: u8 = 0x13;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataPacket {
    pub mask_nonce: [u8; MASK_NONCE_LEN],
    pub masked_header: [u8; NETWORK_HEADER_LEN],
    pub nonce: [u8; NONCE_LEN],
    pub ciphertext: Vec<u8>,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct NetworkHeader {
    pub kind: u8,
    pub frag_index: u8,
    pub frag_total: u8,
    pub dst_peer_id: u32,
    pub session_id: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PacketBody {
    Data {
        seq: u64,
        ip_packet: Vec<u8>,
    },
    RelayForward {
        seq: u64,
        next_peer_id: u32,
        inner_packet: Vec<u8>,
    },
    Disconnect {
        seq: u64,
    },
    LighthouseQuery {
        seq: u64,
        target_ip: IpAddr,
    },
    LighthouseResponse {
        seq: u64,
        target_ip: IpAddr,
        peer_id: u32,
        peer_addr: SocketAddr,
        peer_cert: Cert,
        peer_is_relay: bool,
    },
    LighthouseNotFound {
        seq: u64,
        target_ip: IpAddr,
    },
    Keepalive {
        seq: u64,
        token: u64,
    },
    KeepaliveAck {
        seq: u64,
        token: u64,
    },
}

pub fn encrypt_data_packet(
    seq: u64,
    dst_peer_id: u32,
    session_id: u32,
    ip_packet: &[u8],
    network_key: &[u8; K_HEADER_LEN],
    session_key: &[u8; SESSION_KEY_LEN],
) -> DataPacket {
    let mut plaintext = Vec::with_capacity(1 + 8 + 4 + ip_packet.len() + 32);
    plaintext.push(KIND_DATA);
    plaintext.extend_from_slice(&seq.to_be_bytes());
    put_vec_u32(&mut plaintext, ip_packet);
    add_random_padding(&mut plaintext);
    seal(
        KIND_DATA,
        dst_peer_id,
        session_id,
        network_key,
        session_key,
        &plaintext,
    )
}

pub fn encrypt_disconnect_packet(
    seq: u64,
    dst_peer_id: u32,
    session_id: u32,
    network_key: &[u8; K_HEADER_LEN],
    session_key: &[u8; SESSION_KEY_LEN],
) -> DataPacket {
    let mut plaintext = Vec::with_capacity(1 + 8 + 32);
    plaintext.push(KIND_DISCONNECT);
    plaintext.extend_from_slice(&seq.to_be_bytes());
    add_random_padding(&mut plaintext);
    seal(
        KIND_DISCONNECT,
        dst_peer_id,
        session_id,
        network_key,
        session_key,
        &plaintext,
    )
}

pub fn encrypt_relay_forward_packet(
    seq: u64,
    dst_peer_id: u32,
    session_id: u32,
    next_peer_id: u32,
    inner_packet: &[u8],
    network_key: &[u8; K_HEADER_LEN],
    session_key: &[u8; SESSION_KEY_LEN],
) -> DataPacket {
    let mut plaintext = Vec::with_capacity(1 + 8 + 4 + 4 + inner_packet.len() + 32);
    plaintext.push(KIND_RELAY_FORWARD);
    plaintext.extend_from_slice(&seq.to_be_bytes());
    plaintext.extend_from_slice(&next_peer_id.to_be_bytes());
    put_vec_u32(&mut plaintext, inner_packet);
    add_random_padding(&mut plaintext);
    seal(
        KIND_RELAY_FORWARD,
        dst_peer_id,
        session_id,
        network_key,
        session_key,
        &plaintext,
    )
}

pub fn encrypt_lighthouse_query_packet(
    seq: u64,
    dst_peer_id: u32,
    session_id: u32,
    target_ip: IpAddr,
    network_key: &[u8; K_HEADER_LEN],
    session_key: &[u8; SESSION_KEY_LEN],
) -> DataPacket {
    let ip = target_ip.to_string();
    let mut plaintext = Vec::with_capacity(1 + 8 + 4 + ip.len() + 32);
    plaintext.push(KIND_LIGHTHOUSE_QUERY);
    plaintext.extend_from_slice(&seq.to_be_bytes());
    put_vec_u32(&mut plaintext, ip.as_bytes());
    add_random_padding(&mut plaintext);
    seal(
        KIND_LIGHTHOUSE_QUERY,
        dst_peer_id,
        session_id,
        network_key,
        session_key,
        &plaintext,
    )
}

pub fn encrypt_lighthouse_response_packet(
    seq: u64,
    dst_peer_id: u32,
    session_id: u32,
    target_ip: IpAddr,
    peer_id: u32,
    peer_addr: SocketAddr,
    peer_cert: &Cert,
    peer_is_relay: bool,
    network_key: &[u8; K_HEADER_LEN],
    session_key: &[u8; SESSION_KEY_LEN],
) -> DataPacket {
    let target_ip = target_ip.to_string();
    let peer_addr = peer_addr.to_string();
    let peer_cert = serde_json::to_vec(peer_cert).expect("certificate serialization failed");

    let mut plaintext = Vec::with_capacity(
        1 + 8 + 4 + target_ip.len() + 4 + 4 + peer_addr.len() + 4 + peer_cert.len() + 1 + 32,
    );
    plaintext.push(KIND_LIGHTHOUSE_RESPONSE);
    plaintext.extend_from_slice(&seq.to_be_bytes());
    put_vec_u32(&mut plaintext, target_ip.as_bytes());
    plaintext.extend_from_slice(&peer_id.to_be_bytes());
    put_vec_u32(&mut plaintext, peer_addr.as_bytes());
    put_vec_u32(&mut plaintext, &peer_cert);
    plaintext.push(u8::from(peer_is_relay));
    add_random_padding(&mut plaintext);
    seal(
        KIND_LIGHTHOUSE_RESPONSE,
        dst_peer_id,
        session_id,
        network_key,
        session_key,
        &plaintext,
    )
}

pub fn encrypt_lighthouse_not_found_packet(
    seq: u64,
    dst_peer_id: u32,
    session_id: u32,
    target_ip: IpAddr,
    network_key: &[u8; K_HEADER_LEN],
    session_key: &[u8; SESSION_KEY_LEN],
) -> DataPacket {
    let target_ip = target_ip.to_string();
    let mut plaintext = Vec::with_capacity(1 + 8 + 4 + target_ip.len() + 32);
    plaintext.push(KIND_LIGHTHOUSE_NOT_FOUND);
    plaintext.extend_from_slice(&seq.to_be_bytes());
    put_vec_u32(&mut plaintext, target_ip.as_bytes());
    add_random_padding(&mut plaintext);
    seal(
        KIND_LIGHTHOUSE_NOT_FOUND,
        dst_peer_id,
        session_id,
        network_key,
        session_key,
        &plaintext,
    )
}

pub fn encrypt_keepalive_packet(
    seq: u64,
    dst_peer_id: u32,
    session_id: u32,
    token: u64,
    network_key: &[u8; K_HEADER_LEN],
    session_key: &[u8; SESSION_KEY_LEN],
) -> DataPacket {
    let mut plaintext = Vec::with_capacity(1 + 8 + 8 + 32);
    plaintext.push(KIND_KEEPALIVE);
    plaintext.extend_from_slice(&seq.to_be_bytes());
    plaintext.extend_from_slice(&token.to_be_bytes());
    add_random_padding(&mut plaintext);
    seal(
        KIND_KEEPALIVE,
        dst_peer_id,
        session_id,
        network_key,
        session_key,
        &plaintext,
    )
}

pub fn encrypt_keepalive_ack_packet(
    seq: u64,
    dst_peer_id: u32,
    session_id: u32,
    token: u64,
    network_key: &[u8; K_HEADER_LEN],
    session_key: &[u8; SESSION_KEY_LEN],
) -> DataPacket {
    let mut plaintext = Vec::with_capacity(1 + 8 + 8 + 32);
    plaintext.push(KIND_KEEPALIVE_ACK);
    plaintext.extend_from_slice(&seq.to_be_bytes());
    plaintext.extend_from_slice(&token.to_be_bytes());
    add_random_padding(&mut plaintext);
    seal(
        KIND_KEEPALIVE_ACK,
        dst_peer_id,
        session_id,
        network_key,
        session_key,
        &plaintext,
    )
}

pub fn decrypt_packet(
    data: &[u8],
    network_key: &[u8; K_HEADER_LEN],
    session_key: &[u8; SESSION_KEY_LEN],
) -> Option<(NetworkHeader, PacketBody)> {
    let pkt = deserialize_packet(data)?;
    let header = unmask_header(&pkt, network_key)?;
    let packet_key = Zeroizing::new(kdf::derive_labeled_key(
        "liteway-packet-key-v2",
        session_key,
    ));
    let aad = packet_aad(&pkt);
    let plaintext = aead::decrypt(&*packet_key, &pkt.nonce, &pkt.ciphertext, &aad)?;
    let mut rd = Reader::new(&plaintext);
    let kind = rd.u8()?;
    let seq = rd.u64()?;
    if kind != header.kind {
        return None;
    }
    match kind {
        KIND_DATA => {
            let ip_packet = rd.vec_u32()?.to_vec();
            Some((header, PacketBody::Data { seq, ip_packet }))
        }
        KIND_RELAY_FORWARD => {
            let next_peer_id = rd.u32()?;
            let inner_packet = rd.vec_u32()?.to_vec();
            Some((
                header,
                PacketBody::RelayForward {
                    seq,
                    next_peer_id,
                    inner_packet,
                },
            ))
        }
        KIND_DISCONNECT => Some((header, PacketBody::Disconnect { seq })),
        KIND_LIGHTHOUSE_QUERY => {
            let target_ip = parse_utf8(rd.vec_u32()?)?.parse().ok()?;
            Some((header, PacketBody::LighthouseQuery { seq, target_ip }))
        }
        KIND_LIGHTHOUSE_RESPONSE => {
            let target_ip = parse_utf8(rd.vec_u32()?)?.parse().ok()?;
            let peer_id = rd.u32()?;
            let peer_addr = parse_utf8(rd.vec_u32()?)?.parse().ok()?;
            let peer_cert = serde_json::from_slice(rd.vec_u32()?).ok()?;
            let peer_is_relay = rd.u8()? != 0;
            Some((
                header,
                PacketBody::LighthouseResponse {
                    seq,
                    target_ip,
                    peer_id,
                    peer_addr,
                    peer_cert,
                    peer_is_relay,
                },
            ))
        }
        KIND_LIGHTHOUSE_NOT_FOUND => {
            let target_ip = parse_utf8(rd.vec_u32()?)?.parse().ok()?;
            Some((header, PacketBody::LighthouseNotFound { seq, target_ip }))
        }
        KIND_KEEPALIVE => {
            let token = rd.u64()?;
            Some((header, PacketBody::Keepalive { seq, token }))
        }
        KIND_KEEPALIVE_ACK => {
            let token = rd.u64()?;
            Some((header, PacketBody::KeepaliveAck { seq, token }))
        }
        _ => None,
    }
}

pub fn serialize_packet(pkt: &DataPacket) -> Vec<u8> {
    let mut buf = Vec::with_capacity(MIN_PACKET_LEN + pkt.ciphertext.len());
    buf.extend_from_slice(&pkt.mask_nonce);
    buf.extend_from_slice(&pkt.masked_header);
    buf.extend_from_slice(&pkt.nonce);
    buf.extend_from_slice(&pkt.ciphertext);
    buf
}

pub fn deserialize_packet(data: &[u8]) -> Option<DataPacket> {
    if data.len() < MIN_PACKET_LEN {
        return None;
    }
    let mut mask_nonce = [0u8; MASK_NONCE_LEN];
    mask_nonce.copy_from_slice(&data[..MASK_NONCE_LEN]);
    let mut masked_header = [0u8; NETWORK_HEADER_LEN];
    masked_header.copy_from_slice(&data[MASK_NONCE_LEN..MASK_NONCE_LEN + NETWORK_HEADER_LEN]);
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(
        &data[MASK_NONCE_LEN + NETWORK_HEADER_LEN..MASK_NONCE_LEN + NETWORK_HEADER_LEN + NONCE_LEN],
    );
    let ciphertext = data[MASK_NONCE_LEN + NETWORK_HEADER_LEN + NONCE_LEN..].to_vec();
    Some(DataPacket {
        mask_nonce,
        masked_header,
        nonce,
        ciphertext,
    })
}

pub fn network_header(data: &[u8], network_key: &[u8; K_HEADER_LEN]) -> Option<NetworkHeader> {
    let pkt = deserialize_packet(data)?;
    unmask_header(&pkt, network_key)
}

pub fn derive_traffic_key(
    session_key: &[u8; SESSION_KEY_LEN],
    src_id: u32,
    dst_id: u32,
) -> [u8; SESSION_KEY_LEN] {
    let mut input = Zeroizing::new(Vec::with_capacity(SESSION_KEY_LEN + 8));
    input.extend_from_slice(session_key);
    input.extend_from_slice(&src_id.to_be_bytes());
    input.extend_from_slice(&dst_id.to_be_bytes());
    kdf::derive_labeled_key("liteway-traffic-key-v2", input.as_slice())
}

fn seal(
    kind: u8,
    dst_peer_id: u32,
    session_id: u32,
    network_key: &[u8; K_HEADER_LEN],
    session_key: &[u8; SESSION_KEY_LEN],
    plaintext: &[u8],
) -> DataPacket {
    let header = NetworkHeader {
        kind,
        frag_index: 0,
        frag_total: 0,
        dst_peer_id,
        session_id,
    };
    let mut mask_nonce = [0u8; MASK_NONCE_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    ThreadRng::default().fill_bytes(&mut mask_nonce);
    ThreadRng::default().fill_bytes(&mut nonce);
    let masked_header = mask_network_header(header, &mask_nonce, network_key);
    let pkt_for_aad = DataPacket {
        mask_nonce,
        masked_header,
        nonce,
        ciphertext: Vec::new(),
    };
    let aad = packet_aad(&pkt_for_aad);
    let packet_key = Zeroizing::new(kdf::derive_labeled_key(
        "liteway-packet-key-v2",
        session_key,
    ));
    let ciphertext = aead::encrypt(&*packet_key, &nonce, plaintext, &aad);
    DataPacket {
        mask_nonce,
        masked_header,
        nonce,
        ciphertext,
    }
}

pub fn mask_network_header(
    header: NetworkHeader,
    mask_nonce: &[u8; MASK_NONCE_LEN],
    network_key: &[u8; K_HEADER_LEN],
) -> [u8; NETWORK_HEADER_LEN] {
    let plain = encode_header(header);
    let mask_key = kdf::derive_labeled_key("liteway-network-header-mask-v1", network_key);
    let mask = blake3::keyed_hash(&mask_key, mask_nonce);
    let mut masked = [0u8; NETWORK_HEADER_LEN];
    for (out, (plain, mask)) in masked
        .iter_mut()
        .zip(plain.iter().zip(mask.as_bytes().iter()))
    {
        *out = *plain ^ *mask;
    }
    masked
}

fn encode_header(header: NetworkHeader) -> [u8; NETWORK_HEADER_LEN] {
    let mut out = [0u8; NETWORK_HEADER_LEN];
    out[0] = header.kind;
    out[1] = header.frag_index;
    out[2] = header.frag_total;
    out[4..8].copy_from_slice(&header.dst_peer_id.to_be_bytes());
    out[8..12].copy_from_slice(&header.session_id.to_be_bytes());
    out
}

fn decode_header(bytes: [u8; NETWORK_HEADER_LEN]) -> Option<NetworkHeader> {
    if bytes[3] != 0 || bytes[12..16] != [0; 4] {
        return None;
    }

    let kind = bytes[0];
    match kind {
        KIND_DATA
        | KIND_RELAY_FORWARD
        | KIND_DISCONNECT
        | KIND_LIGHTHOUSE_QUERY
        | KIND_LIGHTHOUSE_RESPONSE
        | KIND_LIGHTHOUSE_NOT_FOUND
        | KIND_KEEPALIVE
        | KIND_KEEPALIVE_ACK
        | KIND_HANDSHAKE_1
        | KIND_HANDSHAKE_2
        | KIND_HANDSHAKE_FRAG => {}
        _ => return None,
    }
    let frag_index = bytes[1];
    let frag_total = bytes[2];
    let dst_peer_id = u32::from_be_bytes(bytes[4..8].try_into().ok()?);
    let session_id = u32::from_be_bytes(bytes[8..12].try_into().ok()?);
    Some(NetworkHeader {
        kind,
        frag_index,
        frag_total,
        dst_peer_id,
        session_id,
    })
}

fn unmask_header(pkt: &DataPacket, network_key: &[u8; K_HEADER_LEN]) -> Option<NetworkHeader> {
    let mask_key = kdf::derive_labeled_key("liteway-network-header-mask-v1", network_key);
    let mask = blake3::keyed_hash(&mask_key, &pkt.mask_nonce);
    let mut plain = [0u8; NETWORK_HEADER_LEN];
    for (out, (masked, mask)) in plain
        .iter_mut()
        .zip(pkt.masked_header.iter().zip(mask.as_bytes().iter()))
    {
        *out = *masked ^ *mask;
    }
    decode_header(plain)
}

pub fn packet_aad(pkt: &DataPacket) -> [u8; MASK_NONCE_LEN + NETWORK_HEADER_LEN] {
    let mut aad = [0u8; MASK_NONCE_LEN + NETWORK_HEADER_LEN];
    aad[..MASK_NONCE_LEN].copy_from_slice(&pkt.mask_nonce);
    aad[MASK_NONCE_LEN..].copy_from_slice(&pkt.masked_header);
    aad
}

fn put_vec_u32(out: &mut Vec<u8>, bytes: &[u8]) {
    let len = bytes.len() as u32;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
}

fn parse_utf8(bytes: &[u8]) -> Option<&str> {
    std::str::from_utf8(bytes).ok()
}

fn add_random_padding(out: &mut Vec<u8>) {
    let mut pad_len = [0u8; 1];
    ThreadRng::default().fill_bytes(&mut pad_len);
    let pad_len = (pad_len[0] % 32) as usize;
    let mut padding = vec![0u8; pad_len];
    ThreadRng::default().fill_bytes(&mut padding);
    out.extend_from_slice(&padding);
}

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn bytes(&mut self, len: usize) -> Option<&'a [u8]> {
        if self.pos + len > self.data.len() {
            return None;
        }
        let bytes = &self.data[self.pos..self.pos + len];
        self.pos += len;
        Some(bytes)
    }

    fn u8(&mut self) -> Option<u8> {
        Some(self.bytes(1)?[0])
    }

    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_be_bytes(self.bytes(4)?.try_into().ok()?))
    }

    fn u64(&mut self) -> Option<u64> {
        Some(u64::from_be_bytes(self.bytes(8)?.try_into().ok()?))
    }

    fn vec_u32(&mut self) -> Option<&'a [u8]> {
        let len = u32::from_be_bytes(self.bytes(4)?.try_into().ok()?) as usize;
        self.bytes(len)
    }
}
