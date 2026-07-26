use ml_kem::{Decapsulate, Encapsulate, TryKeyInit};
use rand::rngs::ThreadRng;
use rand_core::Rng;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519Pk};
use zeroize::{Zeroize, Zeroizing};

use crate::cert::{CaVerifyKey, Cert, NodeSigningSecretKey};
use crate::crypto::aead;
use crate::crypto::hybrid_kem::{self, MLKEM_CT_LEN};
use crate::crypto::hybrid_sig::{self, HybridSignature, HybridSigningKey, HybridVerifyKey};
use crate::crypto::kdf;
use crate::crypto::{K_HEADER_LEN, NONCE_LEN, SESSION_KEY_LEN};
use crate::packet::{self, DataPacket, NetworkHeader, MASK_NONCE_LEN};

const HANDSHAKE_VERSION: u8 = 2;
pub const KIND_HANDSHAKE_1: u8 = packet::KIND_HANDSHAKE_1;
pub const KIND_HANDSHAKE_2: u8 = packet::KIND_HANDSHAKE_2;
pub const KIND_HANDSHAKE_FRAG: u8 = packet::KIND_HANDSHAKE_FRAG;
const FLAG_RELAY: u16 = 0x0001;
const HANDSHAKE_MAX_CLOCK_SKEW_SECS: u64 = 300;

pub struct HandshakeResult {
    pub peer_cert: Cert,
    pub session_key: [u8; SESSION_KEY_LEN],
    pub peer_eph_x25519: [u8; 32],
    pub peer_is_relay: bool,
    pub my_rx_session_id: u32,
    pub peer_rx_session_id: u32,
}

impl Drop for HandshakeResult {
    fn drop(&mut self) {
        self.session_key.zeroize();
    }
}

pub struct HandshakeInitiate {
    pub msg: Vec<u8>,
    pub eph_x25519_sk: EphemeralSecret,
    pub eph_mlkem_sk: hybrid_kem::MlKemSecretKey,
    pub my_rx_session_id: u32,
}

pub struct HandshakeResponse {
    pub msg: Vec<u8>,
    pub session_key: [u8; SESSION_KEY_LEN],
    pub peer_cert: Cert,
    pub peer_is_relay: bool,
    pub my_rx_session_id: u32,
    pub peer_rx_session_id: u32,
}

impl Drop for HandshakeResponse {
    fn drop(&mut self) {
        self.session_key.zeroize();
    }
}

struct Handshake1Plain {
    cert: Cert,
    rx_session_id: u32,
    eph_x25519_pk: [u8; 32],
    eph_mlkem_pk: [u8; hybrid_kem::MLKEM_PK_LEN],
    peer_is_relay: bool,
}

struct Handshake2Plain {
    cert: Cert,
    rx_session_id: u32,
    eph_x25519_pk: [u8; 32],
    mlkem_ct: [u8; MLKEM_CT_LEN],
    peer_is_relay: bool,
}

pub fn create_handshake_1(
    my_cert: &Cert,
    my_signing_key: &NodeSigningSecretKey,
    network_key: &[u8; K_HEADER_LEN],
    relay_flag: bool,
) -> HandshakeInitiate {
    let (eph_x_sk, eph_x_pk, eph_k_sk, eph_k_pk) = hybrid_kem::generate_ephemeral();
    let my_rx_session_id = random_session_id();

    let flags = if relay_flag { FLAG_RELAY } else { 0 };
    let mut signed = Vec::new();
    signed.push(KIND_HANDSHAKE_1);
    signed.push(HANDSHAKE_VERSION);
    signed.extend_from_slice(&flags.to_be_bytes());
    signed.extend_from_slice(&unix_time_secs().to_be_bytes());
    let mut random = [0u8; 16];
    ThreadRng::default().fill_bytes(&mut random);
    signed.extend_from_slice(&random);
    signed.extend_from_slice(&my_rx_session_id.to_be_bytes());
    signed.extend_from_slice(&eph_x_pk.to_bytes());
    signed.extend_from_slice(&hybrid_kem::mlkem_pk_bytes(&eph_k_pk));
    put_vec_u32(&mut signed, &serde_json::to_vec(my_cert).unwrap());

    let sig = sign_node(my_signing_key, &signed);
    let mut plaintext = signed;
    plaintext.extend_from_slice(&sig.ed25519);
    plaintext.extend_from_slice(&sig.ml_dsa);
    add_random_padding(&mut plaintext);

    let msg = seal_handshake(network_key, &plaintext);

    HandshakeInitiate {
        msg,
        eph_x25519_sk: eph_x_sk,
        eph_mlkem_sk: eph_k_sk,
        my_rx_session_id,
    }
}

pub fn handshake_kind(data: &[u8], network_key: &[u8; K_HEADER_LEN]) -> Option<u8> {
    packet::network_header(data, network_key).map(|header| header.kind)
}

pub fn process_handshake_1(
    data: &[u8],
    my_cert: &Cert,
    my_signing_key: &NodeSigningSecretKey,
    network_key: &[u8; K_HEADER_LEN],
    ca_vk: &CaVerifyKey,
    relay_flag: bool,
) -> anyhow::Result<HandshakeResponse> {
    let plaintext = open_handshake(network_key, data)
        .ok_or_else(|| anyhow::anyhow!("handshake 1 decrypt failed"))?;
    let hs1 = parse_handshake_1(&plaintext, ca_vk)?;
    let my_rx_session_id = random_session_id();

    let peer_eph_k_pk = hybrid_kem::MlKemPublicKey::new_from_slice(&hs1.eph_mlkem_pk)
        .map_err(|e| anyhow::anyhow!("invalid peer ephemeral ML-KEM public key: {e:?}"))?;
    let (eph_x_sk, eph_x_pk, _ml_kem_sk, _ml_kem_pk) = hybrid_kem::generate_ephemeral();
    let (mlkem_ct, mlkem_ss) = peer_eph_k_pk.encapsulate_with_rng(&mut ThreadRng::default());
    let peer_x_pk = X25519Pk::from(hs1.eph_x25519_pk);
    let x25519_ss = eph_x_sk.diffie_hellman(&peer_x_pk);

    let mut hybrid_ss = Zeroizing::new([0u8; 64]);
    hybrid_ss[..32].copy_from_slice(x25519_ss.as_bytes());
    hybrid_ss[32..].copy_from_slice(&mlkem_ss);

    let flags = if relay_flag { FLAG_RELAY } else { 0 };
    let mut signed = Vec::new();
    signed.push(KIND_HANDSHAKE_2);
    signed.push(HANDSHAKE_VERSION);
    signed.extend_from_slice(&flags.to_be_bytes());
    signed.extend_from_slice(&unix_time_secs().to_be_bytes());
    let mut random = [0u8; 16];
    ThreadRng::default().fill_bytes(&mut random);
    signed.extend_from_slice(&random);
    signed.extend_from_slice(&my_rx_session_id.to_be_bytes());
    signed.extend_from_slice(&eph_x_pk.to_bytes());
    signed.extend_from_slice(&mlkem_ct);
    signed.extend_from_slice(&blake3::hash(data).as_bytes()[..]);
    put_vec_u32(&mut signed, &serde_json::to_vec(my_cert).unwrap());

    let sig = sign_node(my_signing_key, &signed);
    let mut plaintext2 = signed;
    plaintext2.extend_from_slice(&sig.ed25519);
    plaintext2.extend_from_slice(&sig.ml_dsa);
    add_random_padding(&mut plaintext2);

    let msg = seal_handshake(network_key, &plaintext2);
    let session_key = derive_session_v2(&*hybrid_ss, data, &msg);

    Ok(HandshakeResponse {
        msg,
        session_key,
        peer_cert: hs1.cert,
        peer_is_relay: hs1.peer_is_relay,
        my_rx_session_id,
        peer_rx_session_id: hs1.rx_session_id,
    })
}

pub fn process_handshake_2(
    data: &[u8],
    initiate: HandshakeInitiate,
    network_key: &[u8; K_HEADER_LEN],
    ca_vk: &CaVerifyKey,
) -> anyhow::Result<HandshakeResult> {
    let plaintext = open_handshake(network_key, data)
        .ok_or_else(|| anyhow::anyhow!("handshake 2 decrypt failed"))?;
    let hs2 = parse_handshake_2(&plaintext, &initiate.msg, ca_vk)?;

    let peer_x_pk = X25519Pk::from(hs2.eph_x25519_pk);
    let x25519_ss = initiate.eph_x25519_sk.diffie_hellman(&peer_x_pk);

    let mlkem_ct = ml_kem::ml_kem_768::Ciphertext::try_from(&hs2.mlkem_ct[..])
        .map_err(|e| anyhow::anyhow!("invalid ML-KEM ciphertext: {e:?}"))?;
    let mlkem_ss = initiate.eph_mlkem_sk.decapsulate(&mlkem_ct);

    let mut hybrid_ss = Zeroizing::new([0u8; 64]);
    hybrid_ss[..32].copy_from_slice(x25519_ss.as_bytes());
    hybrid_ss[32..].copy_from_slice(&mlkem_ss);

    let session_key = derive_session_v2(&*hybrid_ss, &initiate.msg, data);

    Ok(HandshakeResult {
        peer_cert: hs2.cert,
        session_key,
        peer_eph_x25519: hs2.eph_x25519_pk,
        peer_is_relay: hs2.peer_is_relay,
        my_rx_session_id: initiate.my_rx_session_id,
        peer_rx_session_id: hs2.rx_session_id,
    })
}

pub(crate) fn seal_handshake(network_key: &[u8; K_HEADER_LEN], plaintext: &[u8]) -> Vec<u8> {
    let (header, payload) = handshake_header_and_payload(plaintext);
    let mut mask_nonce = [0u8; MASK_NONCE_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    ThreadRng::default().fill_bytes(&mut mask_nonce);
    ThreadRng::default().fill_bytes(&mut nonce);
    let masked_header = packet::mask_network_header(header, &mask_nonce, network_key);
    let pkt_for_aad = DataPacket {
        mask_nonce,
        masked_header,
        nonce,
        ciphertext: Vec::new(),
    };
    let aad = packet::packet_aad(&pkt_for_aad);
    let ct = aead::encrypt(network_key, &nonce, payload, &aad);

    let mut msg = Vec::with_capacity(packet::MIN_PACKET_LEN + payload.len());
    msg.extend_from_slice(&mask_nonce);
    msg.extend_from_slice(&masked_header);
    msg.extend_from_slice(&nonce);
    msg.extend_from_slice(&ct);
    msg
}

pub(crate) fn open_handshake(network_key: &[u8; K_HEADER_LEN], data: &[u8]) -> Option<Vec<u8>> {
    let pkt = packet::deserialize_packet(data)?;
    let header = packet::network_header(data, network_key)?;
    let aad = packet::packet_aad(&pkt);
    let plaintext = aead::decrypt(network_key, &pkt.nonce, &pkt.ciphertext, &aad)?;
    if header.kind == KIND_HANDSHAKE_FRAG {
        if header.frag_total == 0 || header.frag_index >= header.frag_total {
            return None;
        }
        let mut out = Vec::with_capacity(7 + plaintext.len());
        out.push(KIND_HANDSHAKE_FRAG);
        out.extend_from_slice(&header.session_id.to_be_bytes());
        out.push(header.frag_index);
        out.push(header.frag_total);
        out.extend_from_slice(&plaintext);
        Some(out)
    } else {
        if header.frag_index != 0 || header.frag_total != 0 {
            return None;
        }
        if plaintext.first().copied()? != header.kind {
            return None;
        }
        Some(plaintext)
    }
}

fn parse_handshake_1(data: &[u8], ca_vk: &CaVerifyKey) -> anyhow::Result<Handshake1Plain> {
    let mut rd = Reader::new(data);
    let signed_len = 1 + 1 + 2 + 8 + 16 + 4 + 32 + hybrid_kem::MLKEM_PK_LEN;
    if data.len() < signed_len + 4 + hybrid_sig::ED25519_SIG_LEN + hybrid_sig::MLDSA_SIG_LEN {
        anyhow::bail!("handshake 1 too short");
    }
    let kind = rd.u8()?;
    if kind != KIND_HANDSHAKE_1 {
        anyhow::bail!("wrong handshake kind");
    }
    let version = rd.u8()?;
    if version != HANDSHAKE_VERSION {
        anyhow::bail!("unsupported handshake version");
    }
    let flags = rd.u16()?;
    let timestamp = rd.u64()?;
    validate_timestamp(timestamp)?;
    let _random = rd.bytes(16)?;
    let rx_session_id = rd.u32()?;
    let eph_x25519_pk = rd.array::<32>()?;
    let eph_mlkem_pk = rd.array::<{ hybrid_kem::MLKEM_PK_LEN }>()?;
    let cert_bytes = rd.vec_u32()?;
    let cert: Cert = serde_json::from_slice(cert_bytes)?;
    let signed = &data[..rd.pos()];
    let ed25519 = rd.array::<{ hybrid_sig::ED25519_SIG_LEN }>()?;
    let ml_dsa = rd.array::<{ hybrid_sig::MLDSA_SIG_LEN }>()?;

    verify_peer_cert_and_sig(&cert, ca_vk, signed, ed25519, ml_dsa)?;

    Ok(Handshake1Plain {
        cert,
        rx_session_id,
        eph_x25519_pk,
        eph_mlkem_pk,
        peer_is_relay: flags & FLAG_RELAY != 0,
    })
}

fn parse_handshake_2(
    data: &[u8],
    expected_hs1_msg: &[u8],
    ca_vk: &CaVerifyKey,
) -> anyhow::Result<Handshake2Plain> {
    let mut rd = Reader::new(data);
    let signed_len = 1 + 1 + 2 + 8 + 16 + 4 + 32 + MLKEM_CT_LEN + 32;
    if data.len() < signed_len + 4 + hybrid_sig::ED25519_SIG_LEN + hybrid_sig::MLDSA_SIG_LEN {
        anyhow::bail!("handshake 2 too short");
    }
    let kind = rd.u8()?;
    if kind != KIND_HANDSHAKE_2 {
        anyhow::bail!("wrong handshake kind");
    }
    let version = rd.u8()?;
    if version != HANDSHAKE_VERSION {
        anyhow::bail!("unsupported handshake version");
    }
    let flags = rd.u16()?;
    let timestamp = rd.u64()?;
    validate_timestamp(timestamp)?;
    let _random = rd.bytes(16)?;
    let rx_session_id = rd.u32()?;
    let eph_x25519_pk = rd.array::<32>()?;
    let mlkem_ct = rd.array::<{ MLKEM_CT_LEN }>()?;
    let hs1_hash = rd.array::<32>()?;
    if hs1_hash != *blake3::hash(expected_hs1_msg).as_bytes() {
        anyhow::bail!("handshake transcript mismatch");
    }
    let cert_bytes = rd.vec_u32()?;
    let cert: Cert = serde_json::from_slice(cert_bytes)?;
    let signed = &data[..rd.pos()];
    let ed25519 = rd.array::<{ hybrid_sig::ED25519_SIG_LEN }>()?;
    let ml_dsa = rd.array::<{ hybrid_sig::MLDSA_SIG_LEN }>()?;

    verify_peer_cert_and_sig(&cert, ca_vk, signed, ed25519, ml_dsa)?;

    Ok(Handshake2Plain {
        cert,
        rx_session_id,
        eph_x25519_pk,
        mlkem_ct,
        peer_is_relay: flags & FLAG_RELAY != 0,
    })
}

fn verify_peer_cert_and_sig(
    cert: &Cert,
    ca_vk: &CaVerifyKey,
    signed: &[u8],
    ed25519: [u8; hybrid_sig::ED25519_SIG_LEN],
    ml_dsa: [u8; hybrid_sig::MLDSA_SIG_LEN],
) -> anyhow::Result<()> {
    if !cert.verify(ca_vk) {
        anyhow::bail!("peer cert verification failed");
    }
    let vk = HybridVerifyKey {
        ed25519: cert.body.keys.ed25519_pk,
        ml_dsa: cert.body.keys.ml_dsa_pk,
    };
    let sig = HybridSignature { ed25519, ml_dsa };
    if !hybrid_sig::hybrid_verify(&vk, signed, &sig) {
        anyhow::bail!("peer handshake signature failed");
    }
    Ok(())
}

fn sign_node(sk: &NodeSigningSecretKey, msg: &[u8]) -> HybridSignature {
    let sk = HybridSigningKey {
        ed25519: sk.ed25519,
        ml_dsa_seed: sk.ml_dsa_seed,
    };
    hybrid_sig::hybrid_sign(&sk, msg)
}

fn derive_session_v2(
    hybrid_ss: &[u8; 64],
    hs1_msg: &[u8],
    hs2_msg: &[u8],
) -> [u8; SESSION_KEY_LEN] {
    let mut input = Zeroizing::new(Vec::with_capacity(64 + 32 + 32));
    input.extend_from_slice(hybrid_ss);
    input.extend_from_slice(blake3::hash(hs1_msg).as_bytes());
    input.extend_from_slice(blake3::hash(hs2_msg).as_bytes());
    kdf::derive_labeled_key("liteway-session-v2", input.as_slice())
}

fn handshake_header_and_payload(plaintext: &[u8]) -> (NetworkHeader, &[u8]) {
    if plaintext.len() >= 7 && plaintext[0] == KIND_HANDSHAKE_FRAG {
        let msg_id = u32::from_be_bytes([plaintext[1], plaintext[2], plaintext[3], plaintext[4]]);
        let frag_index = plaintext[5];
        let frag_total = plaintext[6];
        return (
            NetworkHeader {
                kind: KIND_HANDSHAKE_FRAG,
                frag_index,
                frag_total,
                dst_peer_id: 0,
                session_id: msg_id,
            },
            &plaintext[7..],
        );
    }

    (
        NetworkHeader {
            kind: plaintext.first().copied().unwrap_or(0),
            frag_index: 0,
            frag_total: 0,
            dst_peer_id: 0,
            session_id: 0,
        },
        plaintext,
    )
}

fn put_vec_u32(out: &mut Vec<u8>, bytes: &[u8]) {
    let len = bytes.len() as u32;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
}

fn add_random_padding(out: &mut Vec<u8>) {
    let mut pad_len = [0u8; 1];
    ThreadRng::default().fill_bytes(&mut pad_len);
    let pad_len = (pad_len[0] % 32) as usize;
    let mut padding = vec![0u8; pad_len];
    ThreadRng::default().fill_bytes(&mut padding);
    out.extend_from_slice(&padding);
}

fn unix_time_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn random_session_id() -> u32 {
    loop {
        let id: u32 = rand::random();
        if id != 0 {
            return id;
        }
    }
}

fn validate_timestamp(timestamp: u64) -> anyhow::Result<()> {
    let now = unix_time_secs();
    let min = now.saturating_sub(HANDSHAKE_MAX_CLOCK_SKEW_SECS);
    let max = now.saturating_add(HANDSHAKE_MAX_CLOCK_SKEW_SECS);
    if timestamp < min || timestamp > max {
        anyhow::bail!("handshake timestamp outside allowed clock skew");
    }
    Ok(())
}

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn pos(&self) -> usize {
        self.pos
    }

    fn bytes(&mut self, len: usize) -> anyhow::Result<&'a [u8]> {
        if self.pos + len > self.data.len() {
            anyhow::bail!("field out of bounds");
        }
        let bytes = &self.data[self.pos..self.pos + len];
        self.pos += len;
        Ok(bytes)
    }

    fn u8(&mut self) -> anyhow::Result<u8> {
        Ok(self.bytes(1)?[0])
    }

    fn u16(&mut self) -> anyhow::Result<u16> {
        Ok(u16::from_be_bytes(self.array::<2>()?))
    }

    fn u64(&mut self) -> anyhow::Result<u64> {
        Ok(u64::from_be_bytes(self.array::<8>()?))
    }

    fn array<const N: usize>(&mut self) -> anyhow::Result<[u8; N]> {
        Ok(self.bytes(N)?.try_into()?)
    }

    fn u32(&mut self) -> anyhow::Result<u32> {
        Ok(u32::from_be_bytes(self.array::<4>()?))
    }

    fn vec_u32(&mut self) -> anyhow::Result<&'a [u8]> {
        let len = self.u32()? as usize;
        self.bytes(len)
    }
}
