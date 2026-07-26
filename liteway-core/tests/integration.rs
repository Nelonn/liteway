use liteway_core::cert::{self, CaSigningKey, CaVerifyKey, Cert, NodeSigningSecretKey};
use liteway_core::config::{AppConfig, InterfaceConfig};
use liteway_core::crypto::{aead, hybrid_kem, hybrid_sig, kdf};
use liteway_core::crypto::{K_HEADER_LEN, NONCE_LEN, SESSION_KEY_LEN};
use liteway_core::frag;
use liteway_core::handshake;
use liteway_core::packet;
use rand::rngs::ThreadRng;
use rand_core::Rng;
use std::net::UdpSocket;
use std::time::Duration;

fn test_network_secret() -> [u8; 32] {
    let mut seed = [0u8; 32];
    ThreadRng::default().fill_bytes(&mut seed);
    seed
}

#[test]
fn hybrid_kem_roundtrip() {
    let (sk, pk) = hybrid_kem::generate_hybrid_keypair();
    let (eph_pk, ss1, ct) = hybrid_kem::encapsulate(&pk.x25519, &pk.ml_kem);
    let ss2 = hybrid_kem::decapsulate_static(&sk.x25519, &eph_pk.to_bytes(), &sk.ml_kem, &ct);
    assert_eq!(ss1, ss2, "shared secrets must match");
}

#[test]
fn hybrid_kem_ephemeral_roundtrip() {
    let (eph_sk, eph_pk, eph_k_sk, eph_k_pk) = hybrid_kem::generate_ephemeral();

    // responder encapsulates with initiator's ephemeral public keys
    let peer_x_pk = eph_pk.to_bytes();
    let peer_k_pk = hybrid_kem::mlkem_pk_bytes(&eph_k_pk);
    let pk_x: [u8; 32] = peer_x_pk;
    let pk_k: [u8; hybrid_kem::MLKEM_PK_LEN] = peer_k_pk;
    let (resp_eph_pk, ss1, ct) = hybrid_kem::encapsulate(&pk_x, &pk_k);

    // initiator decapsulates using responder's ephemeral public key
    let ct_bytes: [u8; hybrid_kem::MLKEM_CT_LEN] = ct;
    let resp_pk_x = resp_eph_pk.to_bytes();
    let ss2 = hybrid_kem::decapsulate(
        eph_sk,
        &resp_pk_x,
        &eph_k_sk.to_seed().unwrap().try_into().unwrap(),
        &ct_bytes,
    );
    assert_eq!(ss1, ss2, "ephemeral shared secrets must match");
}

#[test]
fn hybrid_sign_verify() {
    let (sk, vk) = hybrid_sig::generate_hybrid_keypair();
    let msg = b"hello liteway";
    let sig = hybrid_sig::hybrid_sign(&sk, msg);
    assert!(
        hybrid_sig::hybrid_verify(&vk, msg, &sig),
        "signature must verify"
    );
}

#[test]
fn hybrid_sign_verify_wrong_msg() {
    let (sk, vk) = hybrid_sig::generate_hybrid_keypair();
    let sig = hybrid_sig::hybrid_sign(&sk, b"good message");
    assert!(
        !hybrid_sig::hybrid_verify(&vk, b"bad message", &sig),
        "wrong message must not verify"
    );
}

#[test]
fn hybrid_sign_verify_wrong_key() {
    let (sk, _vk) = hybrid_sig::generate_hybrid_keypair();
    let (_, wrong_vk) = hybrid_sig::generate_hybrid_keypair();
    let sig = hybrid_sig::hybrid_sign(&sk, b"test");
    assert!(
        !hybrid_sig::hybrid_verify(&wrong_vk, b"test", &sig),
        "wrong key must not verify"
    );
}

#[test]
fn aead_roundtrip() {
    let mut key = [0u8; K_HEADER_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    ThreadRng::default().fill_bytes(&mut key);
    ThreadRng::default().fill_bytes(&mut nonce);

    let plaintext = b"secret data";
    let aad = b"additional data";
    let ct = aead::encrypt(&key, &nonce, plaintext, aad);
    let decrypted = aead::decrypt(&key, &nonce, &ct, aad).expect("decrypt must succeed");
    assert_eq!(decrypted, plaintext);
}

#[test]
fn aead_wrong_key() {
    let mut key = [0u8; K_HEADER_LEN];
    let mut wrong_key = [0u8; K_HEADER_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    ThreadRng::default().fill_bytes(&mut key);
    ThreadRng::default().fill_bytes(&mut wrong_key);
    ThreadRng::default().fill_bytes(&mut nonce);

    let ct = aead::encrypt(&key, &nonce, b"secret", b"");
    assert!(
        aead::decrypt(&wrong_key, &nonce, &ct, b"").is_none(),
        "wrong key must fail"
    );
}

#[test]
fn aead_tampered_ciphertext() {
    let mut key = [0u8; K_HEADER_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    ThreadRng::default().fill_bytes(&mut key);
    ThreadRng::default().fill_bytes(&mut nonce);

    let mut ct = aead::encrypt(&key, &nonce, b"secret", b"");
    ct[0] ^= 0xff;
    assert!(
        aead::decrypt(&key, &nonce, &ct, b"").is_none(),
        "tampered ciphertext must fail"
    );
}

#[test]
fn kdf_deterministic() {
    let input = [0xabu8; 64];
    let k1 = kdf::derive_session_key(&input);
    let k2 = kdf::derive_session_key(&input);
    assert_eq!(k1, k2, "KDF must be deterministic");
}

fn make_session_key() -> [u8; SESSION_KEY_LEN] {
    let mut k = [0u8; SESSION_KEY_LEN];
    ThreadRng::default().fill_bytes(&mut k);
    k
}

fn make_network_key() -> [u8; K_HEADER_LEN] {
    kdf::derive_network_key(&[0x42u8; 32])
}

fn decrypt_test_packet(
    data: &[u8],
    network_key: &[u8; K_HEADER_LEN],
    session_key: &[u8; SESSION_KEY_LEN],
) -> Option<packet::PacketBody> {
    packet::decrypt_packet(data, network_key, session_key).map(|(_, body)| body)
}

fn test_node_id(name: &str) -> u32 {
    u32::from_be_bytes(
        blake3::hash(name.as_bytes()).as_bytes()[..4]
            .try_into()
            .unwrap(),
    )
}

#[test]
fn packet_encrypt_decrypt_roundtrip() {
    let ip_packet =
        b"\x45\x00\x00\x30\x00\x00\x40\x00\x40\x01\x00\x00\x0a\x00\x00\x01\x0a\x00\x00\x02";
    let network_key = make_network_key();
    let session_key = make_session_key();
    let seq = 7;

    let pkt = packet::encrypt_data_packet(
        seq,
        0x01020304,
        0x05060708,
        ip_packet,
        &network_key,
        &session_key,
    );
    let serialized = packet::serialize_packet(&pkt);
    let decrypted =
        decrypt_test_packet(&serialized, &network_key, &session_key).expect("payload decrypt");
    assert_eq!(
        decrypted,
        packet::PacketBody::Data {
            seq,
            ip_packet: ip_packet.to_vec(),
        }
    );
}

#[test]
fn packet_serialize_deserialize_roundtrip() {
    let ip_packet =
        b"\x45\x00\x00\x30\x00\x00\x40\x00\x40\x01\x00\x00\x0a\x00\x00\x01\x0a\x00\x00\x02";
    let network_key = make_network_key();
    let session_key = make_session_key();

    let pkt = packet::encrypt_data_packet(
        1,
        0x01020304,
        0x05060708,
        ip_packet,
        &network_key,
        &session_key,
    );
    let serialized = packet::serialize_packet(&pkt);
    assert!(serialized.len() > packet::MIN_PACKET_LEN);

    let deserialized = packet::deserialize_packet(&serialized).expect("deserialize");
    assert_eq!(deserialized.mask_nonce, pkt.mask_nonce);
    assert_eq!(deserialized.masked_header, pkt.masked_header);
    assert_eq!(deserialized.nonce, pkt.nonce);
    assert_eq!(deserialized.ciphertext, pkt.ciphertext);
}

#[test]
fn packet_decrypt_data_packet() {
    let ip_packet =
        b"\x45\x00\x00\x30\x00\x00\x40\x00\x40\x01\x00\x00\x0a\x00\x00\x01\x0a\x00\x00\x02";
    let network_key = make_network_key();
    let session_key = make_session_key();

    let pkt = packet::encrypt_data_packet(
        42,
        0x01020304,
        0x05060708,
        ip_packet,
        &network_key,
        &session_key,
    );
    let serialized = packet::serialize_packet(&pkt);

    let result = decrypt_test_packet(&serialized, &network_key, &session_key);
    assert!(result.is_some(), "decrypt_packet must succeed");
    assert_eq!(
        result.unwrap(),
        packet::PacketBody::Data {
            seq: 42,
            ip_packet: ip_packet.to_vec(),
        }
    );
}

#[test]
fn packet_network_header_is_masked_dispatch_metadata() {
    let network_key = make_network_key();
    let wrong_network_key = kdf::derive_network_key(&[0x99u8; 32]);
    let session_key = make_session_key();
    let dst_peer_id = 0x01020304;
    let session_id = 0x05060708;

    let pkt = packet::encrypt_data_packet(
        42,
        dst_peer_id,
        session_id,
        b"payload",
        &network_key,
        &session_key,
    );
    let serialized = packet::serialize_packet(&pkt);

    let header = packet::network_header(&serialized, &network_key).expect("header must unmask");
    assert_eq!(header.kind, packet::KIND_DATA);
    assert_eq!(header.frag_index, 0);
    assert_eq!(header.frag_total, 0);
    assert_eq!(header.dst_peer_id, dst_peer_id);
    assert_eq!(header.session_id, session_id);
    assert!(
        packet::network_header(&serialized, &wrong_network_key).is_none(),
        "wrong network key must not recover dispatch header"
    );
}

#[test]
fn packet_header_is_authenticated_by_payload_tag() {
    let network_key = make_network_key();
    let session_key = make_session_key();
    let pkt = packet::encrypt_data_packet(
        1,
        0x01020304,
        0x05060708,
        b"payload",
        &network_key,
        &session_key,
    );
    let mut serialized = packet::serialize_packet(&pkt);

    serialized[packet::MASK_NONCE_LEN] ^= 0x01;
    assert!(
        packet::decrypt_packet(&serialized, &network_key, &session_key).is_none(),
        "masked header tampering must fail payload decrypt through AAD"
    );
}

#[test]
fn packet_different_session_key_fails() {
    let ip_packet =
        b"\x45\x00\x00\x30\x00\x00\x40\x00\x40\x01\x00\x00\x0a\x00\x00\x01\x0a\x00\x00\x02";
    let network_key = make_network_key();
    let session_key_a = make_session_key();
    let session_key_b = make_session_key();

    let pkt = packet::encrypt_data_packet(
        1,
        0x01020304,
        0x05060708,
        ip_packet,
        &network_key,
        &session_key_a,
    );
    let serialized = packet::serialize_packet(&pkt);
    let result = decrypt_test_packet(&serialized, &network_key, &session_key_b);
    assert!(
        result.is_none(),
        "wrong session key must fail payload decrypt"
    );
}

#[test]
fn packet_tampering_fails() {
    let ip_packet =
        b"\x45\x00\x00\x30\x00\x00\x40\x00\x40\x01\x00\x00\x0a\x00\x00\x01\x0a\x00\x00\x02";
    let network_key = make_network_key();
    let session_key = make_session_key();
    let pkt = packet::encrypt_data_packet(
        1,
        0x01020304,
        0x05060708,
        ip_packet,
        &network_key,
        &session_key,
    );
    let serialized = packet::serialize_packet(&pkt);

    for idx in [
        0,
        packet::MASK_NONCE_LEN,
        packet::MASK_NONCE_LEN + packet::NETWORK_HEADER_LEN + NONCE_LEN,
        serialized.len() - 1,
    ] {
        let mut tampered = serialized.clone();
        tampered[idx] ^= 0xff;
        assert!(
            decrypt_test_packet(&tampered, &network_key, &session_key).is_none(),
            "tampered packet byte {idx} must fail decrypt"
        );
    }
}

#[test]
fn traffic_keys_are_directional() {
    let session_key = make_session_key();
    let network_key = make_network_key();
    let a_to_b = packet::derive_traffic_key(&session_key, 1, 2);
    let b_to_a = packet::derive_traffic_key(&session_key, 2, 1);
    assert_ne!(a_to_b, b_to_a, "traffic keys must be directional");

    let pkt = packet::encrypt_data_packet(1, 2, 0x05060708, b"hello", &network_key, &a_to_b);
    let serialized = packet::serialize_packet(&pkt);
    assert!(decrypt_test_packet(&serialized, &network_key, &a_to_b).is_some());
    assert!(
        decrypt_test_packet(&serialized, &network_key, &b_to_a).is_none(),
        "opposite-direction traffic key must not decrypt"
    );
}

#[test]
fn relay_forward_packet_roundtrip() {
    let session_key = make_session_key();
    let network_key = make_network_key();
    let inner = b"inner encrypted packet";
    let pkt = packet::encrypt_relay_forward_packet(
        9,
        0x01020304,
        0x05060708,
        0x01020304,
        inner,
        &network_key,
        &session_key,
    );
    let serialized = packet::serialize_packet(&pkt);

    assert_eq!(
        decrypt_test_packet(&serialized, &network_key, &session_key).unwrap(),
        packet::PacketBody::RelayForward {
            seq: 9,
            next_peer_id: 0x01020304,
            inner_packet: inner.to_vec(),
        }
    );
}

#[test]
fn lighthouse_query_packet_roundtrip() {
    let session_key = make_session_key();
    let network_key = make_network_key();
    let target_ip = "10.0.0.12".parse().unwrap();
    let pkt = packet::encrypt_lighthouse_query_packet(
        11,
        0x01020304,
        0x05060708,
        target_ip,
        &network_key,
        &session_key,
    );
    let serialized = packet::serialize_packet(&pkt);

    assert_eq!(
        decrypt_test_packet(&serialized, &network_key, &session_key).unwrap(),
        packet::PacketBody::LighthouseQuery { seq: 11, target_ip }
    );
}

#[test]
fn lighthouse_response_packet_roundtrip() {
    let (ca_sk, _ca_vk, _network_secret) = make_ca();
    let node = make_node("resolved-node", "10.0.0.12/24", &ca_sk);
    let session_key = make_session_key();
    let network_key = make_network_key();
    let target_ip = "10.0.0.12".parse().unwrap();
    let peer_addr = "127.0.0.1:4242".parse().unwrap();
    let pkt = packet::encrypt_lighthouse_response_packet(
        12,
        0x01020304,
        0x05060708,
        target_ip,
        0x01020304,
        peer_addr,
        &node.cert,
        false,
        &network_key,
        &session_key,
    );
    let serialized = packet::serialize_packet(&pkt);

    assert_eq!(
        decrypt_test_packet(&serialized, &network_key, &session_key).unwrap(),
        packet::PacketBody::LighthouseResponse {
            seq: 12,
            target_ip,
            peer_id: 0x01020304,
            peer_addr,
            peer_cert: node.cert,
            peer_is_relay: false,
        }
    );
}

#[test]
fn lighthouse_not_found_packet_roundtrip() {
    let session_key = make_session_key();
    let network_key = make_network_key();
    let target_ip = "10.0.0.99".parse().unwrap();
    let pkt = packet::encrypt_lighthouse_not_found_packet(
        13,
        0x01020304,
        0x05060708,
        target_ip,
        &network_key,
        &session_key,
    );
    let serialized = packet::serialize_packet(&pkt);

    assert_eq!(
        decrypt_test_packet(&serialized, &network_key, &session_key).unwrap(),
        packet::PacketBody::LighthouseNotFound { seq: 13, target_ip }
    );
}

#[test]
fn keepalive_packet_roundtrip() {
    let session_key = make_session_key();
    let network_key = make_network_key();
    let pkt = packet::encrypt_keepalive_packet(
        14,
        0x01020304,
        0x05060708,
        0xaabbccddeeff0011,
        &network_key,
        &session_key,
    );
    let serialized = packet::serialize_packet(&pkt);

    assert_eq!(
        decrypt_test_packet(&serialized, &network_key, &session_key).unwrap(),
        packet::PacketBody::Keepalive {
            seq: 14,
            token: 0xaabbccddeeff0011,
        }
    );
}

#[test]
fn keepalive_ack_packet_roundtrip() {
    let session_key = make_session_key();
    let network_key = make_network_key();
    let pkt = packet::encrypt_keepalive_ack_packet(
        15,
        0x01020304,
        0x05060708,
        0x1122334455667788,
        &network_key,
        &session_key,
    );
    let serialized = packet::serialize_packet(&pkt);

    assert_eq!(
        decrypt_test_packet(&serialized, &network_key, &session_key).unwrap(),
        packet::PacketBody::KeepaliveAck {
            seq: 15,
            token: 0x1122334455667788,
        }
    );
}

#[test]
fn relay_forward_outer_and_inner_keys_are_separate() {
    let direct_key = make_session_key();
    let relay_key = make_session_key();
    let network_key = make_network_key();

    let inner = packet::encrypt_data_packet(
        3,
        0x01020304,
        0x05060708,
        b"direct payload",
        &network_key,
        &direct_key,
    );
    let inner_bytes = packet::serialize_packet(&inner);
    let outer = packet::encrypt_relay_forward_packet(
        4,
        99,
        0x11121314,
        99,
        &inner_bytes,
        &network_key,
        &relay_key,
    );
    let outer_bytes = packet::serialize_packet(&outer);

    assert!(
        decrypt_test_packet(&outer_bytes, &network_key, &direct_key).is_none(),
        "direct peer key must not decrypt relay wrapper"
    );

    let packet::PacketBody::RelayForward {
        seq,
        next_peer_id,
        inner_packet,
    } = decrypt_test_packet(&outer_bytes, &network_key, &relay_key).expect("relay wrapper decrypt")
    else {
        panic!("relay wrapper must decrypt to RelayForward");
    };
    assert_eq!(seq, 4);
    assert_eq!(next_peer_id, 99);
    assert_eq!(inner_packet, inner_bytes);
    assert!(
        decrypt_test_packet(&inner_packet, &network_key, &relay_key).is_none(),
        "relay key must not decrypt inner direct packet"
    );
    assert_eq!(
        decrypt_test_packet(&inner_packet, &network_key, &direct_key).unwrap(),
        packet::PacketBody::Data {
            seq: 3,
            ip_packet: b"direct payload".to_vec(),
        }
    );
}

fn app_config_with_secret(network_secret: &str) -> AppConfig {
    AppConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        ca_cert_path: "ca.toml".to_string(),
        node_cert_path: "node-cert.toml".to_string(),
        node_key_path: "node-key.toml".to_string(),
        network_secret: network_secret.to_string(),
        lighthouses: vec![],
        interface: Some(InterfaceConfig::default()),
        am_lighthouse: false,
        am_relay: false,
        punch_interval_secs: 10,
        keepalive_punch: true,
        keepalive_timeout_secs: 30,
        relay_fallback_timeout_secs: 5,
    }
}

#[test]
fn config_network_secret_validates_hex_32_bytes() {
    let cfg = app_config_with_secret(&"11".repeat(32));
    assert_eq!(cfg.network_secret().unwrap(), [0x11; 32]);
}

#[test]
fn app_config_toml_uses_network_secret_name() {
    let cfg: AppConfig = toml::from_str(&format!(
        r#"
ca_cert_path = "ca.toml"
node_cert_path = "node-cert.toml"
node_key_path = "node-key.toml"
network_secret = "{}"
"#,
        "22".repeat(32)
    ))
    .unwrap();

    assert_eq!(cfg.network_secret().unwrap(), [0x22; 32]);
}

#[test]
fn app_config_lighthouse_address_accepts_domain() {
    let cfg: AppConfig = toml::from_str(&format!(
        r#"
ca_cert_path = "ca.toml"
node_cert_path = "node-cert.toml"
node_key_path = "node-key.toml"
network_secret = "{}"

[[lighthouses]]
name = "lh-domain"
address = "lh.example.test:4242"
"#,
        "22".repeat(32)
    ))
    .unwrap();

    assert_eq!(cfg.lighthouses[0].name, "lh-domain");
    assert_eq!(cfg.lighthouses[0].address, "lh.example.test:4242");
}

#[test]
fn config_network_secret_invalid_fails() {
    assert!(app_config_with_secret("not-hex").network_secret().is_err());
    assert!(app_config_with_secret("").network_secret().is_err());
    assert!(app_config_with_secret(&"11".repeat(31))
        .network_secret()
        .is_err());
    assert!(app_config_with_secret(&"11".repeat(33))
        .network_secret()
        .is_err());
}

fn make_ca() -> (CaSigningKey, CaVerifyKey, [u8; 32]) {
    let ca = cert::generate_ca("test-ca", 10, &[]);
    let vk = CaVerifyKey {
        ed25519: ca.cert.verify_key.ed25519,
        ml_dsa: ca.cert.verify_key.ml_dsa,
    };
    (ca.signing_key, vk, test_network_secret())
}

struct TestNode {
    cert: Cert,
    signing_secret_key: NodeSigningSecretKey,
}

fn make_node(name: &str, ip: &str, ca_sk: &CaSigningKey) -> TestNode {
    let (cert, key_file) = cert::generate_node(name, ip, &[], &[], ca_sk, 30);
    TestNode {
        cert,
        signing_secret_key: key_file.signing_secret_key,
    }
}

#[test]
fn handshake_full_roundtrip() {
    let (ca_sk, ca_vk, network_secret) = make_ca();
    let network_key = kdf::derive_network_key(&network_secret);

    let alice = make_node("alice", "10.0.0.1/24", &ca_sk);
    let bob = make_node("bob", "10.0.0.2/24", &ca_sk);

    // Alice -> Bob: handshake 1
    let init =
        handshake::create_handshake_1(&alice.cert, &alice.signing_secret_key, &network_key, false);

    // Bob receives and responds
    let resp = handshake::process_handshake_1(
        &init.msg,
        &bob.cert,
        &bob.signing_secret_key,
        &network_key,
        &ca_vk,
        false,
    )
    .expect("handshake 1 must succeed");

    assert_eq!(
        resp.peer_cert.body.meta.name, "alice",
        "responder sees alice's cert"
    );

    // Alice processes handshake 2
    let result = handshake::process_handshake_2(&resp.msg, init, &network_key, &ca_vk)
        .expect("handshake 2 must succeed");

    assert_eq!(
        result.peer_cert.body.meta.name, "bob",
        "initiator sees bob's cert"
    );

    assert_eq!(
        resp.session_key, result.session_key,
        "both sides must derive the same session key"
    );
    assert_eq!(
        resp.session_key.len(),
        SESSION_KEY_LEN,
        "session key must be correct length"
    );
}

#[test]
fn handshake_wrong_network_key_fails() {
    let (ca_sk, ca_vk, network_secret) = make_ca();
    let network_key = kdf::derive_network_key(&network_secret);
    let wrong_key = kdf::derive_network_key(&[0x99u8; 32]);

    let alice = make_node("alice", "10.0.0.1/24", &ca_sk);
    let bob = make_node("bob", "10.0.0.2/24", &ca_sk);

    let init =
        handshake::create_handshake_1(&alice.cert, &alice.signing_secret_key, &network_key, false);
    let resp = handshake::process_handshake_1(
        &init.msg,
        &bob.cert,
        &bob.signing_secret_key,
        &wrong_key,
        &ca_vk,
        false,
    );
    assert!(resp.is_err(), "wrong network key must fail handshake 1");
}

#[test]
fn handshake_kind_requires_network_key() {
    let (ca_sk, _ca_vk, network_secret) = make_ca();
    let network_key = kdf::derive_network_key(&network_secret);
    let wrong_key = kdf::derive_network_key(&[0x99u8; 32]);

    let alice = make_node("alice", "10.0.0.1/24", &ca_sk);
    let init =
        handshake::create_handshake_1(&alice.cert, &alice.signing_secret_key, &network_key, false);
    assert_eq!(
        handshake::handshake_kind(&init.msg, &network_key),
        Some(handshake::KIND_HANDSHAKE_1)
    );
    assert_eq!(handshake::handshake_kind(&init.msg, &wrong_key), None);

    let data_pkt = packet::encrypt_data_packet(
        1,
        0x01020304,
        0x05060708,
        b"ip payload",
        &network_key,
        &make_session_key(),
    );
    let data_bytes = packet::serialize_packet(&data_pkt);
    assert_eq!(
        handshake::handshake_kind(&data_bytes, &network_key),
        Some(packet::KIND_DATA)
    );
}

#[test]
fn handshake_fragment_metadata_is_in_masked_header() {
    let (_ca_sk, _ca_vk, network_secret) = make_ca();
    let network_key = kdf::derive_network_key(&network_secret);
    let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
    let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
    receiver
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let receiver_addr = receiver.local_addr().unwrap();
    let message = b"fragmented handshake-like payload that needs multiple datagrams";
    let max_datagram = packet::PACKET_OVERHEAD + 8;

    frag::send_fragmented(&sender, message, receiver_addr, &network_key, max_datagram)
        .expect("fragment send must succeed");

    let mut assembler = frag::FragmentAssembler::new();
    let mut buf = [0u8; 2048];
    let mut first_header = None;
    loop {
        let (len, src) = receiver.recv_from(&mut buf).unwrap();
        let header =
            packet::network_header(&buf[..len], &network_key).expect("fragment header must unmask");
        if first_header.is_none() {
            first_header = Some(header);
        }
        match assembler.feed(src, &buf[..len], &network_key) {
            frag::FeedResult::Complete(assembled) => {
                assert_eq!(assembled, message);
                break;
            }
            frag::FeedResult::Buffered => {}
            frag::FeedResult::NotFragment => panic!("fragment packet must be recognized"),
        }
    }

    let header = first_header.expect("at least one fragment must be received");
    assert_eq!(header.kind, handshake::KIND_HANDSHAKE_FRAG);
    assert_eq!(header.frag_index, 0);
    assert!(header.frag_total > 1);
    assert_ne!(
        header.session_id, 0,
        "fragment msg_id is carried in session_id field"
    );
}

#[test]
fn handshake_relay_flag_roundtrip() {
    let (ca_sk, ca_vk, network_secret) = make_ca();
    let network_key = kdf::derive_network_key(&network_secret);

    let alice = make_node("alice", "10.0.0.1/24", &ca_sk);
    let bob = make_node("bob", "10.0.0.2/24", &ca_sk);

    // Alice indicates she is a relay
    let init =
        handshake::create_handshake_1(&alice.cert, &alice.signing_secret_key, &network_key, true);
    let resp = handshake::process_handshake_1(
        &init.msg,
        &bob.cert,
        &bob.signing_secret_key,
        &network_key,
        &ca_vk,
        false,
    )
    .expect("handshake 1 must succeed");

    assert!(resp.peer_is_relay, "bob must see alice as relay");
}

#[test]
fn handshake_wrong_ca_fails() {
    let (ca_sk_a, _ca_vk_a, network_secret_a) = make_ca();
    let (_, ca_vk_b, _) = make_ca();
    let network_key = kdf::derive_network_key(&network_secret_a);

    let alice = make_node("alice", "10.0.0.1/24", &ca_sk_a);
    let bob = make_node("bob", "10.0.0.2/24", &ca_sk_a);

    let init =
        handshake::create_handshake_1(&alice.cert, &alice.signing_secret_key, &network_key, false);
    let resp = handshake::process_handshake_1(
        &init.msg,
        &bob.cert,
        &bob.signing_secret_key,
        &network_key,
        &ca_vk_b,
        false,
    );
    assert!(
        resp.is_err(),
        "wrong CA verify key must fail cert verification"
    );
}

#[test]
fn handshake_copied_cert_without_signing_key_fails() {
    let (ca_sk, ca_vk, network_secret) = make_ca();
    let network_key = kdf::derive_network_key(&network_secret);

    let alice = make_node("alice", "10.0.0.1/24", &ca_sk);
    let bob = make_node("bob", "10.0.0.2/24", &ca_sk);

    let forged =
        handshake::create_handshake_1(&alice.cert, &bob.signing_secret_key, &network_key, false);
    let resp = handshake::process_handshake_1(
        &forged.msg,
        &bob.cert,
        &bob.signing_secret_key,
        &network_key,
        &ca_vk,
        false,
    );
    assert!(
        resp.is_err(),
        "copied cert without its signing key must fail handshake"
    );
}

#[test]
fn handshake_1_tampering_fails() {
    let (ca_sk, ca_vk, network_secret) = make_ca();
    let network_key = kdf::derive_network_key(&network_secret);

    let alice = make_node("alice", "10.0.0.1/24", &ca_sk);
    let bob = make_node("bob", "10.0.0.2/24", &ca_sk);
    let init =
        handshake::create_handshake_1(&alice.cert, &alice.signing_secret_key, &network_key, false);

    for idx in [0, 16, 28, init.msg.len() - 1] {
        let mut tampered = init.msg.clone();
        tampered[idx] ^= 0xff;
        let resp = handshake::process_handshake_1(
            &tampered,
            &bob.cert,
            &bob.signing_secret_key,
            &network_key,
            &ca_vk,
            false,
        );
        assert!(resp.is_err(), "tampered handshake_1 byte {idx} must fail");
    }
}

#[test]
fn handshake_2_wrong_signing_key_fails() {
    let (ca_sk, ca_vk, network_secret) = make_ca();
    let network_key = kdf::derive_network_key(&network_secret);

    let alice = make_node("alice", "10.0.0.1/24", &ca_sk);
    let bob = make_node("bob", "10.0.0.2/24", &ca_sk);
    let mallory = make_node("mallory", "10.0.0.3/24", &ca_sk);

    let init =
        handshake::create_handshake_1(&alice.cert, &alice.signing_secret_key, &network_key, false);
    let resp = handshake::process_handshake_1(
        &init.msg,
        &bob.cert,
        &mallory.signing_secret_key,
        &network_key,
        &ca_vk,
        false,
    )
    .expect("handshake_1 processing itself should succeed");

    assert!(
        handshake::process_handshake_2(&resp.msg, init, &network_key, &ca_vk).is_err(),
        "handshake_2 signed by a key outside Bob cert must fail"
    );
}

#[test]
fn handshake_2_tampering_fails() {
    let (ca_sk, ca_vk, network_secret) = make_ca();
    let network_key = kdf::derive_network_key(&network_secret);

    let alice = make_node("alice", "10.0.0.1/24", &ca_sk);
    let bob = make_node("bob", "10.0.0.2/24", &ca_sk);
    let init =
        handshake::create_handshake_1(&alice.cert, &alice.signing_secret_key, &network_key, false);
    let resp = handshake::process_handshake_1(
        &init.msg,
        &bob.cert,
        &bob.signing_secret_key,
        &network_key,
        &ca_vk,
        false,
    )
    .expect("handshake_1 must succeed");

    for case in 0..4 {
        let init_for_tamper = handshake::create_handshake_1(
            &alice.cert,
            &alice.signing_secret_key,
            &network_key,
            false,
        );
        let fresh_resp = handshake::process_handshake_1(
            &init_for_tamper.msg,
            &bob.cert,
            &bob.signing_secret_key,
            &network_key,
            &ca_vk,
            false,
        )
        .expect("fresh handshake_1 must succeed");
        let mut tampered = fresh_resp.msg.clone();
        let idx = match case {
            0 => 0,
            1 => 16,
            2 => 28,
            _ => tampered.len() - 1,
        };
        tampered[idx] ^= 0xff;
        assert!(
            handshake::process_handshake_2(&tampered, init_for_tamper, &network_key, &ca_vk)
                .is_err(),
            "tampered handshake_2 byte {idx} must fail"
        );
    }

    assert!(
        handshake::process_handshake_2(&resp.msg, init, &network_key, &ca_vk).is_ok(),
        "untampered control handshake should still succeed"
    );
}

#[test]
fn cert_generate_verify() {
    let (ca_sk, ca_vk, _) = make_ca();
    let node = make_node("test-node", "10.0.0.1/24", &ca_sk);
    assert!(
        node.cert.verify(&ca_vk),
        "cert must verify with correct CA key"
    );
}

#[test]
fn cert_wrong_ca_fails() {
    let (ca_sk, _ca_vk, _) = make_ca();
    let (_, wrong_vk, _) = make_ca();
    let node = make_node("test-node", "10.0.0.1/24", &ca_sk);
    assert!(
        !node.cert.verify(&wrong_vk),
        "cert from different CA must not verify"
    );
}

#[test]
fn cert_generate_ca_struct() {
    let full = cert::generate_ca("test-ca-root", 10, &[]);
    assert!(full.cert.meta.is_ca, "CA cert must have is_ca=true");
    assert_eq!(full.cert.meta.name, "test-ca-root");
    assert!(
        full.signing_key.ed25519.iter().any(|&b| b != 0),
        "signing key should be non-zero"
    );
    assert!(
        full.cert.verify_key.ed25519.iter().any(|&b| b != 0),
        "verify key should be non-zero"
    );
    let (_, ca_vk, _) = make_ca();
    // structural check: key sizes match
    assert_eq!(full.cert.verify_key.ml_dsa.len(), ca_vk.ml_dsa.len());
}

#[test]
fn cert_ca_verify_self_fails() {
    let (ca_sk, _ca_vk, _network_secret) = make_ca();
    let node = make_node("node", "10.0.0.1/24", &ca_sk);
    let ca_cert_bytes = serde_json::to_vec(&ca_sk).unwrap();
    let ca_cert_deser: cert::CaSigningKey = serde_json::from_slice(&ca_cert_bytes).unwrap();
    assert_eq!(ca_cert_deser.ed25519, ca_sk.ed25519);
    assert_eq!(ca_cert_deser.ml_dsa_seed, ca_sk.ml_dsa_seed);
    // a non-CA node cert should not be is_ca
    assert!(
        !node.cert.body.meta.is_ca,
        "node cert must have is_ca=false"
    );
}

#[test]
fn cert_groups_roundtrip() {
    let (ca_sk, _ca_vk, _network_secret) = make_ca();
    let groups = vec!["engineering".to_string(), "web".to_string()];
    let (node, _node_key) =
        cert::generate_node("group-node", "10.0.0.1/24", &[], &groups, &ca_sk, 30);
    assert_eq!(node.body.meta.groups, vec!["engineering", "web"]);

    let json = serde_json::to_string(&node).unwrap();
    let cert2: cert::Cert = serde_json::from_str(&json).unwrap();
    assert_eq!(cert2.body.meta.groups, vec!["engineering", "web"]);
}

#[test]
fn cert_body_roundtrip() {
    let (ca_sk, _ca_vk, _network_secret) = make_ca();
    let node = make_node("roundtrip-node", "10.0.0.1/24", &ca_sk);
    let bytes = node.cert.body.to_bytes();
    let body2 = cert::CertBody::from_bytes(&bytes).expect("deserialize CertBody");
    assert_eq!(body2.meta.name, "roundtrip-node");
    assert_eq!(body2.keys.ed25519_pk, node.cert.body.keys.ed25519_pk);
    assert_eq!(body2.keys.ml_dsa_pk, node.cert.body.keys.ml_dsa_pk);
    assert_eq!(body2.addresses.as_ref().unwrap().ip, "10.0.0.1/24");
}

#[test]
fn cert_body_from_bytes_invalid() {
    assert!(cert::CertBody::from_bytes(b"not json").is_err());
}

#[test]
fn cert_sign_direct() {
    let (ca_sk, ca_vk, _network_secret) = make_ca();
    let body = cert::CertBody {
        meta: cert::CertMeta {
            name: "direct-signed".to_string(),
            is_ca: false,
            not_before: chrono::Utc::now(),
            not_after: chrono::Utc::now() + chrono::Duration::days(30),
            groups: vec![],
        },
        keys: cert::KeyMaterial {
            ed25519_pk: [0xccu8; 32],
            ml_dsa_pk: [0xddu8; 1952],
        },
        addresses: None,
    };
    let cert_obj = cert::Cert::sign(body, &ca_sk);
    assert!(cert_obj.verify(&ca_vk), "directly signed cert must verify");
}

#[test]
fn cert_serde_roundtrip() {
    let (ca_sk, ca_vk, _network_secret) = make_ca();
    let node = make_node("serde-node", "10.0.0.1/24", &ca_sk);
    let json = serde_json::to_string(&node.cert).unwrap();
    let cert2: cert::Cert = serde_json::from_str(&json).unwrap();
    assert!(cert2.verify(&ca_vk), "deserialized cert must verify");
}

#[test]
fn cert_full_ca_serde_roundtrip() {
    let full = cert::generate_ca("serde-ca", 10, &[]);
    let json = serde_json::to_string(&full).unwrap();
    let full2: cert::FullCaCert = serde_json::from_str(&json).unwrap();
    assert_eq!(full2.cert.meta.name, "serde-ca");
    assert!(full2.cert.meta.is_ca);
    assert_eq!(full2.cert.verify_key.ed25519, full.cert.verify_key.ed25519);
    assert_eq!(full2.cert.verify_key.ml_dsa, full.cert.verify_key.ml_dsa);
    assert_eq!(full2.signing_key.ed25519, full.signing_key.ed25519);
    assert_eq!(full2.signing_key.ml_dsa_seed, full.signing_key.ml_dsa_seed);
}

#[test]
fn cert_expired_fails() {
    let (ca_sk, ca_vk, _network_secret) = make_ca();
    let past = chrono::Utc::now() - chrono::Duration::days(365);
    let body = cert::CertBody {
        meta: cert::CertMeta {
            name: "expired".to_string(),
            is_ca: false,
            not_before: past - chrono::Duration::days(30),
            not_after: past, // expired 365 days ago
            groups: vec![],
        },
        keys: cert::KeyMaterial {
            ed25519_pk: [0xccu8; 32],
            ml_dsa_pk: [0xddu8; 1952],
        },
        addresses: None,
    };
    let cert_obj = cert::Cert::sign(body, &ca_sk);
    assert!(!cert_obj.verify(&ca_vk), "expired cert must not verify");
}

#[test]
fn cert_not_yet_valid_fails() {
    let (ca_sk, ca_vk, _network_secret) = make_ca();
    let future = chrono::Utc::now() + chrono::Duration::days(30);
    let body = cert::CertBody {
        meta: cert::CertMeta {
            name: "future".to_string(),
            is_ca: false,
            not_before: future,
            not_after: future + chrono::Duration::days(30),
            groups: vec![],
        },
        keys: cert::KeyMaterial {
            ed25519_pk: [0xccu8; 32],
            ml_dsa_pk: [0xddu8; 1952],
        },
        addresses: None,
    };
    let cert_obj = cert::Cert::sign(body, &ca_sk);
    assert!(!cert_obj.verify(&ca_vk), "future cert must not verify");
}

#[test]
fn cert_tampered_signature_fails() {
    let (ca_sk, ca_vk, _network_secret) = make_ca();
    let node = make_node("tampered", "10.0.0.1/24", &ca_sk);
    let mut cert2 = node.cert.clone();
    cert2.signature.ed25519[0] ^= 0xff;
    assert!(!cert2.verify(&ca_vk), "tampered signature must not verify");
}

#[test]
fn cert_generate_node_subnets() {
    let (ca_sk, ca_vk, _network_secret) = make_ca();
    let subnets = vec!["192.168.1.0/24".to_string(), "10.0.0.0/8".to_string()];
    let (node, _node_key) =
        cert::generate_node("subnet-node", "10.0.0.1/24", &subnets, &[], &ca_sk, 30);
    assert!(node.verify(&ca_vk));
    let addrs = node.body.addresses.unwrap();
    assert_eq!(addrs.ip, "10.0.0.1/24");
    assert_eq!(addrs.subnets.len(), 2);
    assert!(addrs.subnets.contains(&"192.168.1.0/24".to_string()));
    assert!(addrs.subnets.contains(&"10.0.0.0/8".to_string()));
}

#[test]
fn cert_key_material_serde() {
    let km = cert::KeyMaterial {
        ed25519_pk: [3u8; 32],
        ml_dsa_pk: [4u8; 1952],
    };
    let json = serde_json::to_string(&km).unwrap();
    let km2: cert::KeyMaterial = serde_json::from_str(&json).unwrap();
    assert_eq!(km2.ed25519_pk, km.ed25519_pk);
    assert_eq!(km2.ml_dsa_pk, km.ml_dsa_pk);
}

#[test]
fn cert_signing_key_drop_zeroizes() {
    let (ca_sk, _ca_vk, _network_secret) = make_ca();
    let node = make_node("zeroize-test", "10.0.0.1/24", &ca_sk);
    let sk = node.signing_secret_key;
    let ed25519_before = sk.ed25519;
    let ml_dsa_before = sk.ml_dsa_seed;
    assert!(
        ed25519_before.iter().any(|&b| b != 0),
        "ed25519 key should be non-zero before drop"
    );
    assert!(
        ml_dsa_before.iter().any(|&b| b != 0),
        "ml_dsa key should be non-zero before drop"
    );
    drop(sk);
}

fn recv_full(sock: &UdpSocket, buf: &mut [u8]) -> (usize, std::net::SocketAddr) {
    loop {
        match sock.recv_from(buf) {
            Ok(v) => return v,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => panic!("recv_from failed: {e}"),
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn udp_handshake(
    init_sock: &UdpSocket,
    resp_sock: &UdpSocket,
    resp_addr: std::net::SocketAddr,
    alice_cert: &cert::Cert,
    alice_sign_sk: &cert::NodeSigningSecretKey,
    bob_cert: &cert::Cert,
    bob_sign_sk: &cert::NodeSigningSecretKey,
    network_key: &[u8; K_HEADER_LEN],
    ca_vk: &CaVerifyKey,
    relay_flag: bool,
) -> ([u8; SESSION_KEY_LEN], [u8; SESSION_KEY_LEN]) {
    let init = handshake::create_handshake_1(alice_cert, alice_sign_sk, network_key, relay_flag);
    init_sock.send_to(&init.msg, resp_addr).unwrap();

    let mut buf = [0u8; 65535];
    let (len, src) = recv_full(resp_sock, &mut buf);
    let resp = handshake::process_handshake_1(
        &buf[..len],
        bob_cert,
        bob_sign_sk,
        network_key,
        ca_vk,
        false,
    )
    .expect("handshake 1 must succeed");
    let bob_session = resp.session_key;
    resp_sock.send_to(&resp.msg, src).unwrap();

    let (len, _) = recv_full(init_sock, &mut buf);
    let result = handshake::process_handshake_2(&buf[..len], init, network_key, ca_vk)
        .expect("handshake 2 must succeed");
    let alice_session = result.session_key;

    assert_eq!(
        bob_session, alice_session,
        "both sides must derive same session key"
    );
    (alice_session, bob_session)
}

#[test]
fn udp_handshake_roundtrip() {
    let (ca_sk, ca_vk, network_secret) = make_ca();
    let network_key = kdf::derive_network_key(&network_secret);
    let alice = make_node("alice-udp", "10.0.0.1/24", &ca_sk);
    let bob = make_node("bob-udp", "10.0.0.2/24", &ca_sk);

    let alice_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let bob_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let bob_addr = bob_sock.local_addr().unwrap();

    udp_handshake(
        &alice_sock,
        &bob_sock,
        bob_addr,
        &alice.cert,
        &alice.signing_secret_key,
        &bob.cert,
        &bob.signing_secret_key,
        &network_key,
        &ca_vk,
        false,
    );
}

#[test]
fn udp_relay_handshake_flag() {
    let (ca_sk, ca_vk, network_secret) = make_ca();
    let network_key = kdf::derive_network_key(&network_secret);
    let relay_node = make_node("relay", "10.0.0.1/24", &ca_sk);
    let client = make_node("client", "10.0.0.2/24", &ca_sk);

    let client_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let relay_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let relay_addr = relay_sock.local_addr().unwrap();

    let init = handshake::create_handshake_1(
        &client.cert,
        &client.signing_secret_key,
        &network_key,
        false,
    );
    client_sock.send_to(&init.msg, relay_addr).unwrap();

    let mut buf = [0u8; 65535];
    let (len, src) = recv_full(&relay_sock, &mut buf);
    let resp = handshake::process_handshake_1(
        &buf[..len],
        &relay_node.cert,
        &relay_node.signing_secret_key,
        &network_key,
        &ca_vk,
        true,
    )
    .expect("handshake 1 must succeed");
    assert!(
        !resp.peer_is_relay,
        "relay didn't set relay_flag, so client should see false"
    );

    let init2 = handshake::create_handshake_1(
        &relay_node.cert,
        &relay_node.signing_secret_key,
        &network_key,
        true,
    );
    relay_sock.send_to(&init2.msg, src).unwrap();

    let (len, _) = recv_full(&client_sock, &mut buf);
    let resp2 = handshake::process_handshake_1(
        &buf[..len],
        &client.cert,
        &client.signing_secret_key,
        &network_key,
        &ca_vk,
        false,
    )
    .expect("handshake 1 must succeed");
    assert!(resp2.peer_is_relay, "client must see relay's relay_flag");
}

#[test]
fn udp_encrypted_data_roundtrip() {
    let (ca_sk, ca_vk, network_secret) = make_ca();
    let network_key = kdf::derive_network_key(&network_secret);
    let alice = make_node("alice-data", "10.0.0.1/24", &ca_sk);
    let bob = make_node("bob-data", "10.0.0.2/24", &ca_sk);

    let alice_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let bob_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    bob_sock
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let bob_addr = bob_sock.local_addr().unwrap();

    let (alice_session, bob_session) = udp_handshake(
        &alice_sock,
        &bob_sock,
        bob_addr,
        &alice.cert,
        &alice.signing_secret_key,
        &bob.cert,
        &bob.signing_secret_key,
        &network_key,
        &ca_vk,
        false,
    );
    let alice_id = test_node_id("alice-data");
    let bob_id = test_node_id("bob-data");
    let alice_tx = packet::derive_traffic_key(&alice_session, alice_id, bob_id);
    let bob_rx = packet::derive_traffic_key(&bob_session, alice_id, bob_id);

    let ip_packet = b"\x45\x00\x00\x2e\x00\x01\x00\x00\x40\x11\x7a\x0a\x0a\x00\x00\x01\x0a\x00\x00\x02\x08\x00\x6a\xeb\x00\x01\x00\x00\x48\x65\x6c\x6c\x6f\x20\x4c\x69\x74\x65\x77\x61\x79\x21";

    // Alice encrypts and sends
    let pkt =
        packet::encrypt_data_packet(1, bob_id, 0x05060708, ip_packet, &network_key, &alice_tx);
    let serialized = packet::serialize_packet(&pkt);
    alice_sock.send_to(&serialized, bob_addr).unwrap();

    // Bob receives and decrypts
    let mut buf = [0u8; 65535];
    let (len, _) = bob_sock.recv_from(&mut buf).unwrap();

    let decrypted =
        decrypt_test_packet(&buf[..len], &network_key, &bob_rx).expect("must decrypt successfully");
    assert_eq!(
        decrypted,
        packet::PacketBody::Data {
            seq: 1,
            ip_packet: ip_packet.to_vec(),
        }
    );
}

#[test]
fn udp_relay_forward() {
    let (ca_sk, ca_vk, network_secret) = make_ca();
    let network_key = kdf::derive_network_key(&network_secret);
    let alice = make_node("alice-rel", "10.0.0.1/24", &ca_sk);
    let bob = make_node("bob-rel", "10.0.0.2/24", &ca_sk);
    let relay = make_node("relay-node", "10.0.0.3/24", &ca_sk);

    let alice_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let bob_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    bob_sock
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let relay_sock = UdpSocket::bind("127.0.0.1:0").unwrap();

    let bob_addr = bob_sock.local_addr().unwrap();
    let relay_addr = relay_sock.local_addr().unwrap();

    let alice_id = test_node_id("alice-rel");
    let bob_id = test_node_id("bob-rel");
    let relay_id = test_node_id("relay-node");
    // Handshake alice<->bob so alice has bob's session_key for payload encryption
    let (alice_bob_session, bob_alice_session) = udp_handshake(
        &alice_sock,
        &bob_sock,
        bob_addr,
        &alice.cert,
        &alice.signing_secret_key,
        &bob.cert,
        &bob.signing_secret_key,
        &network_key,
        &ca_vk,
        false,
    );
    // Handshake relay<->bob so relay knows bob's addr and session key
    udp_handshake(
        &relay_sock,
        &bob_sock,
        bob_addr,
        &relay.cert,
        &relay.signing_secret_key,
        &bob.cert,
        &bob.signing_secret_key,
        &network_key,
        &ca_vk,
        false,
    );
    // Handshake alice<->relay so both know each other's session metadata
    let (alice_relay_session, relay_alice_session) = udp_handshake(
        &alice_sock,
        &relay_sock,
        relay_addr,
        &alice.cert,
        &alice.signing_secret_key,
        &relay.cert,
        &relay.signing_secret_key,
        &network_key,
        &ca_vk,
        true,
    );
    let alice_bob_tx = packet::derive_traffic_key(&alice_bob_session, alice_id, bob_id);
    let bob_alice_rx = packet::derive_traffic_key(&bob_alice_session, alice_id, bob_id);
    let alice_relay_tx = packet::derive_traffic_key(&alice_relay_session, alice_id, relay_id);
    let relay_alice_rx = packet::derive_traffic_key(&relay_alice_session, alice_id, relay_id);

    // Alice wraps an inner Bob packet into an outer relay-forward packet.
    let ip_packet = b"\x45\x00\x00\x2e\x00\x01\x00\x00\x40\x11\x7a\x0a\x0a\x00\x00\x01\x0a\x00\x00\x02\x08\x00\x6a\xeb\x00\x01\x00\x00\x48\x65\x6c\x6c\x6f\x20\x4c\x69\x74\x65\x77\x61\x79\x21";
    let inner = packet::serialize_packet(&packet::encrypt_data_packet(
        1,
        bob_id,
        0x05060708,
        ip_packet,
        &network_key,
        &alice_bob_tx,
    ));
    let outer = packet::encrypt_relay_forward_packet(
        1,
        relay_id,
        0x11121314,
        bob_id,
        &inner,
        &network_key,
        &alice_relay_tx,
    );
    let serialized = packet::serialize_packet(&outer);
    alice_sock.send_to(&serialized, relay_addr).unwrap();

    // Relay receives, decrypts only the outer packet, forwards the inner packet unchanged.
    let mut buf = [0u8; 65535];
    let (len, _) = relay_sock.recv_from(&mut buf).unwrap();
    let relay_body = decrypt_test_packet(&buf[..len], &network_key, &relay_alice_rx)
        .expect("relay must decrypt outer packet");
    let fwd_serialized = match relay_body {
        packet::PacketBody::RelayForward {
            next_peer_id,
            inner_packet,
            ..
        } => {
            assert_eq!(next_peer_id, bob_id);
            inner_packet
        }
        other => panic!("unexpected relay body: {other:?}"),
    };
    relay_sock.send_to(&fwd_serialized, bob_addr).unwrap();

    // Bob receives and decrypts
    let (len, _) = bob_sock.recv_from(&mut buf).unwrap();
    let decrypted =
        decrypt_test_packet(&buf[..len], &network_key, &bob_alice_rx).expect("bob must decrypt");
    assert_eq!(
        decrypted,
        packet::PacketBody::Data {
            seq: 1,
            ip_packet: ip_packet.to_vec(),
        }
    );
}

#[test]
fn udp_zero_overhead_relay_forwards_by_masked_header() {
    let (ca_sk, ca_vk, network_secret) = make_ca();
    let network_key = kdf::derive_network_key(&network_secret);
    let alice = make_node("alice-zero-rel", "10.0.0.1/24", &ca_sk);
    let bob = make_node("bob-zero-rel", "10.0.0.2/24", &ca_sk);
    let relay = make_node("relay-zero-node", "10.0.0.3/24", &ca_sk);

    let alice_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let bob_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    bob_sock
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let relay_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    relay_sock
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();

    let bob_addr = bob_sock.local_addr().unwrap();
    let relay_addr = relay_sock.local_addr().unwrap();

    let alice_id = test_node_id("alice-zero-rel");
    let bob_id = test_node_id("bob-zero-rel");
    let relay_id = test_node_id("relay-zero-node");

    let (alice_bob_session, bob_alice_session) = udp_handshake(
        &alice_sock,
        &bob_sock,
        bob_addr,
        &alice.cert,
        &alice.signing_secret_key,
        &bob.cert,
        &bob.signing_secret_key,
        &network_key,
        &ca_vk,
        false,
    );
    let (alice_relay_session, relay_alice_session) = udp_handshake(
        &alice_sock,
        &relay_sock,
        relay_addr,
        &alice.cert,
        &alice.signing_secret_key,
        &relay.cert,
        &relay.signing_secret_key,
        &network_key,
        &ca_vk,
        true,
    );

    let alice_bob_tx = packet::derive_traffic_key(&alice_bob_session, alice_id, bob_id);
    let bob_alice_rx = packet::derive_traffic_key(&bob_alice_session, alice_id, bob_id);
    let relay_alice_rx = packet::derive_traffic_key(&relay_alice_session, alice_id, relay_id);
    let _alice_relay_tx = packet::derive_traffic_key(&alice_relay_session, alice_id, relay_id);

    let ip_packet = b"\x45\x00\x00\x2e\x00\x01\x00\x00\x40\x11\x7a\x0a\x0a\x00\x00\x01\x0a\x00\x00\x02\x08\x00\x6a\xeb\x00\x01\x00\x00\x48\x65\x6c\x6c\x6f\x20\x4c\x69\x74\x65\x77\x61\x79\x21";
    let packet_for_bob = packet::serialize_packet(&packet::encrypt_data_packet(
        1,
        bob_id,
        0x05060708,
        ip_packet,
        &network_key,
        &alice_bob_tx,
    ));

    alice_sock.send_to(&packet_for_bob, relay_addr).unwrap();

    let mut buf = [0u8; 65535];
    let (len, _) = relay_sock.recv_from(&mut buf).unwrap();
    let relay_received = &buf[..len];
    assert_eq!(
        relay_received, packet_for_bob,
        "zero-overhead relay receives the final packet unchanged"
    );
    let header = packet::network_header(relay_received, &network_key)
        .expect("relay must read masked dispatch header");
    assert_eq!(header.kind, packet::KIND_DATA);
    assert_eq!(header.dst_peer_id, bob_id);
    assert!(
        decrypt_test_packet(relay_received, &network_key, &relay_alice_rx).is_none(),
        "relay session key must not decrypt final peer payload"
    );

    relay_sock.send_to(relay_received, bob_addr).unwrap();

    let (len, _) = bob_sock.recv_from(&mut buf).unwrap();
    let decrypted =
        decrypt_test_packet(&buf[..len], &network_key, &bob_alice_rx).expect("bob must decrypt");
    assert_eq!(
        decrypted,
        packet::PacketBody::Data {
            seq: 1,
            ip_packet: ip_packet.to_vec(),
        }
    );
}
