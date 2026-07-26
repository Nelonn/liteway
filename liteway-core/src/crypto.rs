pub const HYBRID_SHARED_SECRET_LEN: usize = 64;
pub const K_HEADER_LEN: usize = 32;
pub const SESSION_KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;
pub const AEAD_TAG_LEN: usize = 16;
pub const NODE_ID_LEN: usize = 4;

pub mod hybrid_kem {
    use super::HYBRID_SHARED_SECRET_LEN;
    use ml_kem::{Decapsulate, Encapsulate, KeyExport, TryKeyInit};
    use rand::rngs::ThreadRng;
    use rand_core::Rng;
    use x25519_dalek::{EphemeralSecret, PublicKey as X25519Pk};
    use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

    pub const X25519_PK_LEN: usize = 32;
    pub const MLKEM_PK_LEN: usize = 1184;
    pub const MLKEM_SK_LEN: usize = 64;
    pub const MLKEM_CT_LEN: usize = 1088;

    pub type MlKemSecretKey = ml_kem::DecapsulationKey768;
    pub type MlKemPublicKey = ml_kem::EncapsulationKey768;

    pub struct HybridKemPublicKey {
        pub x25519: [u8; X25519_PK_LEN],
        pub ml_kem: [u8; MLKEM_PK_LEN],
    }

    #[derive(Zeroize, ZeroizeOnDrop)]
    pub struct HybridKemSecretKey {
        pub x25519: [u8; X25519_PK_LEN],
        pub ml_kem: [u8; MLKEM_SK_LEN],
    }

    pub fn generate_hybrid_keypair() -> (HybridKemSecretKey, HybridKemPublicKey) {
        use x25519_dalek::StaticSecret;
        let x25519_sk = StaticSecret::random_from_rng(&mut ThreadRng::default());
        let x25519_pk = X25519Pk::from(&x25519_sk);
        let (ml_kem_seed, _ml_kem_sk, ml_kem_pk) = generate_mlkem_keypair();

        let sk = HybridKemSecretKey {
            x25519: x25519_sk.to_bytes(),
            ml_kem: ml_kem_seed,
        };
        let pk = HybridKemPublicKey {
            x25519: x25519_pk.to_bytes(),
            ml_kem: mlkem_pk_bytes(&ml_kem_pk),
        };
        (sk, pk)
    }

    pub fn generate_ephemeral() -> (EphemeralSecret, X25519Pk, MlKemSecretKey, MlKemPublicKey) {
        let eph_sk = EphemeralSecret::random_from_rng(&mut ThreadRng::default());
        let eph_pk = X25519Pk::from(&eph_sk);
        let (_ml_kem_seed, ml_kem_sk, ml_kem_pk) = generate_mlkem_keypair();
        (eph_sk, eph_pk, ml_kem_sk, ml_kem_pk)
    }

    pub fn encapsulate(
        peer_x25519: &[u8; X25519_PK_LEN],
        peer_mlkem: &[u8; MLKEM_PK_LEN],
    ) -> (X25519Pk, [u8; HYBRID_SHARED_SECRET_LEN], [u8; MLKEM_CT_LEN]) {
        let eph_sk = EphemeralSecret::random_from_rng(&mut ThreadRng::default());
        let eph_pk = X25519Pk::from(&eph_sk);
        let peer_pk = X25519Pk::from(*peer_x25519);
        let x25519_ss = eph_sk.diffie_hellman(&peer_pk);

        let mlkem_pk = MlKemPublicKey::new_from_slice(peer_mlkem).unwrap();
        let (mlkem_ct, mlkem_ss) = mlkem_pk.encapsulate_with_rng(&mut ThreadRng::default());

        let mut combined = Zeroizing::new([0u8; HYBRID_SHARED_SECRET_LEN]);
        combined[..32].copy_from_slice(x25519_ss.as_bytes());
        combined[32..].copy_from_slice(&mlkem_ss);

        let mut ct_bytes = [0u8; MLKEM_CT_LEN];
        ct_bytes.copy_from_slice(&mlkem_ct);
        (eph_pk, *combined, ct_bytes)
    }

    pub fn decapsulate(
        x25519_sk: EphemeralSecret,
        peer_x25519: &[u8; X25519_PK_LEN],
        mlkem_sk_bytes: &[u8; MLKEM_SK_LEN],
        ct: &[u8; MLKEM_CT_LEN],
    ) -> [u8; HYBRID_SHARED_SECRET_LEN] {
        let peer_pk = X25519Pk::from(*peer_x25519);
        let x25519_ss = x25519_sk.diffie_hellman(&peer_pk);

        let mlkem_sk = mlkem_sk_from_seed(mlkem_sk_bytes);
        let mlkem_ct = ml_kem::ml_kem_768::Ciphertext::try_from(&ct[..]).unwrap();
        let mlkem_ss = mlkem_sk.decapsulate(&mlkem_ct);

        let mut combined = Zeroizing::new([0u8; HYBRID_SHARED_SECRET_LEN]);
        combined[..32].copy_from_slice(x25519_ss.as_bytes());
        combined[32..].copy_from_slice(&mlkem_ss);
        *combined
    }

    pub fn decapsulate_static(
        x25519_sk_bytes: &[u8; X25519_PK_LEN],
        peer_x25519: &[u8; X25519_PK_LEN],
        mlkem_sk_bytes: &[u8; MLKEM_SK_LEN],
        ct: &[u8; MLKEM_CT_LEN],
    ) -> [u8; HYBRID_SHARED_SECRET_LEN] {
        use x25519_dalek::StaticSecret;
        let static_sk = StaticSecret::from(*x25519_sk_bytes);
        let peer_pk = X25519Pk::from(*peer_x25519);
        let x25519_ss = static_sk.diffie_hellman(&peer_pk);

        let mlkem_sk = mlkem_sk_from_seed(mlkem_sk_bytes);
        let mlkem_ct = ml_kem::ml_kem_768::Ciphertext::try_from(&ct[..]).unwrap();
        let mlkem_ss = mlkem_sk.decapsulate(&mlkem_ct);

        let mut combined = Zeroizing::new([0u8; HYBRID_SHARED_SECRET_LEN]);
        combined[..32].copy_from_slice(x25519_ss.as_bytes());
        combined[32..].copy_from_slice(&mlkem_ss);
        *combined
    }

    pub fn mlkem_pk_bytes(pk: &MlKemPublicKey) -> [u8; MLKEM_PK_LEN] {
        let mut out = [0u8; MLKEM_PK_LEN];
        out.copy_from_slice(&pk.to_bytes());
        out
    }

    pub fn mlkem_sk_from_seed(seed: &[u8; MLKEM_SK_LEN]) -> MlKemSecretKey {
        let seed = ml_kem::Seed::from(*seed);
        MlKemSecretKey::from_seed(seed)
    }

    fn generate_mlkem_keypair() -> ([u8; MLKEM_SK_LEN], MlKemSecretKey, MlKemPublicKey) {
        let mut seed = [0u8; MLKEM_SK_LEN];
        ThreadRng::default().fill_bytes(&mut seed);
        let sk = mlkem_sk_from_seed(&seed);
        let pk = sk.encapsulation_key().clone();
        (seed, sk, pk)
    }
}

pub mod hybrid_sig {
    use ed25519_dalek::Signer;
    use ml_dsa::signature::{SignatureEncoding, Verifier};
    use ml_dsa::{KeyExport, KeyInit, Keypair};
    use rand::rngs::ThreadRng;
    use rand_core::Rng;
    use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

    pub const ED25519_SK_LEN: usize = 32;
    pub const ED25519_PK_LEN: usize = 32;
    pub const ED25519_SIG_LEN: usize = 64;
    pub const MLDSA_SK_LEN: usize = 32;
    pub const MLDSA_PK_LEN: usize = 1952;
    pub const MLDSA_SIG_LEN: usize = 3309;
    pub const HYBRID_SIG_LEN: usize = ED25519_SIG_LEN + MLDSA_SIG_LEN;

    type MlDsaSigningKey = ml_dsa::SigningKey<ml_dsa::MlDsa65>;
    type MlDsaVerifyKey = ml_dsa::VerifyingKey<ml_dsa::MlDsa65>;
    type MlDsaSignature = ml_dsa::Signature<ml_dsa::MlDsa65>;

    #[derive(Zeroize, ZeroizeOnDrop)]
    pub struct HybridSigningKey {
        pub ed25519: [u8; ED25519_SK_LEN],
        pub ml_dsa_seed: [u8; MLDSA_SK_LEN],
    }

    pub struct HybridVerifyKey {
        pub ed25519: [u8; ED25519_PK_LEN],
        pub ml_dsa: [u8; MLDSA_PK_LEN],
    }

    pub struct HybridSignature {
        pub ed25519: [u8; ED25519_SIG_LEN],
        pub ml_dsa: [u8; MLDSA_SIG_LEN],
    }

    pub fn generate_hybrid_keypair() -> (HybridSigningKey, HybridVerifyKey) {
        let mut seed = Zeroizing::new([0u8; 32]);
        ThreadRng::default().fill_bytes(&mut *seed);
        let ed_kp = ed25519_dalek::SigningKey::from_bytes(&*seed);
        let ed_vk = ed_kp.verifying_key();

        let mut ml_dsa_seed = [0u8; MLDSA_SK_LEN];
        ThreadRng::default().fill_bytes(&mut ml_dsa_seed);
        let ml_dsa_sk = ml_dsa_sk_from_seed(&ml_dsa_seed);
        let ml_dsa_pk = ml_dsa_sk.verifying_key();

        let sk = HybridSigningKey {
            ed25519: ed_kp.to_bytes(),
            ml_dsa_seed,
        };
        let vk = HybridVerifyKey {
            ed25519: ed_vk.to_bytes(),
            ml_dsa: ml_dsa_pk.to_bytes().try_into().unwrap(),
        };
        (sk, vk)
    }

    pub fn hybrid_sign(sk: &HybridSigningKey, msg: &[u8]) -> HybridSignature {
        let ed_sk = ed25519_dalek::SigningKey::from_bytes(&sk.ed25519);
        let ed_sig = ed_sk.sign(msg).to_bytes();

        let ml_dsa_sk = ml_dsa_sk_from_seed(&sk.ml_dsa_seed);
        let ml_dsa_sig: MlDsaSignature = ml_dsa_sk.sign(msg);

        HybridSignature {
            ed25519: ed_sig,
            ml_dsa: ml_dsa_sig.to_bytes().try_into().unwrap(),
        }
    }

    pub fn hybrid_verify(vk: &HybridVerifyKey, msg: &[u8], sig: &HybridSignature) -> bool {
        let ed_vk = match ed25519_dalek::VerifyingKey::from_bytes(&vk.ed25519) {
            Ok(k) => k,
            Err(_) => return false,
        };
        let ed_sig = ed25519_dalek::Signature::from_bytes(&sig.ed25519);
        if ed_vk.verify_strict(msg, &ed_sig).is_err() {
            return false;
        }

        let ml_dsa_pk = match MlDsaVerifyKey::new_from_slice(&vk.ml_dsa) {
            Ok(k) => k,
            Err(_) => return false,
        };
        let ml_dsa_sig = match MlDsaSignature::try_from(&sig.ml_dsa[..]) {
            Ok(s) => s,
            Err(_) => return false,
        };
        ml_dsa_pk.verify(msg, &ml_dsa_sig).is_ok()
    }

    fn ml_dsa_sk_from_seed(seed: &[u8; MLDSA_SK_LEN]) -> MlDsaSigningKey {
        let seed = ml_dsa::Seed::from(*seed);
        MlDsaSigningKey::from_seed(&seed)
    }
}

pub mod kdf {
    use super::*;
    use zeroize::Zeroizing;

    pub fn derive_network_key(network_secret: &[u8]) -> [u8; K_HEADER_LEN] {
        let mut key = [0u8; K_HEADER_LEN];
        key.copy_from_slice(&blake3::derive_key(
            "liteway-network-key-v1",
            network_secret,
        ));
        key
    }

    pub fn derive_session_key(hybrid_ss: &[u8; HYBRID_SHARED_SECRET_LEN]) -> [u8; SESSION_KEY_LEN] {
        let mut key = [0u8; SESSION_KEY_LEN];
        key.copy_from_slice(&blake3::derive_key("liteway-session-key-v1", hybrid_ss));
        key
    }

    pub fn derive_labeled_key(context: &'static str, input: &[u8]) -> [u8; SESSION_KEY_LEN] {
        let mut key = [0u8; SESSION_KEY_LEN];
        key.copy_from_slice(&blake3::derive_key(context, input));
        key
    }

    pub fn derive_payload_key(
        session_key: &[u8; SESSION_KEY_LEN],
        nonce: &[u8; NONCE_LEN],
    ) -> [u8; SESSION_KEY_LEN] {
        let mut input = Zeroizing::new(Vec::with_capacity(SESSION_KEY_LEN + NONCE_LEN));
        input.extend_from_slice(session_key);
        input.extend_from_slice(nonce);
        let mut key = [0u8; SESSION_KEY_LEN];
        key.copy_from_slice(&blake3::derive_key(
            "liteway-payload-key-v1",
            input.as_slice(),
        ));
        key
    }
}

pub mod aead {
    use super::*;
    use chacha20poly1305::{
        aead::{Aead, KeyInit, Payload},
        ChaCha20Poly1305,
    };

    pub fn encrypt(
        key: &[u8; K_HEADER_LEN],
        nonce: &[u8; NONCE_LEN],
        plaintext: &[u8],
        aad: &[u8],
    ) -> Vec<u8> {
        let cipher = ChaCha20Poly1305::new_from_slice(key).expect("key length is correct");
        let nonce = chacha20poly1305::Nonce::try_from(&nonce[..]).unwrap();
        let payload = Payload {
            msg: plaintext,
            aad,
        };
        cipher.encrypt(&nonce, payload).expect("encryption failed")
    }

    pub fn decrypt(
        key: &[u8; K_HEADER_LEN],
        nonce: &[u8; NONCE_LEN],
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Option<Vec<u8>> {
        let cipher = ChaCha20Poly1305::new_from_slice(key).expect("key length is correct");
        let nonce = chacha20poly1305::Nonce::try_from(&nonce[..]).unwrap();
        let payload = Payload {
            msg: ciphertext,
            aad,
        };
        cipher.decrypt(&nonce, payload).ok()
    }
}
