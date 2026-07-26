use std::time::{SystemTime, UNIX_EPOCH};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::crypto::hybrid_sig::{self, HybridSignature, HybridSigningKey, HybridVerifyKey};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CertMeta {
    pub name: String,
    pub is_ca: bool,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    #[serde(default)]
    pub groups: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyMaterial {
    #[serde(with = "crate::hex_serde::size_32")]
    pub ed25519_pk: [u8; hybrid_sig::ED25519_PK_LEN],
    #[serde(with = "crate::hex_serde::size_1952")]
    pub ml_dsa_pk: [u8; hybrid_sig::MLDSA_PK_LEN],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeAddresses {
    pub ip: String,
    #[serde(default)]
    pub subnets: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CertBody {
    pub meta: CertMeta,
    pub keys: KeyMaterial,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub addresses: Option<NodeAddresses>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Cert {
    pub body: CertBody,
    pub signature: CertSignature,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CertSignature {
    #[serde(with = "crate::hex_serde::size_64")]
    pub ed25519: [u8; hybrid_sig::ED25519_SIG_LEN],
    #[serde(with = "crate::hex_serde::size_3309")]
    pub ml_dsa: [u8; hybrid_sig::MLDSA_SIG_LEN],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaCert {
    pub meta: CertMeta,
    pub verify_key: CaVerifyKey,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaVerifyKey {
    #[serde(with = "crate::hex_serde::size_32")]
    pub ed25519: [u8; hybrid_sig::ED25519_PK_LEN],
    #[serde(with = "crate::hex_serde::size_1952")]
    pub ml_dsa: [u8; hybrid_sig::MLDSA_PK_LEN],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FullCaCert {
    pub cert: CaCert,
    pub signing_key: CaSigningKey,
}

#[derive(Debug, Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct CaSigningKey {
    #[serde(with = "crate::hex_serde::size_32")]
    pub ed25519: [u8; hybrid_sig::ED25519_SK_LEN],
    #[serde(with = "crate::hex_serde::size_32")]
    pub ml_dsa_seed: [u8; hybrid_sig::MLDSA_SK_LEN],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeKeyFile {
    pub signing_secret_key: NodeSigningSecretKey,
}

#[derive(Debug, Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct NodeSigningSecretKey {
    #[serde(with = "crate::hex_serde::size_32")]
    pub ed25519: [u8; hybrid_sig::ED25519_SK_LEN],
    #[serde(with = "crate::hex_serde::size_32")]
    pub ml_dsa_seed: [u8; hybrid_sig::MLDSA_SK_LEN],
}

impl CertBody {
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap()
    }

    pub fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        Ok(serde_json::from_slice(bytes)?)
    }
}

impl Cert {
    pub fn sign(body: CertBody, ca_signing_key: &CaSigningKey) -> Self {
        let bytes = body.to_bytes();
        let ca_sk = HybridSigningKey {
            ed25519: ca_signing_key.ed25519,
            ml_dsa_seed: ca_signing_key.ml_dsa_seed,
        };
        let sig = hybrid_sig::hybrid_sign(&ca_sk, &bytes);
        Cert {
            body,
            signature: CertSignature {
                ed25519: sig.ed25519,
                ml_dsa: sig.ml_dsa,
            },
        }
    }

    pub fn verify(&self, ca_vk: &CaVerifyKey) -> bool {
        if self.body.meta.is_ca {
            return false;
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let nb = self.body.meta.not_before.timestamp();
        let na = self.body.meta.not_after.timestamp();
        if now < nb || now > na {
            return false;
        }
        let bytes = self.body.to_bytes();
        let vk = HybridVerifyKey {
            ed25519: ca_vk.ed25519,
            ml_dsa: ca_vk.ml_dsa,
        };
        let sig = HybridSignature {
            ed25519: self.signature.ed25519,
            ml_dsa: self.signature.ml_dsa,
        };
        hybrid_sig::hybrid_verify(&vk, &bytes, &sig)
    }
}

pub fn generate_ca(name: &str, years: i64, groups: &[String]) -> FullCaCert {
    let (sk, vk) = hybrid_sig::generate_hybrid_keypair();
    let now = Utc::now();
    let meta = CertMeta {
        name: name.to_string(),
        is_ca: true,
        not_before: now,
        not_after: now + chrono::Duration::days(years * 365),
        groups: groups.to_vec(),
    };
    let ca_cert = CaCert {
        meta,
        verify_key: CaVerifyKey {
            ed25519: vk.ed25519,
            ml_dsa: vk.ml_dsa,
        },
    };
    FullCaCert {
        cert: ca_cert,
        signing_key: CaSigningKey {
            ed25519: sk.ed25519,
            ml_dsa_seed: sk.ml_dsa_seed,
        },
    }
}

pub fn generate_node(
    name: &str,
    ip: &str,
    subnets: &[String],
    groups: &[String],
    ca_signing_key: &CaSigningKey,
    days: i64,
) -> (Cert, NodeKeyFile) {
    let (sig_sk, sig_vk) = hybrid_sig::generate_hybrid_keypair();
    let now = Utc::now();

    let body = CertBody {
        meta: CertMeta {
            name: name.to_string(),
            is_ca: false,
            not_before: now,
            not_after: now + chrono::Duration::days(days),
            groups: groups.to_vec(),
        },
        keys: KeyMaterial {
            ed25519_pk: sig_vk.ed25519,
            ml_dsa_pk: sig_vk.ml_dsa,
        },
        addresses: Some(NodeAddresses {
            ip: ip.to_string(),
            subnets: subnets.to_vec(),
        }),
    };

    let cert = Cert::sign(body, ca_signing_key);
    (
        cert,
        NodeKeyFile {
            signing_secret_key: NodeSigningSecretKey {
                ed25519: sig_sk.ed25519,
                ml_dsa_seed: sig_sk.ml_dsa_seed,
            },
        },
    )
}
