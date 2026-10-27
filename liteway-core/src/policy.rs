//! Network policy: certificate revocation and group ACLs, signed by the CA.
//!
//! Certificates are long-lived and cannot be taken back once issued, so anything
//! that has to change while the network runs lives here instead. The bundle is
//! signed with the CA key, which is what lets any node - including one that is
//! not trusted itself - pass it on: a receiver only needs the CA certificate it
//! already has to tell a genuine bundle from a forged one.

use std::collections::HashSet;
use std::path::Path;
use std::{fs, io};

use anyhow::Context;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::cert::{CaSigningKey, CaVerifyKey, Cert, CertSignature};
use crate::crypto::hybrid_sig::{self, HybridSignature, HybridSigningKey, HybridVerifyKey};

/// Separates policy signatures from certificate signatures made with the same CA
/// key, so neither can ever be passed off as the other.
const POLICY_SIGNING_DOMAIN: &[u8] = b"liteway-policy-v1\0";

/// Matches every node in an ACL rule.
pub const ACL_ANY: &str = "*";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevokedCert {
    /// [`Cert::fingerprint`] of the revoked certificate.
    pub fingerprint: String,
    /// Free text for the operator; nodes never act on it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

/// Nodes holding any group in `from` may open sessions to nodes holding any group
/// in `to`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AclRule {
    pub from: Vec<String>,
    pub to: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyBody {
    /// Only a strictly higher version replaces the bundle a node already has, so
    /// an old bundle replayed by anyone cannot un-revoke a certificate.
    pub version: u64,
    pub issued_at: DateTime<Utc>,
    #[serde(default)]
    pub revoked: Vec<RevokedCert>,
    /// `None` leaves the network open; `Some` denies everything no rule allows,
    /// so `acl = []` cuts every node off from every other.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acl: Option<Vec<AclRule>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedPolicy {
    pub body: PolicyBody,
    pub signature: CertSignature,
}

impl PolicyBody {
    fn signed_bytes(&self) -> Vec<u8> {
        let mut bytes = POLICY_SIGNING_DOMAIN.to_vec();
        bytes.extend_from_slice(&serde_json::to_vec(self).expect("policy serialization failed"));
        bytes
    }
}

impl SignedPolicy {
    pub fn sign(body: PolicyBody, ca_signing_key: &CaSigningKey) -> Self {
        let sk = HybridSigningKey {
            ed25519: ca_signing_key.ed25519,
            ml_dsa_seed: ca_signing_key.ml_dsa_seed,
        };
        let sig = hybrid_sig::hybrid_sign(&sk, &body.signed_bytes());
        SignedPolicy {
            body,
            signature: CertSignature {
                ed25519: sig.ed25519,
                ml_dsa: sig.ml_dsa,
            },
        }
    }

    pub fn verify(&self, ca_vk: &CaVerifyKey) -> bool {
        let vk = HybridVerifyKey {
            ed25519: ca_vk.ed25519,
            ml_dsa: ca_vk.ml_dsa,
        };
        let sig = HybridSignature {
            ed25519: self.signature.ed25519,
            ml_dsa: self.signature.ml_dsa,
        };
        hybrid_sig::hybrid_verify(&vk, &self.body.signed_bytes(), &sig)
    }

    /// Wire form used when nodes hand the bundle to each other.
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("policy serialization failed")
    }

    pub fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        Ok(serde_json::from_slice(bytes)?)
    }

    pub fn from_file(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let path = path.as_ref();
        let content = fs::read_to_string(path)
            .with_context(|| format!("read policy file '{}'", path.display()))?;
        toml::from_str(&content).with_context(|| format!("parse policy file '{}'", path.display()))
    }

    /// Write through a temporary file so a crash mid-write cannot leave a
    /// truncated bundle that fails to load on the next start.
    pub fn save(&self, path: impl AsRef<Path>) -> io::Result<()> {
        let path = path.as_ref();
        let content = toml::to_string_pretty(self).map_err(io::Error::other)?;
        let mut tmp = path.as_os_str().to_owned();
        tmp.push(".tmp");
        fs::write(&tmp, content)?;
        fs::rename(&tmp, path)
    }
}

/// A verified bundle in the form the daemon checks peers against.
#[derive(Debug, Clone)]
pub struct Policy {
    pub signed: Option<SignedPolicy>,
    revoked: HashSet<String>,
}

impl Default for Policy {
    fn default() -> Self {
        Self::open()
    }
}

impl Policy {
    /// What a node runs with before it has seen any bundle: nothing revoked, no ACL.
    pub fn open() -> Self {
        Policy {
            signed: None,
            revoked: HashSet::new(),
        }
    }

    pub fn from_signed(signed: SignedPolicy, ca_vk: &CaVerifyKey) -> anyhow::Result<Self> {
        if !signed.verify(ca_vk) {
            anyhow::bail!("policy bundle signature does not match the CA");
        }
        let revoked = signed
            .body
            .revoked
            .iter()
            .map(|entry| entry.fingerprint.to_ascii_lowercase())
            .collect();
        Ok(Policy {
            signed: Some(signed),
            revoked,
        })
    }

    pub fn version(&self) -> u64 {
        self.signed.as_ref().map_or(0, |signed| signed.body.version)
    }

    /// One line for the log: what this bundle actually enforces.
    pub fn summary(&self) -> String {
        let revoked = self.revoked.len();
        match self.acl() {
            Some(rules) => format!(
                "{revoked} revoked certificate(s), ACL with {} rule(s)",
                rules.len()
            ),
            None => format!("{revoked} revoked certificate(s), no ACL"),
        }
    }

    fn acl(&self) -> Option<&[AclRule]> {
        self.signed.as_ref()?.body.acl.as_deref()
    }

    pub fn is_revoked(&self, cert: &Cert) -> bool {
        !self.revoked.is_empty() && self.revoked.contains(&cert.fingerprint())
    }

    /// Whether `from` may open a session to `to`.
    pub fn allows(&self, from: &Cert, to: &Cert) -> bool {
        let Some(rules) = self.acl() else {
            return true;
        };
        let from_groups = &from.body.meta.groups;
        let to_groups = &to.body.meta.groups;
        rules.iter().any(|rule| {
            matches_groups(&rule.from, from_groups) && matches_groups(&rule.to, to_groups)
        })
    }

    /// Whether two nodes may exchange traffic at all.
    ///
    /// Sessions carry replies, and there is no connection tracking to tell a reply
    /// from a request, so once either side may reach the other the session is
    /// usable in both directions. Direction still decides who may *open* it.
    pub fn allows_either(&self, a: &Cert, b: &Cert) -> bool {
        self.allows(a, b) || self.allows(b, a)
    }
}

fn matches_groups(rule_groups: &[String], node_groups: &[String]) -> bool {
    rule_groups
        .iter()
        .any(|group| group == ACL_ANY || node_groups.contains(group))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert;

    fn node(ca: &cert::FullCaCert, name: &str, groups: &[&str]) -> Cert {
        let groups: Vec<String> = groups.iter().map(|g| g.to_string()).collect();
        cert::generate_node(name, "10.0.0.1/24", &[], &groups, &ca.signing_key, 1).0
    }

    fn body(version: u64, acl: Option<Vec<AclRule>>) -> PolicyBody {
        PolicyBody {
            version,
            issued_at: Utc::now(),
            revoked: Vec::new(),
            acl,
        }
    }

    fn rule(from: &[&str], to: &[&str]) -> AclRule {
        AclRule {
            from: from.iter().map(|g| g.to_string()).collect(),
            to: to.iter().map(|g| g.to_string()).collect(),
        }
    }

    #[test]
    fn bundle_signed_by_another_ca_is_rejected() {
        let ca = cert::generate_ca("ca", 1, &[]);
        let other = cert::generate_ca("other", 1, &[]);
        let signed = SignedPolicy::sign(body(1, None), &other.signing_key);
        assert!(Policy::from_signed(signed, &ca.cert.verify_key).is_err());
    }

    #[test]
    fn tampered_bundle_is_rejected() {
        let ca = cert::generate_ca("ca", 1, &[]);
        let mut signed = SignedPolicy::sign(body(1, None), &ca.signing_key);
        signed.body.version = 2;
        assert!(!signed.verify(&ca.cert.verify_key));
    }

    #[test]
    fn bundle_survives_the_wire_and_toml() {
        let ca = cert::generate_ca("ca", 1, &[]);
        let mut b = body(7, Some(vec![rule(&["a"], &["b"])]));
        b.revoked.push(RevokedCert {
            fingerprint: "00".repeat(32),
            comment: Some("lost laptop".into()),
        });
        let signed = SignedPolicy::sign(b, &ca.signing_key);

        let wire = SignedPolicy::from_bytes(&signed.to_bytes()).unwrap();
        assert!(wire.verify(&ca.cert.verify_key));
        let file: SignedPolicy = toml::from_str(&toml::to_string_pretty(&signed).unwrap()).unwrap();
        assert!(file.verify(&ca.cert.verify_key));
    }

    #[test]
    fn revoked_certificate_is_recognised_by_fingerprint() {
        let ca = cert::generate_ca("ca", 1, &[]);
        let revoked = node(&ca, "revoked", &[]);
        let kept = node(&ca, "kept", &[]);
        let mut b = body(1, None);
        b.revoked.push(RevokedCert {
            fingerprint: revoked.fingerprint().to_ascii_uppercase(),
            comment: None,
        });
        let policy =
            Policy::from_signed(SignedPolicy::sign(b, &ca.signing_key), &ca.cert.verify_key)
                .unwrap();
        assert!(policy.is_revoked(&revoked));
        assert!(!policy.is_revoked(&kept));
    }

    #[test]
    fn acl_is_directional_and_denies_by_default() {
        let ca = cert::generate_ca("ca", 1, &[]);
        let laptop = node(&ca, "laptop", &["laptops"]);
        let server = node(&ca, "server", &["servers"]);
        let printer = node(&ca, "printer", &["printers"]);
        let b = body(1, Some(vec![rule(&["laptops"], &["servers"])]));
        let policy =
            Policy::from_signed(SignedPolicy::sign(b, &ca.signing_key), &ca.cert.verify_key)
                .unwrap();

        assert!(policy.allows(&laptop, &server));
        assert!(!policy.allows(&server, &laptop));
        assert!(policy.allows_either(&server, &laptop));
        assert!(!policy.allows_either(&laptop, &printer));
    }

    #[test]
    fn wildcard_matches_every_node() {
        let ca = cert::generate_ca("ca", 1, &[]);
        let admin = node(&ca, "admin", &["admins"]);
        let anyone = node(&ca, "anyone", &[]);
        let b = body(1, Some(vec![rule(&["admins"], &[ACL_ANY])]));
        let policy =
            Policy::from_signed(SignedPolicy::sign(b, &ca.signing_key), &ca.cert.verify_key)
                .unwrap();
        assert!(policy.allows(&admin, &anyone));
        assert!(!policy.allows(&anyone, &admin));
    }

    #[test]
    fn no_acl_section_leaves_the_network_open_but_empty_acl_closes_it() {
        let ca = cert::generate_ca("ca", 1, &[]);
        let a = node(&ca, "a", &[]);
        let b = node(&ca, "b", &[]);
        assert!(Policy::open().allows(&a, &b));

        let closed = Policy::from_signed(
            SignedPolicy::sign(body(1, Some(Vec::new())), &ca.signing_key),
            &ca.cert.verify_key,
        )
        .unwrap();
        assert!(!closed.allows_either(&a, &b));
    }
}
