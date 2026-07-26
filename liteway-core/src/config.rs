use std::net::SocketAddr;
use std::path::Path;
use std::{fs, io};

use anyhow::Context;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LighthouseConfig {
    pub name: String,
    pub address: SocketAddr,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterfaceConfig {
    pub name: String,
    #[serde(default = "default_mtu")]
    pub mtu: u16,
}

fn default_listen() -> SocketAddr {
    "0.0.0.0:0".parse().unwrap()
}

fn default_mtu() -> u16 {
    1300
}

impl Default for InterfaceConfig {
    fn default() -> Self {
        InterfaceConfig {
            name: "liteway0".to_string(),
            mtu: 1300,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    #[serde(default = "default_listen")]
    pub listen: SocketAddr,
    pub ca_cert_path: String,
    pub node_cert_path: String,
    pub node_key_path: String,
    pub network_secret: String,

    #[serde(default)]
    pub lighthouses: Vec<LighthouseConfig>,

    pub interface: Option<InterfaceConfig>,

    #[serde(default)]
    pub am_lighthouse: bool,

    #[serde(default)]
    pub am_relay: bool,

    #[serde(default = "default_punch_interval")]
    pub punch_interval_secs: u64,

    #[serde(default = "default_keepalive_punch")]
    pub keepalive_punch: bool,

    #[serde(default = "default_keepalive_timeout")]
    pub keepalive_timeout_secs: u64,

    #[serde(default = "default_relay_fallback_timeout")]
    pub relay_fallback_timeout_secs: u64,
}

fn default_punch_interval() -> u64 {
    10
}

fn default_keepalive_punch() -> bool {
    true
}

fn default_keepalive_timeout() -> u64 {
    30
}

fn default_relay_fallback_timeout() -> u64 {
    5
}

impl AppConfig {
    pub fn from_file(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let path = path.as_ref();
        let content = fs::read_to_string(path)
            .with_context(|| format!("read config file '{}'", path.display()))?;
        Ok(toml::from_str(&content)
            .with_context(|| format!("parse config file '{}'", path.display()))?)
    }

    pub fn network_secret(&self) -> anyhow::Result<[u8; 32]> {
        let bytes = hex::decode(&self.network_secret)?;
        if bytes.len() != 32 {
            anyhow::bail!("network_secret must be 32 bytes encoded as 64 hex characters");
        }
        Ok(bytes.try_into().unwrap())
    }

    pub fn save(&self, path: impl AsRef<Path>) -> io::Result<()> {
        let content = toml::to_string_pretty(self).map_err(io::Error::other)?;
        fs::write(path, content)
    }
}
