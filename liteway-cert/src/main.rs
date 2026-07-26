use anyhow::Context;
use clap::{Parser, Subcommand};
use ipnetwork::IpNetwork;
use liteway_core::cert::{self, CaCert, CaSigningKey, CaVerifyKey, Cert};
use std::fs;
use std::io::Write;
use std::net::IpAddr;
use std::path::Path;

#[derive(Parser)]
#[command(name = "liteway", about = "Liteway certificate management CLI")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new CA certificate
    GenCa {
        #[arg(short, long, default_value = "liteway-ca")]
        name: String,
        #[arg(short, long, default_value_t = 10)]
        validity_years: i64,
        #[arg(short, long, default_value = "ca")]
        out: String,
        #[arg(short, long)]
        groups: Vec<String>,
    },

    /// Generate a node certificate signed by the CA
    GenNode {
        #[arg(short, long)]
        name: String,
        #[arg(short, long)]
        ip: String,
        #[arg(short, long)]
        subnets: Vec<String>,
        #[arg(short, long)]
        groups: Vec<String>,
        #[arg(short, long, default_value_t = 365)]
        validity_days: i64,
        #[arg(long, default_value = "ca-key.toml")]
        ca_key: String,
        #[arg(short, long)]
        out: Option<String>,
    },

    /// Verify a node certificate against the CA
    Verify {
        #[arg(short, long)]
        cert: String,
        #[arg(short, long, default_value = "ca.toml")]
        ca_cert: String,
    },

    /// Show certificate details
    Show {
        #[arg(short, long)]
        cert: String,
    },

    /// Generate a lighthouse entry for config
    GenLighthouse {
        #[arg(short, long)]
        cert: String,
        #[arg(short, long)]
        address: String,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::GenCa {
            name,
            validity_years,
            out,
            groups,
        } => {
            let full_ca = cert::generate_ca(&name, validity_years, &groups);

            let ca_cert_path = format!("{}.toml", out);
            let ca_key_path = format!("{}-key.toml", out);

            let ca_toml = toml::to_string_pretty(&full_ca.cert)?;
            fs::write(&ca_cert_path, &ca_toml)?;

            let ca_key = CaKeyFile {
                signing_key: full_ca.signing_key,
            };
            let key_toml = toml::to_string_pretty(&ca_key)?;
            write_private_file(&ca_key_path, key_toml.as_bytes())?;

            println!("CA certificate written to {}", ca_cert_path);
            println!("CA signing key written to {}", ca_key_path);
            println!("\nAdd the network secret to every node config (keep it secret; it is not CA key material):");
            println!("network_secret = \"{}\"", generate_network_secret());
        }

        Commands::GenNode {
            name,
            ip,
            subnets,
            groups,
            validity_days,
            ca_key,
            out,
        } => {
            validate_node_ip_cidr(&ip)?;
            let out = out.unwrap_or_else(|| name.clone());
            let ca_key_toml_str = fs::read_to_string(&ca_key)
                .with_context(|| format!("read CA key file '{ca_key}'"))?;
            let ca_key_file: CaKeyFile = toml::from_str(&ca_key_toml_str)?;

            let ca_sk = CaSigningKey {
                ed25519: ca_key_file.signing_key.ed25519,
                ml_dsa_seed: ca_key_file.signing_key.ml_dsa_seed,
            };

            let (node_cert, node_key_material) =
                cert::generate_node(&name, &ip, &subnets, &groups, &ca_sk, validity_days);

            let node_cert_path = format!("{}-cert.toml", out);
            let node_key_path = format!("{}-key.toml", out);

            let cert_toml = toml::to_string_pretty(&node_cert)?;
            fs::write(&node_cert_path, &cert_toml)?;

            let key_toml = toml::to_string_pretty(&node_key_material)?;
            write_private_file(&node_key_path, key_toml.as_bytes())?;

            println!("Node certificate written to {}", node_cert_path);
            println!("Node secret key written to {}", node_key_path);
        }

        Commands::Verify { cert, ca_cert } => {
            let ca_toml_str = fs::read_to_string(&ca_cert)
                .with_context(|| format!("read CA cert file '{ca_cert}'"))?;
            let ca: CaCert = toml::from_str(&ca_toml_str)?;
            let ca_vk = CaVerifyKey {
                ed25519: ca.verify_key.ed25519,
                ml_dsa: ca.verify_key.ml_dsa,
            };

            let cert_toml_str = fs::read_to_string(&cert)
                .with_context(|| format!("read node cert file '{cert}'"))?;
            let node_cert = parse_node_cert(&cert_toml_str)?;

            if node_cert.verify(&ca_vk) {
                println!("Certificate VALID");
                println!("  Name: {}", node_cert.body.meta.name);
                println!("  Valid until: {}", node_cert.body.meta.not_after);
                if let Some(ref addrs) = node_cert.body.addresses {
                    println!("  IP: {}", addrs.ip);
                }
            } else {
                println!("Certificate INVALID");
            }
        }

        Commands::Show { cert } => {
            let cert_toml_str =
                fs::read_to_string(&cert).with_context(|| format!("read cert file '{cert}'"))?;
            match parse_node_cert(&cert_toml_str) {
                Ok(node_cert) => {
                    println!("=== Node Certificate ===");
                    println!("  Name: {}", node_cert.body.meta.name);
                    println!("  Groups: {:?}", node_cert.body.meta.groups);
                    println!("  CA: {}", node_cert.body.meta.is_ca);
                    println!(
                        "  Valid: {} -> {}",
                        node_cert.body.meta.not_before, node_cert.body.meta.not_after
                    );
                    if let Some(ref addrs) = node_cert.body.addresses {
                        println!("  IP: {}", addrs.ip);
                        println!("  Subnets: {:?}", addrs.subnets);
                    }
                    println!(
                        "  Ed25519 PK: {}",
                        hex::encode(&node_cert.body.keys.ed25519_pk)
                    );
                    println!(
                        "  ML-DSA PK: {}",
                        hex::encode(&node_cert.body.keys.ml_dsa_pk)
                    );
                }
                Err(_) => {
                    let ca: CaCert = toml::from_str(&cert_toml_str)?;
                    println!("=== CA Certificate ===");
                    println!("  Name: {}", ca.meta.name);
                    println!("  Groups: {:?}", ca.meta.groups);
                    println!("  Valid: {} -> {}", ca.meta.not_before, ca.meta.not_after);
                    println!("  Ed25519 PK: {}", hex::encode(&ca.verify_key.ed25519));
                    println!("  ML-DSA PK: {}", hex::encode(&ca.verify_key.ml_dsa));
                }
            }
        }

        Commands::GenLighthouse { cert, address } => {
            let cert_toml_str = fs::read_to_string(&cert)
                .with_context(|| format!("read node cert file '{cert}'"))?;
            let node_cert = parse_node_cert(&cert_toml_str)?;

            println!("[[lighthouses]]");
            println!("name = \"{}\"", node_cert.body.meta.name);
            println!("address = \"{}\"", address);
        }
    }

    Ok(())
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct CaKeyFile {
    signing_key: CaSigningKey,
}

fn parse_node_cert(toml_str: &str) -> anyhow::Result<Cert> {
    Ok(toml::from_str::<Cert>(toml_str)?)
}

fn validate_node_ip_cidr(ip: &str) -> anyhow::Result<()> {
    if !ip.contains('/') {
        anyhow::bail!("node IP must include CIDR prefix, for example 10.0.0.1/24");
    }
    let network: IpNetwork = ip
        .parse()
        .with_context(|| format!("parse node IP CIDR '{ip}'"))?;
    let host_prefix = match network.ip() {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };
    if network.prefix() == 0 || network.prefix() >= host_prefix {
        anyhow::bail!(
            "node IP {ip} breaks lighthouse discovery; use a mesh prefix like 10.0.0.1/24"
        );
    }
    Ok(())
}

fn generate_network_secret() -> String {
    use rand_core::Rng;
    let mut seed = [0u8; 32];
    rand::rngs::ThreadRng::default().fill_bytes(&mut seed);
    hex::encode(seed)
}

#[cfg(test)]
mod tests {
    use super::validate_node_ip_cidr;

    #[test]
    fn node_ip_requires_cidr_prefix() {
        assert!(validate_node_ip_cidr("10.0.0.1").is_err());
    }

    #[test]
    fn node_ip_rejects_host_only_prefix() {
        assert!(validate_node_ip_cidr("10.0.0.1/32").is_err());
        assert!(validate_node_ip_cidr("fd00::1/128").is_err());
    }

    #[test]
    fn node_ip_accepts_mesh_prefix() {
        validate_node_ip_cidr("10.0.0.1/24").unwrap();
        validate_node_ip_cidr("fd00::1/64").unwrap();
    }
}

fn write_private_file(path: impl AsRef<Path>, bytes: &[u8]) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path.as_ref())?;
        file.write_all(bytes)?;
        file.sync_all()?;
        Ok(())
    }

    #[cfg(not(unix))]
    {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path.as_ref())?;
        file.write_all(bytes)?;
        file.sync_all()?;
        Ok(())
    }
}
