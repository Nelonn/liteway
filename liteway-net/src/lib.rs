use ipnetwork::IpNetwork;
use std::io;
use std::net::{IpAddr, UdpSocket};

pub fn check_permissions() -> io::Result<()> {
    #[cfg(target_os = "windows")]
    {
        match std::fs::metadata(r"C:\Windows\System32\config\SAM") {
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "administrator privileges required",
                ));
            }
            Err(_) => {}
        }
    }
    #[cfg(target_os = "linux")]
    {
        let uid = unsafe { libc::geteuid() };
        if uid != 0 {
            let cap_net_admin = std::fs::read_to_string("/proc/self/status")
                .ok()
                .and_then(|s| {
                    s.lines().find_map(|l| {
                        l.strip_prefix("CapEff:\t")
                            .and_then(|hex| u64::from_str_radix(hex.trim(), 16).ok())
                    })
                })
                .map(|mask| mask & (1 << 12) != 0)
                .unwrap_or(false);
            if !cap_net_admin {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "root or CAP_NET_ADMIN required",
                ));
            }
        }
    }
    #[cfg(target_os = "macos")]
    {
        let uid = unsafe { libc::geteuid() };
        if uid != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "root privileges required",
            ));
        }
    }
    Ok(())
}

pub fn parse_addr(addr: &str) -> io::Result<(IpAddr, u8)> {
    let network: IpNetwork = addr
        .parse()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    Ok((network.ip(), network.prefix()))
}

#[cfg(target_os = "windows")]
pub fn configure_udp_socket(socket: &UdpSocket) -> io::Result<()> {
    windows::configure_udp_socket(socket)
}

#[cfg(not(target_os = "windows"))]
pub fn configure_udp_socket(_socket: &UdpSocket) -> io::Result<()> {
    Ok(())
}

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "linux")]
pub use linux::{add_route, del_route, set_interface_ip};

#[cfg(target_os = "macos")]
mod macos;

#[cfg(target_os = "macos")]
pub use macos::set_interface_ip;

#[cfg(target_os = "windows")]
mod windows;

#[cfg(target_os = "windows")]
pub use windows::set_interface_ip;

#[cfg(target_os = "windows")]
pub use windows::{add_route, del_route};

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
pub fn add_route(_subnet: &str, _iface: &str) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "platform not supported",
    ))
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
pub fn del_route(_subnet: &str, _iface: &str) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "platform not supported",
    ))
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub fn set_interface_ip(_name: &str, _addr: &str) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "platform not supported",
    ))
}
