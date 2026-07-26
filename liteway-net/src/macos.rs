use libc::{ioctl, socket, AF_INET, SIOCAIFADDR, SOCK_DGRAM};
use std::ffi::CString;
use std::io;
use std::mem;
use std::net::{IpAddr, Ipv4Addr};

#[repr(C)]
struct ifaliasreq {
    ifra_name: [libc::c_char; libc::IFNAMSIZ as usize],
    ifra_addr: libc::sockaddr_in,
    ifra_broadaddr: libc::sockaddr_in,
    ifra_mask: libc::sockaddr_in,
}

fn sockaddr_in(addr: Ipv4Addr) -> libc::sockaddr_in {
    libc::sockaddr_in {
        sin_len: mem::size_of::<libc::sockaddr_in>() as u8,
        sin_family: AF_INET as libc::sa_family_t,
        sin_port: 0,
        sin_addr: libc::in_addr {
            s_addr: u32::from_be_bytes(addr.octets()),
        },
        sin_zero: [0; 8],
    }
}

pub fn set_interface_ip(name: &str, addr: &str) -> io::Result<()> {
    let (ip, prefix) = super::parse_addr(addr)?;

    let ip = match ip {
        IpAddr::V4(v4) => v4,
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "only IPv4 supported on macOS",
            ))
        }
    };

    let fd = unsafe { socket(AF_INET, SOCK_DGRAM, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }

    let cname = CString::new(name)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid interface name"))?;

    let mut ifra: ifaliasreq = unsafe { mem::zeroed() };

    let name_bytes = cname.as_bytes();
    let name_len = name_bytes.len().min(libc::IFNAMSIZ as usize - 1);
    for (dst, src) in ifra.ifra_name[..name_len]
        .iter_mut()
        .zip(name_bytes[..name_len].iter().copied())
    {
        *dst = src as libc::c_char;
    }

    ifra.ifra_addr = sockaddr_in(ip);

    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    let host_mask = if prefix == 32 { 0 } else { u32::MAX >> prefix };
    let broadcast = u32::from_be_bytes(ip.octets()) | host_mask;

    ifra.ifra_mask = sockaddr_in(Ipv4Addr::from(mask));

    ifra.ifra_broadaddr = sockaddr_in(Ipv4Addr::from(broadcast));

    let ret = unsafe { ioctl(fd, SIOCAIFADDR, &ifra) };

    unsafe {
        libc::close(fd);
    }

    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}
