use std::io;
use std::mem;
use std::net::{IpAddr, Ipv4Addr};
use std::os::windows::io::AsRawSocket;
use windows_sys::Win32::NetworkManagement::IpHelper::{
    CreateIpForwardEntry2, CreateUnicastIpAddressEntry, DeleteIpForwardEntry2,
    InitializeUnicastIpAddressEntry, SetUnicastIpAddressEntry, IP_ADDRESS_PREFIX,
    MIB_IPFORWARD_ROW2, MIB_UNICASTIPADDRESS_ROW,
};
use windows_sys::Win32::Networking::WinSock::SOCKADDR_INET;
use windows_sys::Win32::Networking::WinSock::{
    WSAIoctl, AF_INET, IN_ADDR, IN_ADDR_0, IN_ADDR_0_0, SIO_UDP_CONNRESET, SOCKADDR_IN,
};

pub fn configure_udp_socket(socket: &std::net::UdpSocket) -> io::Result<()> {
    let mut bytes_returned = 0u32;
    let mut enabled = 0u32;
    let result = unsafe {
        WSAIoctl(
            socket.as_raw_socket() as usize,
            SIO_UDP_CONNRESET as u32,
            &mut enabled as *mut _ as *mut _,
            mem::size_of_val(&enabled) as u32,
            std::ptr::null_mut(),
            0,
            &mut bytes_returned,
            std::ptr::null_mut(),
            None,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

pub fn set_interface_ip(interface_name: &str, addr: &str) -> io::Result<()> {
    let (ip, prefix_len) = super::parse_addr(addr)?;
    let ip = match ip {
        std::net::IpAddr::V4(v4) => v4,
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "only IPv4 supported on Windows",
            ))
        }
    };

    let index = interface_index_by_name(interface_name)?;
    let mut row: MIB_UNICASTIPADDRESS_ROW = unsafe { mem::zeroed() };
    unsafe {
        InitializeUnicastIpAddressEntry(&mut row);
    }
    row.InterfaceIndex = index;
    row.Address = sockaddr_inet(ip);
    row.OnLinkPrefixLength = prefix_len;
    row.ValidLifetime = u32::MAX;
    row.PreferredLifetime = u32::MAX;
    row.SkipAsSource = 0;

    let result = unsafe { CreateUnicastIpAddressEntry(&row) };
    if result == 0 {
        Ok(())
    } else if result == 5010 {
        let result = unsafe { SetUnicastIpAddressEntry(&row) };
        if result == 0 {
            Ok(())
        } else {
            Err(win32_error(result, "SetUnicastIpAddressEntry failed"))
        }
    } else {
        Err(win32_error(result, "CreateUnicastIpAddressEntry failed"))
    }
}

pub fn add_route(subnet: &str, interface_name: &str) -> io::Result<()> {
    let row = route_row(subnet, interface_name)?;
    let result = unsafe { CreateIpForwardEntry2(&row) };
    if result == 0 || result == 5010 {
        Ok(())
    } else {
        Err(win32_error(result, "CreateIpForwardEntry2 failed"))
    }
}

pub fn del_route(subnet: &str, interface_name: &str) -> io::Result<()> {
    let row = route_row(subnet, interface_name)?;
    let result = unsafe { DeleteIpForwardEntry2(&row) };
    if result == 0 || result == 1168 {
        Ok(())
    } else {
        Err(win32_error(result, "DeleteIpForwardEntry2 failed"))
    }
}

fn route_row(subnet: &str, interface_name: &str) -> io::Result<MIB_IPFORWARD_ROW2> {
    let (ip, prefix_len) = parse_subnet(subnet)?;
    let index = interface_index_by_name(interface_name)?;

    let mut row: MIB_IPFORWARD_ROW2 = unsafe { mem::zeroed() };
    row.InterfaceIndex = index;
    row.DestinationPrefix = IP_ADDRESS_PREFIX {
        Prefix: sockaddr_inet(ip),
        PrefixLength: prefix_len,
    };
    row.NextHop = sockaddr_inet(Ipv4Addr::UNSPECIFIED);
    row.ValidLifetime = u32::MAX;
    row.PreferredLifetime = u32::MAX;
    row.Metric = 1;
    row.Immortal = 1;
    Ok(row)
}

fn parse_subnet(subnet: &str) -> io::Result<(Ipv4Addr, u8)> {
    let network: ipnetwork::IpNetwork = subnet
        .parse()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    match network.ip() {
        IpAddr::V4(ip) => Ok((ip, network.prefix())),
        IpAddr::V6(_) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "only IPv4 routes supported on Windows",
        )),
    }
}

fn sockaddr_inet(ip: Ipv4Addr) -> SOCKADDR_INET {
    let ip_bytes = ip.octets();
    let sin = SOCKADDR_IN {
        sin_family: AF_INET,
        sin_port: 0,
        sin_addr: IN_ADDR {
            S_un: IN_ADDR_0 {
                S_un_b: IN_ADDR_0_0 {
                    s_b1: ip_bytes[0],
                    s_b2: ip_bytes[1],
                    s_b3: ip_bytes[2],
                    s_b4: ip_bytes[3],
                },
            },
        },
        sin_zero: [0; 8],
    };

    let mut sinet: SOCKADDR_INET = unsafe { mem::zeroed() };
    sinet.Ipv4 = sin;
    sinet.si_family = AF_INET;
    sinet
}

fn win32_error(code: u32, message: &'static str) -> io::Error {
    io::Error::new(
        io::ErrorKind::Other,
        format!("{message}: {}", io::Error::from_raw_os_error(code as i32)),
    )
}

fn interface_index_by_name(name: &str) -> io::Result<u32> {
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetAdaptersAddresses, GAA_FLAG_INCLUDE_PREFIX, IP_ADAPTER_ADDRESSES_LH,
    };
    use windows_sys::Win32::Networking::WinSock::AF_UNSPEC;

    let mut buf_len: u32 = 0;
    let ret = unsafe {
        GetAdaptersAddresses(
            AF_UNSPEC as u32,
            GAA_FLAG_INCLUDE_PREFIX,
            std::ptr::null(),
            std::ptr::null_mut(),
            &mut buf_len,
        )
    };
    if ret != 111 {
        return Err(io::Error::other("GetAdaptersAddresses size query failed"));
    }

    let mut buf = vec![0u8; buf_len as usize];
    let ptr = buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH;
    let ret = unsafe {
        GetAdaptersAddresses(
            AF_UNSPEC as u32,
            GAA_FLAG_INCLUDE_PREFIX,
            std::ptr::null(),
            ptr,
            &mut buf_len,
        )
    };
    if ret != 0 {
        return Err(io::Error::other("GetAdaptersAddresses failed"));
    }

    unsafe {
        let mut current = ptr;
        while !current.is_null() {
            let adapter = &*current;
            let name_len = (0..)
                .take_while(|&i| *(*current).FriendlyName.add(i) != 0)
                .count();
            let adapter_name = String::from_utf16_lossy(std::slice::from_raw_parts(
                (*current).FriendlyName,
                name_len,
            ));
            if adapter_name == name {
                return Ok(adapter.Anonymous1.Anonymous.IfIndex);
            }
            current = adapter.Next;
        }
    }

    Err(io::Error::new(
        io::ErrorKind::NotFound,
        format!("interface '{}' not found", name),
    ))
}
