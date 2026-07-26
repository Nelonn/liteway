use std::io;
use std::net::IpAddr;

use futures::TryStreamExt;
use netlink_packet_route::route::{
    RouteAddress, RouteAttribute, RouteHeader, RouteMessage, RouteProtocol, RouteScope, RouteType,
};
use netlink_packet_route::AddressFamily;
use tokio::runtime::Builder;

fn get_iface_index<'a>(
    handle: &'a rtnetlink::Handle,
    name: &'a str,
) -> impl std::future::Future<Output = io::Result<u32>> + 'a {
    async move {
        let mut links = handle.link().get().match_name(name.to_string()).execute();

        let link = links
            .try_next()
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "interface not found"))?;

        Ok(link.header.index)
    }
}

fn with_rtnetlink<F, T>(f: F) -> io::Result<T>
where
    F: std::future::Future<Output = io::Result<T>>,
{
    let rt = Builder::new_current_thread().enable_io().build()?;
    rt.block_on(f)
}

pub fn set_interface_ip(name: &str, addr: &str) -> io::Result<()> {
    let (ip, prefix_len) = super::parse_addr(addr)?;

    with_rtnetlink(async {
        let (connection, handle, _) =
            rtnetlink::new_connection().map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        tokio::spawn(connection);

        let iface_idx = get_iface_index(&handle, name).await?;

        handle
            .link()
            .set(iface_idx)
            .up()
            .execute()
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        handle
            .address()
            .add(iface_idx, ip, prefix_len)
            .execute()
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        Ok(())
    })
}

fn parse_subnet(subnet: &str) -> io::Result<(IpAddr, u8)> {
    let network: ipnetwork::IpNetwork = subnet
        .parse()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    Ok((network.ip(), network.prefix()))
}

fn build_route_message(subnet: &str, _iface: &str, iface_idx: u32) -> io::Result<RouteMessage> {
    let (ip, prefix_len) = parse_subnet(subnet)?;
    let mut msg = RouteMessage::default();
    msg.header.table = RouteHeader::RT_TABLE_MAIN;
    msg.header.protocol = RouteProtocol::Static;
    msg.header.scope = RouteScope::Universe;
    msg.header.kind = RouteType::Unicast;

    match ip {
        IpAddr::V4(addr) => {
            msg.header.address_family = AddressFamily::Inet;
            msg.header.destination_prefix_length = prefix_len;
            msg.attributes
                .push(RouteAttribute::Destination(RouteAddress::Inet(addr)));
        }
        IpAddr::V6(addr) => {
            msg.header.address_family = AddressFamily::Inet6;
            msg.header.destination_prefix_length = prefix_len;
            msg.attributes
                .push(RouteAttribute::Destination(RouteAddress::Inet6(addr)));
        }
    }

    msg.attributes.push(RouteAttribute::Oif(iface_idx));
    Ok(msg)
}

pub fn add_route(subnet: &str, iface: &str) -> io::Result<()> {
    let (ip, prefix_len) = parse_subnet(subnet)?;

    with_rtnetlink(async {
        let (connection, handle, _) =
            rtnetlink::new_connection().map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        tokio::spawn(connection);

        let iface_idx = get_iface_index(&handle, iface).await?;

        let result = match ip {
            IpAddr::V4(addr) => {
                handle
                    .route()
                    .add()
                    .v4()
                    .destination_prefix(addr, prefix_len)
                    .output_interface(iface_idx)
                    .execute()
                    .await
            }
            IpAddr::V6(addr) => {
                handle
                    .route()
                    .add()
                    .v6()
                    .destination_prefix(addr, prefix_len)
                    .output_interface(iface_idx)
                    .execute()
                    .await
            }
        };

        result.or_else(|e| {
            let msg = e.to_string();
            if msg.contains("File exists") || msg.contains("os error 17") {
                Ok(())
            } else {
                Err(io::Error::new(io::ErrorKind::Other, e))
            }
        })
    })
}

pub fn del_route(subnet: &str, iface: &str) -> io::Result<()> {
    with_rtnetlink(async {
        let (connection, handle, _) =
            rtnetlink::new_connection().map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        tokio::spawn(connection);

        let iface_idx = get_iface_index(&handle, iface).await?;
        let msg = build_route_message(subnet, iface, iface_idx)?;

        handle
            .route()
            .del(msg)
            .execute()
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
    })
}
