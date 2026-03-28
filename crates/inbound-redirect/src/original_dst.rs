use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use tokio::net::TcpStream;
use veex_core::Destination;

use crate::error::{RedirectError, Result};

pub const SO_ORIGINAL_DST: i32 = 80;
pub const IP6T_SO_ORIGINAL_DST: i32 = 80;

pub fn resolve_original_dst(stream: &TcpStream) -> Result<Destination> {
    resolve_original_dst_impl(stream)
}

#[cfg(target_os = "linux")]
fn resolve_original_dst_impl(stream: &TcpStream) -> Result<Destination> {
    use std::{mem::MaybeUninit, os::fd::AsRawFd};

    let fd = stream.as_raw_fd();
    let family = stream.local_addr()?.ip();
    let (level, option) = match family {
        IpAddr::V4(_) => (libc::SOL_IP, SO_ORIGINAL_DST),
        IpAddr::V6(_) => (libc::SOL_IPV6, IP6T_SO_ORIGINAL_DST),
    };

    let mut storage = MaybeUninit::<libc::sockaddr_storage>::zeroed();
    let mut len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;

    // SAFETY: `storage` points to valid writable memory for `sockaddr_storage`, `len`
    // is initialized to the available size, and `fd` comes from a live `TcpStream`.
    let rc = unsafe { libc::getsockopt(fd, level, option, storage.as_mut_ptr().cast(), &mut len) };
    if rc != 0 {
        return Err(RedirectError::GetSockOpt {
            level,
            option,
            source: std::io::Error::last_os_error(),
        });
    }

    // SAFETY: `getsockopt` returned success and initialized `len` bytes in `storage`.
    let storage = unsafe { storage.assume_init() };
    match storage.ss_family as i32 {
        libc::AF_INET => {
            let expected = std::mem::size_of::<libc::sockaddr_in>();
            let actual = len as usize;
            if actual < expected {
                return Err(RedirectError::UnexpectedSockAddrLen { expected, actual });
            }

            // SAFETY: AF_INET guarantees the storage starts with a valid `sockaddr_in`.
            let sockaddr = unsafe {
                &*((&storage as *const libc::sockaddr_storage).cast::<libc::sockaddr_in>())
            };
            Ok(parse_sockaddr_in(sockaddr))
        }
        libc::AF_INET6 => {
            let expected = std::mem::size_of::<libc::sockaddr_in6>();
            let actual = len as usize;
            if actual < expected {
                return Err(RedirectError::UnexpectedSockAddrLen { expected, actual });
            }

            // SAFETY: AF_INET6 guarantees the storage starts with a valid `sockaddr_in6`.
            let sockaddr = unsafe {
                &*((&storage as *const libc::sockaddr_storage).cast::<libc::sockaddr_in6>())
            };
            Ok(parse_sockaddr_in6(sockaddr))
        }
        family => Err(RedirectError::UnsupportedAddressFamily(family)),
    }
}

#[cfg(not(target_os = "linux"))]
fn resolve_original_dst_impl(_stream: &TcpStream) -> Result<Destination> {
    Err(RedirectError::UnsupportedPlatform)
}

#[cfg(target_os = "linux")]
fn parse_sockaddr_in(sockaddr: &libc::sockaddr_in) -> Destination {
    let ip = Ipv4Addr::from(sockaddr.sin_addr.s_addr.to_ne_bytes());
    let port = u16::from_be(sockaddr.sin_port);
    Destination::from_ip(IpAddr::V4(ip), port)
}

#[cfg(target_os = "linux")]
fn parse_sockaddr_in6(sockaddr: &libc::sockaddr_in6) -> Destination {
    let ip = Ipv6Addr::from(sockaddr.sin6_addr.s6_addr);
    let port = u16::from_be(sockaddr.sin6_port);
    Destination::from_ip(IpAddr::V6(ip), port)
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use veex_core::Host;

    use super::{parse_sockaddr_in, parse_sockaddr_in6};

    #[test]
    fn parses_ipv4_sockaddr_from_network_byte_order() {
        let sockaddr = libc::sockaddr_in {
            sin_family: libc::AF_INET as libc::sa_family_t,
            sin_port: 8443u16.to_be(),
            sin_addr: libc::in_addr {
                s_addr: u32::from_ne_bytes([203, 0, 113, 9]),
            },
            sin_zero: [0; 8],
        };

        let destination = parse_sockaddr_in(&sockaddr);
        assert_eq!(
            destination.host,
            Host::Ip(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)))
        );
        assert_eq!(destination.port, 8443);
    }

    #[test]
    fn parses_ipv6_sockaddr_from_network_byte_order() {
        let sockaddr = libc::sockaddr_in6 {
            sin6_family: libc::AF_INET6 as libc::sa_family_t,
            sin6_port: 9443u16.to_be(),
            sin6_flowinfo: 0,
            sin6_addr: libc::in6_addr {
                s6_addr: Ipv6Addr::LOCALHOST.octets(),
            },
            sin6_scope_id: 0,
        };

        let destination = parse_sockaddr_in6(&sockaddr);
        assert_eq!(destination.host, Host::Ip(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert_eq!(destination.port, 9443);
    }
}
