use std::{
    error::Error,
    fmt, io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener},
};

#[cfg(target_os = "linux")]
use std::{mem::MaybeUninit, os::fd::AsRawFd};

#[cfg(target_os = "linux")]
use socket2::{Domain, Protocol, Socket, Type};

use tokio::net::TcpStream;

pub const SO_ORIGINAL_DST: i32 = 80;
pub const IP6T_SO_ORIGINAL_DST: i32 = 80;

#[derive(Debug)]
pub enum TransparentError {
    UnsupportedPlatform,
    GetSockOpt {
        level: i32,
        option: i32,
        source: io::Error,
    },
    UnexpectedSockAddrLen {
        expected: usize,
        actual: usize,
    },
    UnsupportedAddressFamily(i32),
    Io(io::Error),
}

impl fmt::Display for TransparentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedPlatform => {
                f.write_str("transparent socket helpers are only supported on linux")
            }
            Self::GetSockOpt {
                level,
                option,
                source,
            } => write!(
                f,
                "getsockopt(level={level}, option={option}) failed: {source}"
            ),
            Self::UnexpectedSockAddrLen { expected, actual } => write!(
                f,
                "getsockopt returned sockaddr length {actual}, expected at least {expected}"
            ),
            Self::UnsupportedAddressFamily(family) => {
                write!(
                    f,
                    "unsupported sockaddr family returned by getsockopt: {family}"
                )
            }
            Self::Io(err) => write!(f, "transparent socket i/o error: {err}"),
        }
    }
}

impl Error for TransparentError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::GetSockOpt { source, .. } => Some(source),
            Self::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<io::Error> for TransparentError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

pub fn get_original_dst(stream: &TcpStream) -> Result<SocketAddr> {
    get_original_dst_impl(stream)
}

pub fn get_tproxy_dst(stream: &TcpStream) -> Result<SocketAddr> {
    Ok(stream.local_addr()?)
}

pub fn create_transparent_listener(addr: SocketAddr) -> Result<TcpListener> {
    create_transparent_listener_impl(addr)
}

#[cfg(target_os = "linux")]
fn get_original_dst_impl(stream: &TcpStream) -> Result<SocketAddr> {
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
        return Err(TransparentError::GetSockOpt {
            level,
            option,
            source: io::Error::last_os_error(),
        });
    }

    // SAFETY: `getsockopt` returned success and initialized `len` bytes in `storage`.
    let storage = unsafe { storage.assume_init() };
    match storage.ss_family as i32 {
        libc::AF_INET => {
            let expected = std::mem::size_of::<libc::sockaddr_in>();
            let actual = len as usize;
            if actual < expected {
                return Err(TransparentError::UnexpectedSockAddrLen { expected, actual });
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
                return Err(TransparentError::UnexpectedSockAddrLen { expected, actual });
            }

            // SAFETY: AF_INET6 guarantees the storage starts with a valid `sockaddr_in6`.
            let sockaddr = unsafe {
                &*((&storage as *const libc::sockaddr_storage).cast::<libc::sockaddr_in6>())
            };
            Ok(parse_sockaddr_in6(sockaddr))
        }
        family => Err(TransparentError::UnsupportedAddressFamily(family)),
    }
}

#[cfg(not(target_os = "linux"))]
fn get_original_dst_impl(_stream: &TcpStream) -> Result<SocketAddr> {
    Err(TransparentError::UnsupportedPlatform)
}

#[cfg(target_os = "linux")]
fn create_transparent_listener_impl(addr: SocketAddr) -> Result<TcpListener> {
    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_reuse_address(true)?;

    let enabled: libc::c_int = 1;
    // SAFETY: the file descriptor is live, the option buffer points to a valid integer,
    // and the provided length matches the pointed-to value size.
    let rc = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_IP,
            libc::IP_TRANSPARENT,
            (&enabled as *const libc::c_int).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(TransparentError::Io(io::Error::last_os_error()));
    }

    socket.bind(&addr.into())?;
    socket.listen(1024)?;
    socket.set_nonblocking(true)?;
    Ok(socket.into())
}

#[cfg(not(target_os = "linux"))]
fn create_transparent_listener_impl(_addr: SocketAddr) -> Result<TcpListener> {
    Err(TransparentError::UnsupportedPlatform)
}

#[cfg(target_os = "linux")]
fn parse_sockaddr_in(sockaddr: &libc::sockaddr_in) -> SocketAddr {
    let ip = Ipv4Addr::from(sockaddr.sin_addr.s_addr.to_ne_bytes());
    let port = u16::from_be(sockaddr.sin_port);
    SocketAddr::new(IpAddr::V4(ip), port)
}

#[cfg(target_os = "linux")]
fn parse_sockaddr_in6(sockaddr: &libc::sockaddr_in6) -> SocketAddr {
    let ip = Ipv6Addr::from(sockaddr.sin6_addr.s6_addr);
    let port = u16::from_be(sockaddr.sin6_port);
    SocketAddr::new(IpAddr::V6(ip), port)
}

pub type Result<T> = std::result::Result<T, TransparentError>;

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

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
            destination,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)), 8443)
        );
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
        assert_eq!(
            destination,
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 9443)
        );
    }
}
