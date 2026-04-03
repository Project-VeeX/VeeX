use std::{
    error::Error,
    fmt, io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener},
};

#[cfg(target_os = "linux")]
use std::{mem::MaybeUninit, os::fd::AsRawFd};

use tokio::net::TcpStream;
use tracing::warn;

#[cfg(target_os = "linux")]
use crate::socket::{
    create_dual_stack_listener as create_dual_stack_listener_socket,
    create_transparent_listener as create_transparent_listener_socket,
};

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

pub fn is_v4_mapped(addr: &SocketAddr) -> bool {
    match addr {
        SocketAddr::V6(v6) => v6.ip().to_ipv4_mapped().is_some(),
        SocketAddr::V4(_) => false,
    }
}

pub fn get_original_dst(stream: &TcpStream) -> Result<SocketAddr> {
    get_original_dst_impl(stream)
}

pub fn get_tproxy_dst(stream: &TcpStream) -> Result<SocketAddr> {
    Ok(stream.local_addr()?)
}

pub fn create_dual_stack_listener(addr: SocketAddr) -> Result<TcpListener> {
    create_dual_stack_listener_impl(addr)
}

pub fn create_transparent_listener(addr: SocketAddr) -> Result<TcpListener> {
    create_transparent_listener_impl(addr)
}

#[cfg(target_os = "linux")]
fn get_original_dst_impl(stream: &TcpStream) -> Result<SocketAddr> {
    let fd = stream.as_raw_fd();
    let local_addr = stream.local_addr()?;
    let peer_addr = stream.peer_addr().ok();
    let mut primary_error = None;
    let options = original_dst_socket_options(local_addr, peer_addr);

    for (index, (level, option)) in options.into_iter().enumerate() {
        match get_original_dst_with_option(fd, level, option) {
            Ok(destination) => return Ok(destination),
            Err(err) if index == 0 && should_retry_original_dst_option(&err) => {
                let retry_option = options[1];
                warn!(
                    event = "original_dst_retry",
                    peer = ?peer_addr,
                    local = %local_addr,
                    first_option = original_dst_option_name(level, option),
                    retry_option = original_dst_option_name(retry_option.0, retry_option.1),
                    errno = retry_errno(&err),
                    "retrying original destination lookup"
                );
                primary_error = Some(err);
            }
            Err(err) if primary_error.is_some() && should_retry_original_dst_option(&err) => {
                continue;
            }
            Err(err) => return Err(err),
        }
    }

    match primary_error {
        Some(err) => Err(err),
        None => Err(TransparentError::Io(io::Error::other(
            "original dst lookup exhausted without capturing an error",
        ))),
    }
}

#[cfg(not(target_os = "linux"))]
fn get_original_dst_impl(_stream: &TcpStream) -> Result<SocketAddr> {
    Err(TransparentError::UnsupportedPlatform)
}

#[cfg(target_os = "linux")]
fn get_original_dst_with_option(fd: i32, level: i32, option: i32) -> Result<SocketAddr> {
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
    sockaddr_to_std(&storage, len)
}

#[cfg(target_os = "linux")]
fn original_dst_socket_options(
    local_addr: SocketAddr,
    peer_addr: Option<SocketAddr>,
) -> [(i32, i32); 2] {
    if prefers_ipv4_original_dst(local_addr, peer_addr) {
        [
            (libc::SOL_IP, SO_ORIGINAL_DST),
            (libc::SOL_IPV6, IP6T_SO_ORIGINAL_DST),
        ]
    } else {
        [
            (libc::SOL_IPV6, IP6T_SO_ORIGINAL_DST),
            (libc::SOL_IP, SO_ORIGINAL_DST),
        ]
    }
}

#[cfg(target_os = "linux")]
fn prefers_ipv4_original_dst(local_addr: SocketAddr, peer_addr: Option<SocketAddr>) -> bool {
    is_ipv4_or_mapped(&local_addr) || peer_addr.as_ref().map(is_ipv4_or_mapped).unwrap_or(false)
}

#[cfg(target_os = "linux")]
fn is_ipv4_or_mapped(addr: &SocketAddr) -> bool {
    addr.is_ipv4() || is_v4_mapped(addr)
}

#[cfg(target_os = "linux")]
fn should_retry_original_dst_option(err: &TransparentError) -> bool {
    matches!(
        err,
        TransparentError::GetSockOpt { source, .. }
            if matches!(
                source.raw_os_error(),
                Some(libc::ENOENT) | Some(libc::ENOPROTOOPT) | Some(libc::EOPNOTSUPP)
            )
    )
}

#[cfg(target_os = "linux")]
fn original_dst_option_name(level: i32, option: i32) -> &'static str {
    match (level, option) {
        (libc::SOL_IP, SO_ORIGINAL_DST) => "so_original_dst",
        (libc::SOL_IPV6, IP6T_SO_ORIGINAL_DST) => "ip6t_so_original_dst",
        _ => "unknown",
    }
}

#[cfg(target_os = "linux")]
fn retry_errno(err: &TransparentError) -> i32 {
    match err {
        TransparentError::GetSockOpt { source, .. } => source.raw_os_error().unwrap_or(0),
        _ => 0,
    }
}

#[cfg(target_os = "linux")]
fn create_dual_stack_listener_impl(addr: SocketAddr) -> Result<TcpListener> {
    create_dual_stack_listener_socket(addr).map_err(TransparentError::Io)
}

#[cfg(not(target_os = "linux"))]
fn create_dual_stack_listener_impl(_addr: SocketAddr) -> Result<TcpListener> {
    Err(TransparentError::UnsupportedPlatform)
}

#[cfg(target_os = "linux")]
fn create_transparent_listener_impl(addr: SocketAddr) -> Result<TcpListener> {
    create_transparent_listener_socket(addr).map_err(TransparentError::Io)
}

#[cfg(not(target_os = "linux"))]
fn create_transparent_listener_impl(_addr: SocketAddr) -> Result<TcpListener> {
    Err(TransparentError::UnsupportedPlatform)
}

#[cfg(target_os = "linux")]
fn sockaddr_to_std(storage: &libc::sockaddr_storage, len: libc::socklen_t) -> Result<SocketAddr> {
    match storage.ss_family as i32 {
        libc::AF_INET => {
            let expected = std::mem::size_of::<libc::sockaddr_in>();
            let actual = len as usize;
            if actual < expected {
                return Err(TransparentError::UnexpectedSockAddrLen { expected, actual });
            }

            // SAFETY: AF_INET guarantees the storage starts with a valid `sockaddr_in`.
            let sockaddr = unsafe {
                &*((storage as *const libc::sockaddr_storage).cast::<libc::sockaddr_in>())
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
                &*((storage as *const libc::sockaddr_storage).cast::<libc::sockaddr_in6>())
            };
            Ok(parse_sockaddr_in6(sockaddr))
        }
        family => Err(TransparentError::UnsupportedAddressFamily(family)),
    }
}

#[cfg(target_os = "linux")]
fn parse_sockaddr_in(sockaddr: &libc::sockaddr_in) -> SocketAddr {
    let ip = Ipv4Addr::from(u32::from_be(sockaddr.sin_addr.s_addr));
    SocketAddr::new(IpAddr::V4(ip), u16::from_be(sockaddr.sin_port))
}

#[cfg(target_os = "linux")]
fn parse_sockaddr_in6(sockaddr: &libc::sockaddr_in6) -> SocketAddr {
    SocketAddr::new(
        IpAddr::V6(Ipv6Addr::from(sockaddr.sin6_addr.s6_addr)),
        u16::from_be(sockaddr.sin6_port),
    )
}

pub type Result<T> = std::result::Result<T, TransparentError>;

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    use super::{
        is_v4_mapped, original_dst_socket_options, parse_sockaddr_in, parse_sockaddr_in6,
        IP6T_SO_ORIGINAL_DST, SO_ORIGINAL_DST,
    };

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

    #[test]
    fn detects_ipv4_mapped_ipv6_addr() {
        let addr = SocketAddr::new(
            IpAddr::V6(Ipv4Addr::new(192, 0, 2, 10).to_ipv6_mapped()),
            80,
        );
        assert!(is_v4_mapped(&addr));
    }

    #[test]
    fn prefers_ipv4_original_dst_for_ipv4_mapped_peer() {
        let options = original_dst_socket_options(
            SocketAddr::from((Ipv6Addr::UNSPECIFIED, 1041)),
            Some(SocketAddr::new(
                IpAddr::V6(Ipv4Addr::new(192, 0, 2, 10).to_ipv6_mapped()),
                40000,
            )),
        );

        assert_eq!(options[0], (libc::SOL_IP, SO_ORIGINAL_DST));
        assert_eq!(options[1], (libc::SOL_IPV6, IP6T_SO_ORIGINAL_DST));
    }

    #[test]
    fn prefers_ipv6_original_dst_for_native_ipv6_socket() {
        let options = original_dst_socket_options(
            SocketAddr::from((Ipv6Addr::UNSPECIFIED, 1041)),
            Some(SocketAddr::from((Ipv6Addr::LOCALHOST, 40000))),
        );

        assert_eq!(options[0], (libc::SOL_IPV6, IP6T_SO_ORIGINAL_DST));
        assert_eq!(options[1], (libc::SOL_IP, SO_ORIGINAL_DST));
    }
}
