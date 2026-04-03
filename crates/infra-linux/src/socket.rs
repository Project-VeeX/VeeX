use std::{
    io,
    net::{Ipv4Addr, SocketAddr, TcpListener},
};

#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;

#[cfg(target_os = "linux")]
use socket2::{Domain, Protocol, Socket, Type};

#[cfg(target_os = "linux")]
pub(crate) fn create_dual_stack_listener(addr: SocketAddr) -> io::Result<TcpListener> {
    create_listener(addr, false)
}

#[cfg(target_os = "linux")]
pub(crate) fn create_transparent_listener(addr: SocketAddr) -> io::Result<TcpListener> {
    create_listener(addr, true)
}

#[cfg(target_os = "linux")]
fn create_listener(addr: SocketAddr, transparent: bool) -> io::Result<TcpListener> {
    match create_listener_once(addr, transparent) {
        Ok(listener) => Ok(listener),
        Err(primary_err) => match ipv4_fallback_addr(addr) {
            Some(fallback_addr) => {
                create_listener_once(fallback_addr, transparent).map_err(|fallback_err| {
                    combine_listener_errors(
                        addr,
                        fallback_addr,
                        transparent,
                        primary_err,
                        fallback_err,
                    )
                })
            }
            None => Err(primary_err),
        },
    }
}

#[cfg(target_os = "linux")]
fn create_listener_once(addr: SocketAddr, transparent: bool) -> io::Result<TcpListener> {
    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_reuse_address(true)?;

    if domain == Domain::IPV6 {
        socket.set_only_v6(false)?;
    }

    if transparent {
        apply_transparent_options(&socket, domain)?;
    }

    socket.bind(&addr.into())?;
    socket.listen(1024)?;
    socket.set_nonblocking(true)?;
    Ok(socket.into())
}

#[cfg(target_os = "linux")]
fn apply_transparent_options(socket: &Socket, domain: Domain) -> io::Result<()> {
    if domain == Domain::IPV4 {
        return set_sockopt_int(socket, libc::SOL_IP, libc::IP_TRANSPARENT, 1);
    }

    let ipv6_result = set_sockopt_int(socket, libc::SOL_IPV6, libc::IPV6_TRANSPARENT, 1);
    let ipv4_result = set_sockopt_int(socket, libc::SOL_IP, libc::IP_TRANSPARENT, 1);

    match (ipv6_result, ipv4_result) {
        (Ok(()), Ok(())) | (Ok(()), Err(_)) | (Err(_), Ok(())) => Ok(()),
        (Err(err), Err(_)) => Err(err),
    }
}

#[cfg(target_os = "linux")]
fn set_sockopt_int(socket: &Socket, level: i32, option: i32, value: libc::c_int) -> io::Result<()> {
    // SAFETY: the socket fd is live, the option buffer points to a valid integer,
    // and the provided length matches the pointed-to value size.
    let rc = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            level,
            option,
            (&value as *const libc::c_int).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };

    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(target_os = "linux")]
fn ipv4_fallback_addr(addr: SocketAddr) -> Option<SocketAddr> {
    match addr {
        SocketAddr::V6(v6) if v6.ip().is_unspecified() => {
            Some(SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), v6.port()))
        }
        _ => None,
    }
}

#[cfg(target_os = "linux")]
fn combine_listener_errors(
    primary_addr: SocketAddr,
    fallback_addr: SocketAddr,
    transparent: bool,
    primary_err: io::Error,
    fallback_err: io::Error,
) -> io::Error {
    let listener_kind = if transparent {
        "transparent listener"
    } else {
        "listener"
    };

    io::Error::new(
        fallback_err.kind(),
        format!(
            "failed to create {listener_kind} on {primary_addr}: {primary_err}; ipv4 fallback on {fallback_addr} also failed: {fallback_err}"
        ),
    )
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::{
        io,
        net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    };

    use super::{combine_listener_errors, ipv4_fallback_addr};

    #[test]
    fn builds_ipv4_fallback_for_unspecified_ipv6() {
        let fallback = ipv4_fallback_addr(SocketAddr::from((Ipv6Addr::UNSPECIFIED, 1041)))
            .expect("unspecified ipv6 addr should fallback");

        assert_eq!(fallback, SocketAddr::from((Ipv4Addr::UNSPECIFIED, 1041)));
    }

    #[test]
    fn skips_ipv4_fallback_for_specific_ipv6() {
        assert!(ipv4_fallback_addr(SocketAddr::from((Ipv6Addr::LOCALHOST, 1041))).is_none());
    }

    #[test]
    fn combined_listener_error_mentions_primary_and_fallback_failures() {
        let error = combine_listener_errors(
            SocketAddr::from((Ipv6Addr::UNSPECIFIED, 1041)),
            SocketAddr::from((Ipv4Addr::UNSPECIFIED, 1041)),
            true,
            io::Error::new(io::ErrorKind::PermissionDenied, "ipv6 failed"),
            io::Error::new(io::ErrorKind::AddrInUse, "ipv4 failed"),
        );

        assert_eq!(error.kind(), io::ErrorKind::AddrInUse);
        assert!(error.to_string().contains("ipv6 failed"));
        assert!(error.to_string().contains("ipv4 failed"));
    }
}
