use std::{
    io,
    net::{Ipv4Addr, SocketAddr, TcpListener},
};

use tracing::{debug, warn};

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
                emit_listener_fallback(addr, fallback_addr, &primary_err);
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
        apply_transparent_options(&socket, domain, addr)?;
    }

    socket.bind(&addr.into())?;
    socket.listen(1024)?;
    socket.set_nonblocking(true)?;
    Ok(socket.into())
}

#[cfg(target_os = "linux")]
fn apply_transparent_options(socket: &Socket, domain: Domain, addr: SocketAddr) -> io::Result<()> {
    if domain == Domain::IPV4 {
        let ipv4_result = set_sockopt_int(socket, libc::SOL_IP, libc::IP_TRANSPARENT, 1);
        emit_transparent_socket_config(addr, None, "ipv4", &ipv4_result, None);
        return ipv4_result;
    }

    let ipv6_result = set_sockopt_int(socket, libc::SOL_IPV6, libc::IPV6_TRANSPARENT, 1);
    let ipv4_result = set_sockopt_int(socket, libc::SOL_IP, libc::IP_TRANSPARENT, 1);
    emit_transparent_socket_config(addr, None, "ipv6", &ipv4_result, Some(&ipv6_result));

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

#[cfg(target_os = "linux")]
fn emit_listener_fallback(from: SocketAddr, to: SocketAddr, reason: &io::Error) {
    warn!(
        event = "listener_fallback",
        from = %from,
        to = %to,
        reason = %reason,
        errno = ?reason.raw_os_error(),
        "listener fallback"
    );
}

#[cfg(target_os = "linux")]
fn emit_transparent_socket_config(
    local_addr: SocketAddr,
    peer_addr: Option<SocketAddr>,
    socket_family: &'static str,
    ipv4_result: &io::Result<()>,
    ipv6_result: Option<&io::Result<()>>,
) {
    let ipv4_status = sockopt_status(ipv4_result);
    let ipv6_status = ipv6_result.map(sockopt_status).unwrap_or_default();
    debug!(
        event = "transparent_socket_config",
        socket_family = %socket_family,
        local_addr = ?local_addr,
        peer_addr = ?peer_addr,
        ipv4_transparent_ok = ipv4_status.ok,
        ipv4_transparent_errno = ?ipv4_status.errno,
        ipv6_transparent_ok = ipv6_status.ok,
        ipv6_transparent_errno = ?ipv6_status.errno,
        "transparent socket configured"
    );
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct SockoptStatus {
    ok: bool,
    errno: Option<i32>,
}

#[cfg(target_os = "linux")]
fn sockopt_status(result: &io::Result<()>) -> SockoptStatus {
    match result {
        Ok(()) => SockoptStatus {
            ok: true,
            errno: None,
        },
        Err(err) => SockoptStatus {
            ok: false,
            errno: err.raw_os_error(),
        },
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::{
        collections::BTreeMap,
        io,
        net::{Ipv4Addr, Ipv6Addr, SocketAddr},
        sync::{Arc, Mutex},
    };

    use tracing::{field::Field, Event, Subscriber};
    use tracing_subscriber::{
        layer::{Context, Layer},
        prelude::*,
        registry::LookupSpan,
    };

    use super::{
        combine_listener_errors, emit_listener_fallback, emit_transparent_socket_config,
        ipv4_fallback_addr,
    };

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

    #[test]
    fn transparent_socket_config_event_includes_ok_and_errno_fields() {
        let (_guard, events) = install_test_subscriber();
        let ipv4_result = Err(io::Error::from_raw_os_error(libc::EPERM));

        emit_transparent_socket_config(
            SocketAddr::from((Ipv4Addr::UNSPECIFIED, 1041)),
            None,
            "ipv4",
            &ipv4_result,
            None,
        );

        assert_has_event_fields(
            &events,
            "transparent_socket_config",
            &[
                "socket_family",
                "local_addr",
                "peer_addr",
                "ipv4_transparent_ok",
                "ipv4_transparent_errno",
                "ipv6_transparent_ok",
                "ipv6_transparent_errno",
            ],
        );
    }

    #[test]
    fn listener_fallback_event_includes_errno_field() {
        let (_guard, events) = install_test_subscriber();
        let reason = io::Error::from_raw_os_error(libc::EADDRINUSE);

        emit_listener_fallback(
            SocketAddr::from((Ipv6Addr::UNSPECIFIED, 1041)),
            SocketAddr::from((Ipv4Addr::UNSPECIFIED, 1041)),
            &reason,
        );

        assert_has_event_fields(
            &events,
            "listener_fallback",
            &["from", "to", "reason", "errno"],
        );
    }

    #[derive(Clone, Debug, Default, Eq, PartialEq)]
    struct CapturedEvent {
        fields: BTreeMap<String, String>,
    }

    #[derive(Default)]
    struct EventVisitor {
        fields: BTreeMap<String, String>,
    }

    impl tracing::field::Visit for EventVisitor {
        fn record_bool(&mut self, field: &Field, value: bool) {
            self.fields
                .insert(field.name().to_string(), value.to_string());
        }

        fn record_i64(&mut self, field: &Field, value: i64) {
            self.fields
                .insert(field.name().to_string(), value.to_string());
        }

        fn record_u64(&mut self, field: &Field, value: u64) {
            self.fields
                .insert(field.name().to_string(), value.to_string());
        }

        fn record_str(&mut self, field: &Field, value: &str) {
            self.fields
                .insert(field.name().to_string(), value.to_string());
        }

        fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
            self.fields
                .insert(field.name().to_string(), format!("{value:?}"));
        }
    }

    #[derive(Clone)]
    struct CaptureLayer {
        events: Arc<Mutex<Vec<CapturedEvent>>>,
    }

    impl<S> Layer<S> for CaptureLayer
    where
        S: Subscriber + for<'lookup> LookupSpan<'lookup>,
    {
        fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
            let mut visitor = EventVisitor::default();
            event.record(&mut visitor);
            self.events
                .lock()
                .expect("captured events lock should not be poisoned")
                .push(CapturedEvent {
                    fields: visitor.fields,
                });
        }
    }

    fn install_test_subscriber() -> (
        tracing::subscriber::DefaultGuard,
        Arc<Mutex<Vec<CapturedEvent>>>,
    ) {
        let events = Arc::new(Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::registry().with(CaptureLayer {
            events: Arc::clone(&events),
        });

        (tracing::subscriber::set_default(subscriber), events)
    }

    fn assert_has_event_fields(
        events: &Arc<Mutex<Vec<CapturedEvent>>>,
        event_name: &str,
        expected_fields: &[&str],
    ) {
        let events = events
            .lock()
            .expect("captured events lock should not be poisoned");
        let matched = events.iter().any(|event| {
            event.fields.get("event").map(String::as_str) == Some(event_name)
                && expected_fields
                    .iter()
                    .all(|field| event.fields.contains_key(*field))
        });

        assert!(
            matched,
            "expected event `{event_name}` with fields {:?}, captured events: {:?}",
            expected_fields, *events
        );
    }
}
