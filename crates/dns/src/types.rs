use std::{collections::BTreeMap, sync::Arc};

use veex_core::{Destination, Dial, Network};
use veex_transport::TlsClientOptions;

use crate::traits::DnsUpstream;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsRuntimeConfig {
    pub final_server_tag: String,
    pub servers: Vec<DnsServer>,
    pub rules: Vec<DnsRule>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsServer {
    pub tag: String,
    pub transport: DnsServerTransport,
    pub destination: Destination,
    pub dial: Dial,
}

impl DnsServer {
    pub fn outbound_tag(&self) -> Option<&str> {
        match self.transport {
            DnsServerTransport::Unsupported(_) => None,
            _ => Some(self.dial.detour.as_deref().unwrap_or("direct")),
        }
    }

    pub fn detour_tag(&self) -> &str {
        self.outbound_tag().unwrap_or("")
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsHttpsOptions {
    pub path: String,
    pub headers: BTreeMap<String, String>,
    pub tls: TlsClientOptions,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DnsServerTransport {
    Local,
    Udp,
    Tcp,
    Tls(TlsClientOptions),
    Https(DnsHttpsOptions),
    Unsupported(String),
}

impl DnsServerTransport {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Local => "local",
            Self::Udp => "udp",
            Self::Tcp => "tcp",
            Self::Tls(_) => "tls",
            Self::Https(_) => "https",
            Self::Unsupported(kind) => kind.as_str(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DnsRouteReason {
    Rule,
    Final,
    ExplicitResolver,
    SafeDefault,
}

impl DnsRouteReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Rule => "rule",
            Self::Final => "final",
            Self::ExplicitResolver => "explicit_resolver",
            Self::SafeDefault => "safe_default",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsRule {
    pub domain: Vec<String>,
    pub server_tag: String,
}

#[derive(Clone)]
pub struct DnsSelection {
    pub server_tag: String,
    pub reason: DnsRouteReason,
    pub upstream: Arc<dyn DnsUpstream>,
}

pub(crate) fn upstream_network(transport: &DnsServerTransport) -> Network {
    match transport {
        DnsServerTransport::Local | DnsServerTransport::Udp => Network::Udp,
        DnsServerTransport::Tcp
        | DnsServerTransport::Tls(_)
        | DnsServerTransport::Https(_)
        | DnsServerTransport::Unsupported(_) => Network::Tcp,
    }
}
