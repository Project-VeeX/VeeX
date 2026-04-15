mod dialer;
mod executor;
mod http;
mod request;
mod router;
mod traits;
mod types;
mod upstream;
mod wire;

pub use executor::DnsExecutor;
pub use http::DEFAULT_DOH_PATH;
pub use router::DnsRouter;
pub use traits::DnsUpstream;
pub use types::{
    DnsHttpsOptions, DnsRouteReason, DnsRule, DnsRuntimeConfig, DnsSelection, DnsServer,
    DnsServerTransport,
};
pub use wire::{build_a_query, parse_query_domain, parse_response_ips};
