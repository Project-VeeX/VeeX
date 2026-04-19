mod cache;
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
    DEFAULT_DNS_CACHE_CAPACITY, DnsHttpsOptions, DnsRouteReason, DnsRule, DnsRuntimeConfig,
    DnsSelection, DnsServer, DnsServerTransport, MIN_DNS_CACHE_CAPACITY,
};
pub use wire::{
    DnsQueryInfo, build_a_query, parse_query_domain, parse_query_info, parse_response_ips,
    parse_response_min_ttl, rewrite_message_id,
};
