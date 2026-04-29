# VeeX Owner Matrix

This reference records the current intended owner for config-facing shared fields and their runtime landing zones.

The goal is not to copy sing-box internal organization verbatim. The goal is to use sing-box `listen` / `dial` / `tls` grouping as an external compatibility guide while keeping VeeX runtime ownership explicit.

## Decision Rule

Use this order when deciding where a field belongs:

1. external compatibility status
   - check whether the sing-box field is current, deprecated, or out of scope
2. internal shared-field grouping
   - decide whether the field belongs to VeeX internal `listen` / `dial` / `tls` organization
3. runtime owner
   - decide which VeeX layer actually owns the behavior at runtime

Do not force a runtime landing zone only because sing-box documents a field under a shared section.

## Owner Table

| Concern | Primary owner | Responsibilities | Non-responsibilities |
| --- | --- | --- | --- |
| external config surface | `crates/config` | flat public shape, parse, validate, defaults, compatibility quarantine | runtime policy, listener behavior, transport behavior |
| shared config grouping | `crates/config/src/schema/shared.rs` | internal `ListenFields` / `DialFields` / `TlsFields` organization | direct runtime execution |
| config-to-runtime lowering | `crates/cli/src/factory/lowering/shared.rs` | lower shared config fields into runtime inputs | component-specific protocol semantics |
| inbound listen runtime | `veex_core::portal::Listen` | normalized listener address/port contract shared by listener-backed components | Linux socket tuning, transparent destination recovery, protocol parsing |
| outbound dial runtime | `veex_core::portal::Dial` | normalized dial-stage policy shared by direct outbound, trojan outbound, and DNS upstream dialing | TLS handshake semantics, protocol framing |
| dial-side resolution policy | `veex_core::dns::ResolveContext` | explicit resolver tag, disable-cache bit, recursion depth, caller metadata | DNS server selection execution, transport dialing |
| outbound TLS runtime | `veex_transport::OutboundTls` | TLS-stage options and validation | route policy, protocol setup, connect policy |
| DNS upstream selection/runtime | `crates/dns` | DNS server selection, safe fallback, cache behavior, upstream exchange | generic outbound connect policy |
| component-specific inbound behavior | `crates/portal-inbound` | direct override fields, SOCKS server behavior, transparent destination recovery | generic listener ownership |
| component-specific outbound behavior | `crates/portal-outbound` | trojan server/password, direct packet session behavior | generic shared dial semantics |

## Current Field Mapping

### `listen`

- external compatibility guide: sing-box shared `listen`
- VeeX shared grouping owner: `ListenFields`
- VeeX runtime owner: `portal::Listen`
- current stable runtime landing:
  - `listen`
  - `listen_port`

Do not force `routing_mark`, `reuse_addr`, `bind_interface`, or `detour` into `portal::Listen` until VeeX has a clear cross-component listener runtime owner for them.

### `dial`

- external compatibility guide: sing-box shared `dial`
- VeeX shared grouping owner: `DialFields`
- VeeX runtime owner: `portal::Dial`

Current stable runtime landing:

- `detour`
- `connect_timeout`
- `routing_mark`
- `disable_tcp_keep_alive`
- `tcp_keep_alive`
- `tcp_keep_alive_interval`
- `domain_resolver.server`
- `domain_resolver.disable_cache`

`portal::Dial` is the owner of dial-side resolve policy lowering into `ResolveContext`.

### `tls`

- external compatibility guide: sing-box shared `tls`
- VeeX shared grouping owner: `TlsFields`
- VeeX runtime owner: `OutboundTls`

Current stable runtime landing:

- `enabled`
- `server_name`
- `disable_sni`
- `insecure`
- `certificate_path`
- `ca_path`
- `handshake_timeout`
- `alpn`

Do not move TLS-stage semantics into `portal::Dial` or route-level abstractions.

## Review Rules

- If a field changes connect behavior, first ask whether `portal::Dial` or `transport` owns it.
- If a field changes TLS behavior, `OutboundTls` owns it unless there is a strong contrary reason.
- If a field affects dial-side DNS selection or cache policy, prefer `ResolveContext` plus `dns` ownership rather than duplicating logic in component dialers.
- If a field only makes sense for one component family, keep it out of shared fields even if sing-box places it near shared sections.
- If a field is deprecated in sing-box docs, do not use internal organization cleanup as an excuse to revive it in VeeX.
