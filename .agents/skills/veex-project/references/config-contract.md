# VeeX Config Contract

This reference records the exact accepted configuration surface and the current compatibility boundary.

## Supported Input Surface

Current supported configuration surface:

- inbound types:
  - `direct`
  - `socks`
  - `redirect`
  - `tproxy`
- inbound `listen` values:
  - IPv4 literals such as `0.0.0.0`
  - IPv6 literals such as `::`
  - bracketed IPv6 literals such as `[::]`
- `direct.network`:
  - omitted: treated as TCP
  - `"tcp"`: accepted
  - `"udp"`: accepted
  - any other value: rejected
- direct inbound fields:
  - `tag`
  - `listen`
  - `listen_port`
  - `override_address`
  - `override_port`
- `tproxy.network`:
  - omitted: treated as TCP
  - `"tcp"`: accepted
  - any other value: rejected
- outbound types:
  - `direct`
  - `trojan`
- direct outbound fields:
  - `tag`
  - `routing_mark`
  - runtime behavior:
    - TCP stream connect is supported
    - UDP packet session connect is supported
- route fields:
  - `final`
  - `rules`
- dns fields:
  - `final`
  - `servers`
  - `rules`

Current UDP execution boundary:

- only `direct` inbound accepts `network: "udp"`
- only `direct` outbound supports packet execution
- UDP association ownership lives in the packet dispatcher rather than in protocol-private inbound code
- internal DNS upstream queries also reuse outbound packet or stream capability rather than bypassing it with ad-hoc sockets

## `route.rules` Semantics

`route.rules` currently supports the minimal matcher subset:

- `domain` — exact domain match
- `domain_suffix` — apex or subdomain suffix match
- `ip_cidr` — IP destination match
- `ip_is_private` — private IPv4 or unique-local IPv6 destination
- `ip_is_loopback` — loopback destination
- `ip_is_link_local` — link-local destination
- `port` — exact destination port
- `inbound` — exact inbound tag

Current rule execution contract:

- `outbound` and `action="hijack-dns"` are the supported final actions
- `action="sniff"` is the supported upgrade action
- rules are evaluated in declaration order
- first match wins
- within one rule, all populated matcher fields must match
- `route.final` is lowered into the router's default final action
- the runtime does not auto-insert recursion-prevention direct rules; operators must configure private/local or upstream-server direct exceptions explicitly in `route.rules`
- rules that depend on sniffed domains must appear after the `action="sniff"` rule that enriches routing context
- `action="hijack-dns"` hands the matching DNS ingress flow to the internal DNS executor instead of creating a forward association or entering relay

## `dns` Semantics

The current accepted DNS subset is intentionally narrow:

- `dns.final`:
  - when omitted, set to `null`, or set to `""`, defaults to `dns.servers[0].tag`
  - when present, must match an existing DNS server tag
- `dns.servers[*]`:
  - `tag`
  - `type`
  - `server` / `server_port` / `detour` for non-`local` upstreams
  - `local` reads `nameserver` entries from `/etc/resolv.conf` and ignores unused upstream fields
- `dns.rules[*]`:
  - `domain`
  - `server`
  - optional `action="route"`

Current DNS runtime boundary:

- `local` executes standard UDP queries against `nameserver` entries read from `/etc/resolv.conf`
- UDP and TCP upstream servers are executed through detour-aware outbound stream or packet capability
- TLS/HTTPS upstream servers are executed through detour-aware outbound stream capability
- DNS server selection belongs to the DNS subsystem, not to `route.rules`
- DNS queries use short-lived upstream stream or packet sessions rather than client-facing associations or relay

## Removed Compatibility Field

`route.bypass` is no longer accepted.

Migration direction:

- convert exact domain direct exceptions into `route.rules` with `domain` + `outbound: "direct"`
- convert exact IP direct exceptions into `route.rules` with `ip_cidr` + `outbound: "direct"`
- convert private/local recursion-prevention intent into `ip_is_private`, `ip_is_loopback`, or `ip_is_link_local` route rules

## Known Ignored Fields

Known tolerated-but-unimplemented fields (accepted in config but have no effect):

- `domain_resolver` — domain resolution strategy
- `log.output` — log output destination (e.g. file path, syslog); VeeX currently logs to stdout/stderr only

Note: `log.timestamp` is implemented and controls whether tracing output includes RFC3339 timestamps.

Known fields remain strictly typed. An unsupported type on a known field is still an error.

## Compatibility Fixture

The repository compatibility fixture is:

- `examples/direct-trojan.json`
- `examples/direct-udp-dns.json`
- `examples/direct-udp-echo.json`
- `examples/tproxy-compat.json`

`examples/tproxy-compat.json` intentionally uses `listen="::"` to cover dual-stack validation more closely.

Typical validation command:

```sh
veex check -c examples/direct-trojan.json
```

## Contract Notes

- tolerated fields are not implemented features
- the compatibility contract is intentionally narrow
- any expansion of the accepted surface should keep parser, validation, fixture, and public-doc changes aligned
