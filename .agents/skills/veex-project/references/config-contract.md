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
- route fields:
  - `final`
  - `rules`

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

- `outbound` is the only supported action
- rules are evaluated in declaration order
- first match wins
- within one rule, all populated matcher fields must match
- `route.final` is lowered into the router's default final action
- the runtime does not auto-insert recursion-prevention direct rules; operators must configure private/local or upstream-server direct exceptions explicitly in `route.rules`
- rules that depend on sniffed domains must appear after the `action="sniff"` rule that enriches routing context

## Removed Compatibility Field

`route.bypass` is no longer accepted.

Migration direction:

- convert exact domain direct exceptions into `route.rules` with `domain` + `outbound: "direct"`
- convert exact IP direct exceptions into `route.rules` with `ip_cidr` + `outbound: "direct"`
- convert private/local recursion-prevention intent into `ip_is_private`, `ip_is_loopback`, or `ip_is_link_local` route rules

## Known Ignored Fields

Known tolerated-but-unimplemented fields (accepted in config but have no effect):

- `dns` — DNS server or resolver configuration
- `domain_resolver` — domain resolution strategy
- `log.output` — log output destination (e.g. file path, syslog); VeeX currently logs to stdout/stderr only

Note: `log.timestamp` is implemented and controls whether tracing output includes RFC3339 timestamps.

Known fields remain strictly typed. An unsupported type on a known field is still an error.

## Compatibility Fixture

The repository compatibility fixture is:

- `examples/direct-trojan.json`
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
