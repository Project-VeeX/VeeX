# TProxy Config Compatibility

This document defines the current configuration subset used by the Phase3 transparent proxy flow.

## Supported Input

Current supported configuration surface:

- inbound types:
  - `socks`
  - `redirect`
  - `tproxy`
- inbound `listen` values:
  - IPv4 literals such as `0.0.0.0`
  - IPv6 literals such as `::`
  - bracketed IPv6 literals such as `[::]`
- `tproxy.network`
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
  - `bypass`

## `route.bypass` Semantics

`route.bypass` currently supports:

- exact domain matches
- exact IP matches

It does not currently support:

- CIDR ranges
- domain suffix matching
- a rule execution engine

The router still applies built-in bypass before configured bypass:

- loopback
- private
- link-local
- configured bypass
- final outbound

## Known Ignored Fields

The current parser intentionally ignores unknown fields. The repository compatibility example relies on that behavior for the following fields:

- `dns`
- `route.rules`
- `domain_resolver`
- `log.timestamp`
- `log.output`

Known fields remain strictly typed. An unsupported type on a known field is still an error.

## Reference Example

Use the repository example as the single-source compatibility fixture:

- `examples/tproxy-compat.json`

That example intentionally uses `listen="::"` to match dual-stack OpenWrt/Passwall-style validation more closely.

Validate it with:

```sh
veex check -c examples/tproxy-compat.json
```

## Not Implemented In This Phase

The following are intentionally out of scope for the current compatibility surface:

- DNS execution
- UDP transparent proxying
- sniffing
- fake-ip
- `route.rules` execution

## Compatibility Contract

The intent of this subset is conservative:

- accept the fields needed for the current transparent proxy path
- ignore unrelated fields that commonly appear in upstream-style JSON
- reject invalid types for the fields that `veex` actually consumes
