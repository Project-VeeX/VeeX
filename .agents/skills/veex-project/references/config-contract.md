# VeeX Config Contract

Use this file when the task depends on the exact accepted configuration surface rather than the broader project description.

## Supported Input Surface

Current supported configuration surface:

- inbound types:
  - `socks`
  - `redirect`
  - `tproxy`
- inbound `listen` values:
  - IPv4 literals such as `0.0.0.0`
  - IPv6 literals such as `::`
  - bracketed IPv6 literals such as `[::]`
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
  - `bypass`

## `route.bypass` Semantics

`route.bypass` currently supports:

- exact domain matches
- exact IP matches

It does not currently support:

- CIDR ranges
- domain suffix matching
- a rule execution engine

The router applies built-in bypass before configured bypass:

- loopback
- private
- link-local
- configured bypass
- final outbound

## Known Ignored Fields

The current parser may tolerate unrelated fields that commonly appear in broader upstream-style JSON:

- `dns`
- `route.rules`
- `domain_resolver`
- `log.timestamp`
- `log.output`

Known fields remain strictly typed. An unsupported type on a known field is still an error.

## Compatibility Fixture

Use the repository example as the compatibility fixture:

- `examples/tproxy-compat.json`

That fixture intentionally uses `listen="::"` to cover dual-stack validation more closely.

Validate it with:

```sh
veex check -c examples/tproxy-compat.json
```

## Response Rules

- Do not describe tolerated fields as implemented features.
- Do not widen the compatibility contract casually.
- If a proposed config change expands the accepted surface, call out the parser, validation, fixture, and guide updates that must stay aligned.
