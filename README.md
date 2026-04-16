# VeeX

VeeX is a Rust proxy core for OpenWrt-class and Linux router environments. It accepts a minimal sing-box-compatible JSON configuration subset and implements a deliberately narrow proxy execution surface rather than a full networking platform.

The current deployment shape is:

```text
direct | socks | redirect | tproxy
    -> VeeX
    -> direct | trojan
```

## Current Surface

- Inbounds:
  - `direct` for TCP and minimal UDP packet ingress
  - `socks`
  - `redirect`
  - `tproxy` for TCP stream ingress
- Outbounds:
  - `direct`
  - `trojan`
- Routing:
  - ordered `route.rules`
  - `action="sniff"` as an upgrade action
  - `action="hijack-dns"` as a final action
  - default `route.final`
- Connect behavior:
  - sequential multi-address fallback
  - stage-specific TCP connect and TLS handshake timeouts
- DNS:
  - an internal DNS executor
  - local, UDP, TCP, TLS, and HTTPS upstreams
  - upstream access via outbound detour capability
- CLI:
  - `veex run`
  - `veex check`
  - `veex version`

## Scope

At the execution layer, VeeX has explicit stream and packet paths. When both paths exist for a capability, documentation should treat them as peer execution paths rather than as a primary path plus an appendix.

The current public component surface is still asymmetric: stream support is broader than packet support. Packet support is intentionally narrow today, centered on direct packet ingress and egress plus the DNS paths built on top of that foundation.

Transparent proxy support is treated as explicit ingress handling, not as a hidden policy system. VeeX does not auto-insert private, local, or upstream-exception direct rules. If a deployment needs those exceptions, define them explicitly in `route.rules`.

This repository is not a full DNS platform, a generalized UDP proxy stack, a TUN implementation, or a general routing system. OpenWrt packaging, `procd`, and LuCI integration are outside this repository.

## Quick Start

Build:

```bash
cargo build -p veex-cli
```

Check a config:

```bash
target/debug/veex check -c examples/socks-trojan.json
```

Run the daemon:

```bash
target/debug/veex run -c examples/socks-trojan.json
```

Example configs:

- `examples/direct-trojan.json`
- `examples/direct-udp-dns.json`
- `examples/direct-udp-echo.json`
- `examples/socks-trojan.json`
- `examples/redirect-trojan.json`
- `examples/tproxy-compat.json`
- `examples/tproxy-sniff-rules.json`

## Docs

- `docs/architecture.md` for the public architecture and capability boundaries
- `docs/roadmap.md` for current priorities and future-direction constraints
- `docs/observability.md` for observability and error-model guarantees
- `CHANGELOG.md` for release-by-release deltas

## License

VeeX is released under `MPL-2.0`.
