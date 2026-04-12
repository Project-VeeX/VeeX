# VeeX

VeeX is a Rust proxy core for OpenWrt-class and Linux router environments. It focuses on a narrow execution plane for explicit proxy and transparent proxy deployments, with a deliberately small scope.

## Scope

- inbound: `direct`, `socks`, `redirect`, `tproxy` (TCP only)
- outbound: `trojan`, `direct`
- route: ordered `route.rules` pipeline, `action="sniff"` upgrades, `action="hijack-dns"`, and default `route.final`
- connect: sequential multi-address fallback
- interface: `veex run`, `veex check`, `veex version`
- config: minimal sing-box-compatible JSON subset

Transparent-proxy recursion prevention is explicit now: VeeX does not auto-insert private/local or upstream-server direct rules. If a deployment needs those exceptions, define them yourself in `route.rules`.

VeeX is aimed at OpenWrt, ImmortalWrt, and other Linux router-oriented environments where a small execution plane is needed for `direct`, `socks`, `redirect`, or `tproxy` traffic that must reach `direct` or `trojan` outbounds. The current surface is still stream-first, with a minimal UDP packet path available for `direct-in -> direct-out`, plus a first DNS subsystem slice for `dns-in -> hijack-dns -> UDP/TCP/TLS/HTTPS upstream via detour outbound`, with TCP or UDP ingress selected by ordinary `direct` inbound routing. It is intended for operators, integrators, and downstream projects that need a CLI proxy core rather than a full network platform.

VeeX is not the right fit when the requirement is a full DNS platform, generalized UDP proxying, TUN, or a general routing platform. This repository is also limited to the core itself; OpenWrt packaging, `procd`, and LuCI integration belong outside this repository.

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

- `docs/architecture.md` for the public architecture and current boundaries
- `docs/roadmap.md` for phase history, current stage, and evolution direction
- `docs/observability.md` for the public observability and error-model whitepaper
- `CHANGELOG.md` for release-by-release deltas

## License

VeeX is released under `MPL-2.0`.
