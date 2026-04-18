# VeeX

> Built for high performance, low overhead, and memory safety.

  VeeX (pronounced `/viːks/`, like 'weeks') is a rust-based proxy runtime core for high-speed traffic exchange and efficient data forwarding. It implements a deliberately scoped
  sing-box-compatible subset and focuses on a narrow, explicit proxy execution surface rather than a full networking platform.

## Features

- Inbounds: `direct`, `socks`, `redirect`, `tproxy`
- Outbounds: `direct`, `trojan`
- Routing: 
  - ordered `route.rules` and fallback `route.final`
  - route actions: `sniff`, `hijack-dns`
- DNS: internal DNS executor with `local`, `UDP`, `TCP`, `TLS`, and `HTTPS` upstream support
- CLI: `veex run`, `veex check`, `veex version`

## Scope

VeeX has explicit stream and packet execution paths. Stream support is broader today, while packet support remains intentionally narrow around direct packet ingress/egress and the DNS paths built on top of that foundation.

Transparent proxy support is treated as explicit ingress handling, not as a hidden policy system. VeeX does not auto-insert private, local, or upstream-exception direct rules; deployments that need those exceptions should define them explicitly in `route.rules`.

This repository is not a full DNS platform, a generalized UDP proxy stack, a TUN implementation, or a general routing system. OpenWrt packaging, `procd`, and LuCI integration remain outside this repository.

## Quick Start

- Show version  
```bash
    veex version
```
- Check a config
```bash
    veex check -c path/to/config.json
```
- Run the daemon
```bash
    veex run -c path/to/config.json
```

for developer: 

- Build:

```bash
cargo build -p veex-cli
```

## Docs

- `docs/architecture.md` for the public architecture and capability boundaries
- `docs/roadmap.md` for current priorities and future-direction constraints
- `docs/observability.md` for observability and error-model guarantees
- `CHANGELOG.md` for release-by-release deltas

## License

VeeX is released under `MPL-2.0`.
