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
- DNS:
  - internal DNS executor with `local`, `UDP`, `TCP`, `TLS`, and `HTTPS` upstream support
  - owns both hijacked client query handling and dial-side domain resolution
- CLI: `veex run`, `veex check`, `veex version`

## Scope

VeeX has explicit stream and packet execution paths. Stream support is broader today, while packet support remains intentionally narrow around direct packet ingress/egress and the DNS paths built on top of that foundation.

Packet execution is its own lifecycle, not a stream byproduct:

```text
first packet -> association create -> route decision -> outbound packet session -> reverse receive/write-back -> idle reclaim or runtime shutdown
```

The first packet determines the route and creates the association. Subsequent packets reuse that association until the reverse path exits, the association is reclaimed for idleness, or runtime shutdown closes active packet sessions.

When outbound or DNS upstream dialing needs domain resolution, VeeX uses the DNS subsystem's controlled resolver path. `domain_resolver` selects an explicit DNS server when configured; otherwise dial-side resolution falls back through safe DNS server selection rather than hidden transport-side policy.

Outbound stream execution follows one shared chain:

```text
resolve -> connect -> (tls) -> (protocol) -> relay
```

`direct` uses the shared resolve/connect semantics and then enters relay immediately. `trojan` keeps the same resolve/connect base semantics, adds TLS when enabled, then performs Trojan protocol request setup before relay. `connect_timeout` belongs to the connect stage; `tls.handshake_timeout` belongs only to the TLS stage.

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
