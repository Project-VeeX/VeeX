# VeeX

VeeX is a Rust proxy core for OpenWrt-class and Linux router environments. It provides a focused TCP execution plane for explicit proxy and transparent proxy paths, with a deliberately narrow scope that stays out of DNS, UDP, TUN, and packaging concerns.

## Features

- inbound: `socks`, `redirect`, `tproxy` (TCP only)
- outbound: `trojan`, `direct`
- route: `final`, basic `bypass`
- interface: `veex run`, `veex check`, `veex version`
- config: minimal sing-box-compatible JSON subset

## Scope

VeeX is aimed at OpenWrt, ImmortalWrt, and other Linux router-oriented environments where a small TCP execution plane is needed for `socks`, `redirect`, or `tproxy` traffic that must reach `direct` or `trojan` outbounds. It is intended for operators, integrators, and downstream projects that need a CLI proxy core rather than a full network platform.

VeeX is not the right fit when the requirement is a full DNS, UDP, TUN, or general routing platform. This repository is also limited to the core itself; OpenWrt packaging, `procd`, and LuCI integration belong outside this repository.

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

- `examples/socks-trojan.json`
- `examples/redirect-trojan.json`
- `examples/tproxy-compat.json`

For project structure, runtime model, and compatibility boundaries, see `PROJECT_GUIDE.md`.

## License

VeeX is released under `MPL-2.0`.
