# VeeX

VeeX is a configurable proxy core written in Rust.

The long-term project direction is a reusable proxy core that can host multiple inbound and outbound protocols behind a stable daemon interface. The current implementation is intentionally narrower: it focuses on the first usable path with Trojan as the only protocol-specific outbound.

**🚧 Project VeeX is in the experimental phase. 🚧**

## Status

Current user-facing scope:

- SOCKS5 inbound for TCP `CONNECT`
- Linux redirect inbound for TCP transparent proxy validation
- Linux TPROXY inbound for TCP transparent proxy validation
- Trojan outbound over TLS
- direct outbound for bypass and local destinations
- foreground daemon with config validation and graceful shutdown

Current non-goals:

- additional protocols beyond Trojan
- OpenWrt packaging and service integration in this repository

## Build

Build the binary from source:

```bash
cargo build -p veex-cli
```

The resulting executable is:

```bash
target/debug/veex
```

For validation or distribution builds, use a non-default Cargo profile as needed.

## Distribution

VeeX is released as a CLI binary.

OpenWrt and ImmortalWrt packaging is intentionally kept out of this repository.

The dedicated packaging/feed repository will be linked here when it is created:

- `TBD`

Transparent proxy validation guides live in:

- `docs/transparent-proxy-iptables.md`
- `docs/transparent-proxy-fw4.md`
- `docs/transparent-proxy-openwrt-sop.md`

## Usage

Show version:

```bash
target/debug/veex version
```

Validate a config file:

```bash
target/debug/veex check -c examples/socks-trojan.json
```

Run the daemon in foreground mode:

```bash
target/debug/veex run -c examples/socks-trojan.json
```

Show command usage:

```bash
target/debug/veex
```

Runtime behavior:

- stays in foreground
- does not daemonize itself
- writes logs to stdout/stderr
- exits cleanly on `SIGINT` and `SIGTERM`

## Configuration

VeeX currently accepts a minimal sing-box-compatible JSON subset.

Top-level fields:

- `log.level`
- `log.disabled`
- `inbounds[]`
- `outbounds[]`
- `route.final`

Currently supported inbound types:

- `socks`
- `redirect`
- `tproxy`

Currently supported outbound types:

- `trojan`
- `direct`

Transparent proxy listener notes:

- `redirect` and `tproxy` listen addresses accept IPv4 and IPv6 literals
- `listen="::"` is supported for dual-stack transparent-proxy validation
- bracketed IPv6 listen literals such as `[::]` are also accepted

Example configs:

- `examples/socks-trojan.json`
- `examples/redirect-trojan.json`
- `examples/tproxy-compat.json`

## Roadmap

Current milestone:

- stable SOCKS5 -> Trojan -> remote TCP path
- stable Linux redirect -> Trojan/direct path
- stable Linux TPROXY -> Trojan/direct path
- config validation through `veex check`
- process-level smoke coverage for `veex run` and `veex check`
- transparent proxy validation guides for OpenWrt-class systems

Next milestone:

- binary release contract for downstream OpenWrt packaging
- downstream packaging/feed repository
- richer routing and policy support

Later milestones:

- more outbound protocols
- richer routing policies
- stronger observability and operations support

## Contributing

Run formatting, tests, and clippy before sending changes:

```bash
cargo fmt --all --check
cargo test --workspace
cargo clippy --workspace --all-targets
```

If runtime behavior changes, update the smallest relevant test coverage.

## License

VeeX is released under `MPL-2.0`.
