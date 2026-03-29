# VeeX

VeeX is a configurable proxy core written in Rust.

The long-term project direction is a reusable proxy core that can host multiple inbound and outbound protocols behind a stable daemon interface. The current implementation is intentionally narrower: it focuses on the first usable path with Trojan as the only protocol-specific outbound.

**🚧 Project VeeX is in the experimental phase. 🚧**

## Status

Current user-facing scope:

- SOCKS5 inbound for TCP `CONNECT`
- Trojan outbound over TLS
- direct outbound for bypass and local destinations
- foreground daemon with config validation and graceful shutdown

Current non-goals:

- transparent proxy runtime path
- additional protocols beyond Trojan

## Build

Build the binary from source:

```bash
cargo build -p veex-cli
```

The resulting executable is:

```bash
target/debug/veex
```

## Distribution

VeeX is released as a CLI binary.

OpenWrt and ImmortalWrt packaging is intentionally kept out of this repository.

The dedicated packaging/feed repository will be linked here when it is created:

- `TBD`

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

Currently supported outbound types:

- `trojan`
- `direct`

Example configs:

- `examples/socks-trojan.json`
- `examples/redirect-trojan.json`

`redirect` is already represented in config parsing, but its runtime path belongs to the next milestone.

## Roadmap

Current milestone:

- stable SOCKS5 -> Trojan -> remote TCP path
- config validation through `veex check`
- process-level smoke coverage for `veex run` and `veex check`

Next milestone:

- redirect inbound
- transparent proxy validation
- binary release contract for downstream OpenWrt packaging

Later milestones:

- more outbound protocols
- richer routing policies
- stronger observability and operations support

## Contributing

Before sending changes, run:

```bash
cargo fmt --all --check
cargo test --workspace
cargo clippy --workspace --all-targets
```

If your change affects runtime behavior, update or add the smallest test that proves the success path and the failure path.

## License

VeeX is released under `MPL-2.0`.
