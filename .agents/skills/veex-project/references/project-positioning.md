# VeeX Project Positioning

## One-Line Definition

VeeX is a Rust proxy core for OpenWrt-class and Linux router environments, intentionally focused on the TCP execution plane rather than a full networking platform.

## Role

- External shape:
  - `veex run -c <config>`
  - `veex check -c <config>`
  - `veex version`
- The real target is to replace the TCP data-plane slice sing-box commonly provides in OpenWrt router topologies, not its DNS stack, policy platform, or full protocol surface.
- The typical target path is:
  - `SOCKS / REDIRECT / TPROXY -> veex -> direct | trojan`

## Supported Surface

- Inbounds:
  - `socks`
  - `redirect`
  - `tproxy`, TCP only
- Outbounds:
  - `trojan`
  - `direct`
- Route:
  - `final`
  - `bypass`, currently basic exact-match semantics
- Config compatibility:
  - a minimal sing-box-compatible JSON subset
  - `direct.routing_mark` is supported

## Explicit Non-Goals

- built-in DNS server
- DoH / DoT client
- fake-ip
- sniff
- UDP proxying
- TUN
- full `route.rules` engine
- full sing-box compatibility
- downstream OpenWrt packaging / feed / LuCI integration

## DNS Boundary

- The project conclusion is that DNS can stay decoupled from VeeX.
- Router deployments can continue to use external DNS split/steering components.
- Do not let DNS requirements pull VeeX into a larger platform shape.

## Repository Boundary

- Main repository owns:
  - Rust core
  - CLI
  - config
  - Linux transparent infrastructure
  - tests
  - examples
  - persistent project docs and guides
- Downstream repositories own:
  - OpenWrt package / ipk
  - `procd` / init scripts
  - LuCI / feed integration

## Default Framing

- First ask whether the request still serves the TCP execution-plane goal.
- If it pushes the project toward a DNS platform, generic routing engine, or downstream packaging repo, classify it as out of scope or later-roadmap work before discussing implementation.
- Treat `README.md` and `PROJECT_GUIDE.md` as the stable public entrypoints for this framing.
