# Transparent Proxy Regression Checklist

Use this checklist before treating a Phase3 build as releasable for transparent proxy validation.

## Preflight

- `cargo fmt --all --check`
- `cargo check --workspace`
- `cargo test --workspace`
- `cargo clippy --workspace --all-targets`
- cross-build `release-test` or `release` target binary for the intended router target
- confirm the router is running the latest uploaded `/tmp/veex`

## Core Runtime

- `veex version` runs on the router
- `veex check -c ...` succeeds on the router
- `veex run -c ...` starts and binds the intended inbound port
- `SIGTERM` stops the process cleanly

## Phase1 Paths

- `socks -> direct` succeeds
- `socks -> trojan` succeeds

## Phase2 Paths

- `redirect -> direct -> private destination` succeeds
- `redirect -> trojan -> external HTTPS` succeeds
- redirect logs show the restored original destination

## Phase3 Paths

- `tproxy -> direct -> private destination` succeeds
- `tproxy -> trojan -> external HTTPS` succeeds
- TPROXY rule counters increase during validation
- `ip rule show` includes the expected interception rule
- `ip route show table 100` includes the expected local route

## Route Selection And Logs

- logs contain `event=session_start`
- logs contain `event=route_select`
- logs contain `event=session_finish`
- successful sessions end with `error_kind=none`

## Bypass Paths

- private destination uses `outbound=direct`
- loopback destination uses `outbound=direct`
- Trojan server address uses `outbound=direct`
- bypass logs include `event=route_select`

## Direct Egress

- no-mark direct behavior still works
- `routing_mark` is validated on a Linux/OpenWrt target if the deployment depends on it
- marked direct egress does not recurse into `outbound=proxy`

## Failure Paths

- invalid config fails at `veex check`
- unreachable direct destination is diagnosable
- wrong Trojan password is diagnosable
- certificate validation failure is diagnosable

## Rule Hygiene

- validation rules are limited to one client and one target at a time
- rollback commands are prepared before adding rules
- no persistent firewall state is changed during temporary validation

## Evidence To Keep

- command transcript or shell history
- the exact config used
- relevant `veex` logs
- the target host/IP used for validation

## Release Gate

Do not treat Phase3 validation as complete unless all of the following are true:

- `socks` code path is working
- `redirect` code path is working
- `tproxy` code path is working
- original destination recovery is working
- bypass behavior is working
- policy routing state matches the intended TPROXY setup
- direct no-loop behavior is working when `routing_mark` is part of the deployment
- successful Trojan sessions are not misclassified as relay failures
