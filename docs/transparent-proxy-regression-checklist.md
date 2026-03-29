# Transparent Proxy Regression Checklist

Use this checklist before treating a Phase2 build as releasable for transparent proxy validation.

## Preflight

- `cargo fmt --all --check`
- `cargo test --workspace`
- cross-build `release-test` or `release` target binary for the intended router target
- confirm the router is running the latest uploaded `/tmp/veex`

## Core Runtime

- `veex version` runs on the router
- `veex check -c ...` succeeds on the router
- `veex run -c ...` starts and binds the redirect port
- `SIGTERM` stops the process cleanly

## Success Paths

- `redirect -> direct -> private destination` succeeds
- `redirect -> trojan -> external HTTPS` succeeds
- logs contain `event=session_start`
- logs contain `event=session_finish`
- successful sessions end with `error_kind=none`

## Bypass Paths

- private destination uses `outbound=direct`
- loopback destination uses `outbound=direct`
- Trojan server address uses `outbound=direct`
- bypass logs include `event=route_select`

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

Do not treat Phase2 validation as complete unless all of the following are true:

- `redirect` code path is working
- original destination recovery is working
- bypass behavior is working
- successful Trojan sessions are not misclassified as relay failures
