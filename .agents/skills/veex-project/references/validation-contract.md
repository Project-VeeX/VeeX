# VeeX Validation Contract

This reference records stable validation signals, evidence expectations, and diagnostic order for VeeX.

## Core Event Contract

Important event names:

- `event=session_start`
- `event=route_select`
- `event=session_finish`

Important fields:

- `original_dst`
- `outbound`
- `reason`
- `error_kind`

Baseline expectations:

- successful sessions end with `error_kind=none`
- private and loopback direct-route rules should resolve to `outbound=direct`
- Trojan traffic should resolve to the proxy outbound path

## Evidence To Keep

For any meaningful transparent-proxy validation, keep:

- the exact config used
- the exact firewall or policy-routing commands used
- relevant `ip rule` and `ip route` output
- client command output
- relevant `veex` logs

## Example Signal Shapes

Useful success-oriented signal shape:

```text
event=session_start ... original_dst=...
event=route_select outbound=...
event=session_finish outbound=... error_kind=none
```

Useful direct-route-oriented signal shape:

```text
event=route_select outbound=direct route_reason=rule
event=session_finish outbound=direct error_kind=none
```

Useful proxy-oriented signal shape:

```text
event=session_start ... original_dst=...
event=session_finish outbound=proxy error_kind=none
```

## Diagnostic Sequence

A minimal diagnostic sequence is:

```sh
/tmp/veex version
/tmp/veex check -c <config>
ss -ltnp | grep <port>
iptables -t nat -S
logread | grep veex
```

Lower-level tools such as `strace` only become useful when these basic checks still do not explain the behavior.

## Important Failure Interpretations

- If `check` fails, fix the config before analyzing firewall behavior.
- If logs show an IPv4-mapped peer on a dual-stack listener, do not assume an address-family bug immediately; confirm the delivery path first.
- A client-visible success with a logged failure can indicate a transport-edge condition such as TLS close behavior, not necessarily a broken user-facing path.
- A `direct` recursion-prevention route that times out can still mean route selection worked; timeout alone does not prove that the direct rule was wrong.

## Release Gate

Do not describe transparent-proxy validation as complete unless all relevant paths for the current deployment are covered:

- `socks` path works
- `redirect` path works when that deployment path matters
- `tproxy` path works when that deployment path matters
- original-destination recovery works
- direct recursion-prevention route behavior works
- policy-routing state matches the intended TPROXY setup when TPROXY is in scope
- direct no-loop behavior works when `routing_mark` is part of the deployment
- successful Trojan sessions are not misclassified as relay failures

## Validation Discipline

- Keep validation narrow: one client, one destination, one port at a time.
- Keep rollback commands ready before adding temporary rules.
- Do not treat guidance for `fw4/nft`, TPROXY, or `routing_mark` as fully closed device validation unless the recorded validation status says so.

## Interpretation Notes

- recorded validation coverage and proposed validation steps are separate concerns
- `validation-status.md` carries the current maturity snapshot, while this file records evidence and diagnostic expectations
