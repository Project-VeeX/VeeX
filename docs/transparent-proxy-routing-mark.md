# Routing Mark Validation For Direct Egress

This guide explains how `direct.routing_mark` fits into Phase3 validation.

`veex` uses `SO_MARK` on Linux when `direct.routing_mark` is configured. The purpose is to keep direct egress from re-entering transparent proxy policy.

## When You Need It

`routing_mark` matters when router-originated traffic or policy-routed traffic could otherwise loop back into transparent proxy interception.

It is not required for the most conservative first round where you validate only downstream client traffic through `PREROUTING`.

## Plan The Marks

Use separate values for separate jobs.

Recommended example:

- interception mark for TPROXY delivery: `0x1`
- direct routing mark for `SO_MARK`: `0xff`

Do not use the same value for both paths unless you have explicitly designed policy routing and exclusion rules around that choice.

## Config Example

```json
{
  "outbounds": [
    {
      "type": "direct",
      "tag": "direct",
      "routing_mark": 255
    }
  ]
}
```

The full repository example is:

- `examples/tproxy-compat.json`

## Validation 1: No-Mark Baseline

Before treating `routing_mark` as valid, keep a no-mark baseline:

- run `veex` with a direct outbound that has no `routing_mark`
- confirm `socks -> direct` and `redirect -> direct` still work
- confirm no-mark direct behavior matches previous releases

This baseline is important because the current implementation intentionally keeps the no-mark path on the existing `TcpStream::connect` branch.

## Validation 2: Marked Direct Egress

When you validate the marked path, confirm all of the following:

- the config includes `routing_mark`
- the direct path is expected to stay out of transparent proxy interception
- the deployment excludes the direct mark from any router-originated interception rules

Example early-return rule for an existing `iptables` output chain:

```sh
iptables -t mangle -I VEEX_OUTPUT 1 -m mark --mark 0xff/0xff -j RETURN
```

Example early-return rule for an existing `nftables` output chain:

```sh
nft add rule inet veex_output output meta mark 0xff return
```

These are examples only. Adapt the chain names to your own temporary validation setup.

## What To Check

Use this order:

```sh
/tmp/veex check -c /tmp/tproxy-compat.json
ip rule show
ip route show table 100
logread | grep 'event=route_select'
logread | grep 'event=session_finish'
```

Expected evidence:

- direct bypass traffic shows `outbound=direct`
- Trojan server self-bypass does not recurse into `outbound=proxy`
- marked direct sessions do not re-enter your transparent proxy rule set

Valid no-loop evidence can look like either of these:

```text
event=route_select outbound=direct reason=configured
event=session_finish outbound=direct error_kind=none
```

or, if the target itself is unreachable:

```text
event=route_select outbound=direct reason=configured
event=session_finish outbound=direct error_kind=timeout
```

The key is that the path stays `direct` and does not recurse back into `proxy`.

## Common Failure Modes

- the same mark is reused for TPROXY delivery and direct egress
- the direct mark is not excluded from router-originated interception
- `ip rule` or `table 100` is missing for the interception path
- `routing_mark` is expected to compensate for broken TPROXY rules

## Current Implementation Note

The current Phase3 implementation keeps two direct connect paths:

- no-mark direct uses the existing `TcpStream::connect` path
- marked direct uses the Linux `SO_MARK` path

This is intentional for the current phase and should be treated as a compatibility-preserving design choice, not as the final long-term shape.
