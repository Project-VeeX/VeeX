# Transparent Proxy TPROXY Validation

This guide covers the Phase3 validation path for `tproxy inbound` on Linux and OpenWrt-class systems.

It is intentionally scoped to:

- TCP only
- one client at a time
- one destination at a time
- temporary rules only

It does not describe persistent firewall integration.

## Scope

Validated intent:

- `TPROXY -> tproxy inbound -> direct outbound -> private destination`
- `TPROXY -> tproxy inbound -> trojan outbound -> external HTTPS`

This guide assumes:

- `veex` is uploaded manually, for example to `/tmp/veex`
- a compatible config is uploaded manually, for example to `/tmp/tproxy-compat.json`
- the system allows `IP_TRANSPARENT`, `TPROXY`, and policy routing changes

## Mark Planning

Keep inbound interception and direct egress marks distinct.

Recommended split:

- interception mark: `0x1`
- direct routing mark: `0xff`

Do not blindly reuse the same mark for both roles. The interception mark is used to deliver TPROXY traffic to local sockets through policy routing. The direct routing mark is used by `SO_MARK` on direct egress and should stay independent.

## Prerequisites

You need all of the following before testing:

- root privileges or equivalent `CAP_NET_ADMIN`
- `ip rule` and `ip route`
- a kernel/userspace stack with TPROXY support
- a `veex` config whose inbound listens on the intended TPROXY port

Conservative example assumptions:

- `tproxy` listen port: `1041`
- listener: `::` for dual-stack validation
- client: `192.168.7.150`
- external target: `185.45.5.35:443`
- LAN interface: `br-lan`

## Policy Routing Bootstrap

Prepare a dedicated rule and local route for the interception mark:

```sh
ip rule add fwmark 0x1/0x1 lookup 100
ip route add local 0.0.0.0/0 dev lo table 100
```

If you validate a dual-stack config whose `tproxy` inbound listens on `::`, add the IPv6 policy-routing pair as well:

```sh
ip -6 rule add fwmark 0x1/0x1 lookup 100
ip -6 route add local ::/0 dev lo table 100
```

Verify them:

```sh
ip rule show
ip route show table 100
```

Optional dual-stack verification:

```sh
ip -6 rule show
ip -6 route show table 100
```

Expected shape:

```text
... fwmark 0x1/0x1 lookup 100
local 0.0.0.0/0 dev lo scope host
```

## Start `veex`

Validate the config first:

```sh
/tmp/veex check -c /tmp/tproxy-compat.json
```

Start the process:

```sh
/tmp/veex run -c /tmp/tproxy-compat.json > /tmp/veex-tproxy.log 2>&1 &
echo $! > /tmp/veex-tproxy.pid
```

Confirm the listener:

```sh
ss -ltnp | grep 1041
```

For dual-stack `listen="::"` validation, `ss` output may show either `[::]:1041` or `*:1041`.

## iptables TPROXY Example

Use temporary `mangle` rules only:

```sh
iptables -t mangle -D PREROUTING -i br-lan -j VEEX_TPROXY 2>/dev/null || true
iptables -t mangle -F VEEX_TPROXY 2>/dev/null || true
iptables -t mangle -X VEEX_TPROXY 2>/dev/null || true
iptables -t mangle -N VEEX_TPROXY
iptables -t mangle -I PREROUTING 1 -i br-lan -j VEEX_TPROXY
iptables -t mangle -A VEEX_TPROXY -s 192.168.7.150 -d 185.45.5.35 -p tcp --dport 443 -j TPROXY --on-port 1041 --tproxy-mark 0x1/0x1
```

Inspect counters while testing:

```sh
iptables -t mangle -L VEEX_TPROXY -n -v
```

## fw4/nftables TPROXY Example

Use a dedicated temporary table:

```sh
nft delete table inet veex_tproxy 2>/dev/null || true
nft add table inet veex_tproxy
nft 'add chain inet veex_tproxy prerouting { type filter hook prerouting priority mangle; policy accept; }'
nft add rule inet veex_tproxy prerouting iifname "br-lan" ip saddr 192.168.7.150 ip daddr 185.45.5.35 tcp dport 443 meta mark set 0x1 tproxy to :1041
```

Inspect counters while testing:

```sh
nft list chain inet veex_tproxy prerouting -a
```

## Validation Steps

First validate the private bypass path with a private destination. Then validate the external Trojan path.

External HTTPS example:

```sh
curl --resolve www.google.com:443:185.45.5.35 -I https://www.google.com
```

Expected evidence:

- TPROXY rule counters increase
- `ip rule show` still contains the `lookup 100` rule
- `ip route show table 100` still shows the local route
- `event=session_start` shows the expected `original_dst`
- `event=session_finish` ends with `error_kind=none`

If you are validating IPv6 interception too, also confirm:

- `ip -6 rule show` still contains the `lookup 100` rule
- `ip -6 route show table 100` still shows the local route

For direct/private validation, expected log shape is:

```text
event=route_select outbound=direct reason=private
event=session_finish outbound=direct error_kind=none
```

For Trojan validation, expected log shape is:

```text
event=session_start inbound=tproxy-in original_dst=185.45.5.35:443
event=session_finish outbound=proxy error_kind=none
```

## Rollback

Always remove temporary rules, policy routing state, and the running process:

```sh
iptables -t mangle -D PREROUTING -i br-lan -j VEEX_TPROXY 2>/dev/null || true
iptables -t mangle -F VEEX_TPROXY 2>/dev/null || true
iptables -t mangle -X VEEX_TPROXY 2>/dev/null || true
nft delete table inet veex_tproxy 2>/dev/null || true
ip rule del fwmark 0x1/0x1 lookup 100 2>/dev/null || true
ip route del local 0.0.0.0/0 dev lo table 100 2>/dev/null || true
ip -6 rule del fwmark 0x1/0x1 lookup 100 2>/dev/null || true
ip -6 route del local ::/0 dev lo table 100 2>/dev/null || true
kill -TERM "$(cat /tmp/veex-tproxy.pid 2>/dev/null)" 2>/dev/null || true
```

## Notes

- Start with `PREROUTING` only. Do not broaden to router-originated traffic until the conservative LAN path is green.
- `listen="::"` is supported for dual-stack transparent-proxy validation and does not rely on the system `bindv6only` default.
- If TPROXY does not work, fall back to the existing `REDIRECT` guides first:
  - `docs/transparent-proxy-iptables.md`
  - `docs/transparent-proxy-fw4.md`
