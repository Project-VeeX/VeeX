# OpenWrt Transparent Proxy SOP

This SOP describes the smallest reproducible Phase3 validation flow on an OpenWrt-class router without relying on package-manager integration.

It assumes:

- `veex` has already been cross-built for the target device
- the binary is uploaded manually, for example to `/tmp/veex`
- configuration files are uploaded manually
- firewall rules are temporary

Primary references:

- `docs/transparent-proxy-tproxy.md`
- `docs/transparent-proxy-routing-mark.md`
- `docs/tproxy-config-compatibility.md`

Fallback references for older `REDIRECT` validation:

- `docs/transparent-proxy-iptables.md`
- `docs/transparent-proxy-fw4.md`

## 1. Preflight

Confirm the binary runs:

```sh
/tmp/veex version
```

Confirm the Phase3 compatibility config parses:

```sh
/tmp/veex check -c /tmp/tproxy-compat.json
```

## 2. Stop The Previous Transparent Proxy Daemon

Stop the previously running transparent proxy process before starting `veex`.

Examples:

```sh
/etc/init.d/<previous_proxy_service> stop 2>/dev/null || true
killall <previous_proxy_binary> 2>/dev/null || true
```

Do not continue until you are sure only one transparent proxy data plane is active.

## 3. Prepare Policy Routing

Install the temporary policy routing bootstrap used by the TPROXY interception mark:

```sh
ip rule add fwmark 0x1/0x1 lookup 100
ip route add local 0.0.0.0/0 dev lo table 100
```

Verify them:

```sh
ip rule show
ip route show table 100
```

## 4. Start `veex`

```sh
/tmp/veex run -c /tmp/tproxy-compat.json > /tmp/veex-tproxy.log 2>&1 &
echo $! > /tmp/veex-tproxy.pid
```

Verify the listener:

```sh
ss -ltnp | grep 1041
```

## 5. Add Temporary TPROXY Rules

Follow one of the temporary TPROXY setups from:

- `docs/transparent-proxy-tproxy.md`

Keep the validation narrow:

- one client
- one destination IP
- one destination port

## 6. Validate The Data Path

Validate in this order:

1. private bypass
2. Trojan outbound
3. Trojan server self-bypass

Useful checks:

```sh
curl --resolve www.google.com:443:185.45.5.35 -I https://www.google.com
ip rule show
ip route show table 100
logread | grep 'event=session_start'
logread | grep 'event=route_select'
logread | grep 'event=session_finish'
```

Success criteria:

- rule counters increase
- `event=session_start` shows the expected `original_dst`
- private traffic shows `outbound=direct` and `reason=private`
- Trojan traffic shows `outbound=proxy`
- Trojan server self-bypass shows `outbound=direct` and `reason=configured`
- successful sessions end with `error_kind=none`

## 7. Validate Direct No-Loop Behavior

If the deployment also intercepts router-originated traffic, validate the direct egress mark plan from:

- `docs/transparent-proxy-routing-mark.md`

Success criteria:

- marked direct traffic stays on `outbound=direct`
- marked direct traffic does not recurse into `outbound=proxy`

## 8. Collect Evidence

Keep the following:

- the exact config file
- the exact firewall commands
- the exact `ip rule` and `ip route` output
- client command output
- `veex` log output

## 9. Roll Back

Always remove temporary rules, policy routing state, and stop `veex`:

```sh
iptables -t mangle -D PREROUTING -i br-lan -j VEEX_TPROXY 2>/dev/null || true
iptables -t mangle -F VEEX_TPROXY 2>/dev/null || true
iptables -t mangle -X VEEX_TPROXY 2>/dev/null || true
nft delete table inet veex_tproxy 2>/dev/null || true
ip rule del fwmark 0x1/0x1 lookup 100 2>/dev/null || true
ip route del local 0.0.0.0/0 dev lo table 100 2>/dev/null || true
kill -TERM "$(cat /tmp/veex-tproxy.pid 2>/dev/null)" 2>/dev/null || true
```

## 10. Run The Redirect Fallback If Needed

If the TPROXY path is not green yet, re-run the conservative `REDIRECT` validation flow before blaming application logic:

- `docs/transparent-proxy-iptables.md`
- `docs/transparent-proxy-fw4.md`

Do not broaden to persistent firewall integration or wider interception until the conservative validation path is green end-to-end.
