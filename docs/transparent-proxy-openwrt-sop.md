# OpenWrt Transparent Proxy SOP

This SOP describes the smallest reproducible flow for validating transparent proxy behavior on an OpenWrt-class router without relying on a package manager integration.

It assumes:

- `veex` has already been cross-built for the target device
- the binary is uploaded manually, for example to `/tmp/veex`
- configuration files are uploaded manually
- firewall rules are temporary

## 1. Preflight

Confirm the binary runs:

```sh
/tmp/veex version
```

Confirm the config parses:

```sh
/tmp/veex check -c /tmp/veex-redirect-trojan.json
```

## 2. Start `veex`

```sh
/tmp/veex run -c /tmp/veex-redirect-trojan.json > /tmp/veex-redir.log 2>&1 &
echo $! > /tmp/veex-redir.pid
```

Verify the listener:

```sh
ss -ltnp | grep 10080
```

## 3. Validate Private Bypass First

Use the conservative `iptables` flow from:

- `docs/transparent-proxy-iptables.md`

Success criteria:

- the client reaches the router local service
- `event=route_select` shows `reason=private`
- `event=session_finish` ends with `error_kind=none`

## 4. Validate Trojan Path

Still follow the conservative `iptables` flow and only redirect:

- one client
- one destination IP
- one port

Success criteria:

- the client receives a successful HTTPS response
- `event=session_start` shows the expected `original_dst`
- `event=session_finish` shows `outbound=proxy`
- `event=session_finish` ends with `error_kind=none`

## 5. Validate Trojan Server Self-Bypass

Restart `veex`, then target the Trojan server address itself.

Success criteria:

- `event=route_select` shows `outbound=direct`
- `reason=configured`
- no recursion into `outbound=proxy`

## 6. Collect Evidence

Keep the following:

- the exact config file
- the exact firewall commands
- client command output
- `veex` log output

## 7. Roll Back

Always remove temporary rules and stop `veex`:

```sh
iptables -t nat -D PREROUTING -i br-lan -j VEEX_TEST 2>/dev/null || true
iptables -t nat -F VEEX_TEST 2>/dev/null || true
iptables -t nat -X VEEX_TEST 2>/dev/null || true
kill -TERM "$(cat /tmp/veex-redir.pid 2>/dev/null)" 2>/dev/null || true
```

## 8. Escalate Only After This SOP Passes

Do not move to persistent firewall integration, package integration, or broader LAN interception until this SOP is green end-to-end.
