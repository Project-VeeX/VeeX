# Transparent Proxy Validation On OpenWrt 21.02

This guide covers the conservative validation path for `fw3 + iptables` systems such as OpenWrt 21.02 and ImmortalWrt 21.02.

It is intentionally scoped to temporary validation rules. It does not modify `/etc/config/firewall`, does not restart the firewall service, and does not attempt to manage rules persistently.

## Scope

Validated target class:

- OpenWrt 21.02 / ImmortalWrt 21.02
- `fw3`
- `iptables`
- TCP only

Validated data paths:

- `REDIRECT -> redirect inbound -> direct outbound -> private destination`
- `REDIRECT -> redirect inbound -> trojan outbound -> external HTTPS`

## Concepts

`PREROUTING` is used for LAN client traffic entering the router. This is the primary path for validating transparent proxying of downstream devices.

`OUTPUT` is only needed if you want to transparently proxy connections initiated by the router itself. That is not required for the basic LAN validation flow and should stay out of the first verification round.

## Safety Rules

Use all of the following constraints during validation:

- only target one client IP at a time
- only target one destination IP and port at a time
- only use temporary rules
- always keep a rollback command ready
- do not redirect the `veex` listening port back into itself
- do not rely on firewall rules alone to prevent recursion; `veex` must still bypass reserved ranges and the Trojan server address

## Temporary Cleanup

Before and after each validation round:

```sh
iptables -t nat -D PREROUTING -i br-lan -j VEEX_TEST 2>/dev/null || true
iptables -t nat -F VEEX_TEST 2>/dev/null || true
iptables -t nat -X VEEX_TEST 2>/dev/null || true
kill -TERM "$(cat /tmp/veex-redir.pid 2>/dev/null)" 2>/dev/null || true
```

## Validation 1: Private Destination Bypass

Goal:

- verify `REDIRECT`
- verify `SO_ORIGINAL_DST`
- verify `private` bypass
- avoid external traffic

Start `veex` with a `redirect + direct` config:

```sh
/tmp/veex run -c /tmp/veex-redirect-direct.json > /tmp/veex-redir.log 2>&1 &
echo $! > /tmp/veex-redir.pid
```

Create a temporary chain and redirect only one client to the router local web interface:

```sh
iptables -t nat -N VEEX_TEST 2>/dev/null || true
iptables -t nat -F VEEX_TEST
iptables -t nat -I PREROUTING 1 -i br-lan -j VEEX_TEST
iptables -t nat -A VEEX_TEST -s 192.168.7.150 -d 192.168.7.1 -p tcp --dport 80 -j REDIRECT --to-ports 10080
```

From the test client:

```sh
curl -I http://192.168.7.1/
```

Expected `veex` log shape:

```text
event=session_start inbound=redir-in original_dst=192.168.7.1:80
event=route_select outbound=direct reason=private
event=session_finish outbound=direct error_kind=none
```

## Validation 2: Redirect To Trojan Outbound

Goal:

- verify `redirect inbound`
- verify restored destination address
- verify `trojan outbound`
- verify successful HTTPS through transparent proxy

Start `veex` with a `redirect + trojan` config:

```sh
/tmp/veex run -c /tmp/veex-redirect-trojan.json > /tmp/veex-redir.log 2>&1 &
echo $! > /tmp/veex-redir.pid
```

Resolve the target host on the router first and pick one IPv4 address:

```sh
nslookup www.google.com 127.0.0.1
```

Create a single-target temporary rule:

```sh
iptables -t nat -N VEEX_TEST 2>/dev/null || true
iptables -t nat -F VEEX_TEST
iptables -t nat -I PREROUTING 1 -i br-lan -j VEEX_TEST
iptables -t nat -A VEEX_TEST -s 192.168.7.150 -d 185.45.5.35 -p tcp --dport 443 -j REDIRECT --to-ports 10080
```

From the test client:

```sh
curl --resolve www.google.com:443:185.45.5.35 -I https://www.google.com
```

Expected `veex` log shape:

```text
event=session_start inbound=redir-in original_dst=185.45.5.35:443
event=session_finish outbound=proxy bytes_up=... bytes_down=... error_kind=none
```

If you are using a third-party Trojan endpoint with a certificate chain that fails strict verification, use `tls.insecure=true` only for validation and record that decision explicitly.

## Validation 3: Trojan Server Self-Bypass

Goal:

- verify that the Trojan server address does not recurse back into `proxy`

Restart `veex` after resolving the Trojan host so that its current IP set can be added to the bypass table.

Create a temporary rule targeting the Trojan server address itself:

```sh
iptables -t nat -N VEEX_TEST 2>/dev/null || true
iptables -t nat -F VEEX_TEST
iptables -t nat -I PREROUTING 1 -i br-lan -j VEEX_TEST
iptables -t nat -A VEEX_TEST -s 192.168.7.150 -d <trojan_server_ip> -p tcp --dport <trojan_server_port> -j REDIRECT --to-ports 10080
```

The success criterion is not an application-level `200 OK`. The success criterion is:

- `event=route_select`
- `outbound=direct`
- `reason=configured`
- no recursion into `outbound=proxy`

## Rollback

Always remove rules and stop `veex` when a round is finished:

```sh
iptables -t nat -D PREROUTING -i br-lan -j VEEX_TEST
iptables -t nat -F VEEX_TEST
iptables -t nat -X VEEX_TEST
kill -TERM "$(cat /tmp/veex-redir.pid)"
```

## Notes

- This guide is intentionally narrow. It proves the data path before any attempt at persistent firewall integration.
- Broad LAN-wide `80/443` interception should only be attempted after the regression checklist is fully green.
