# Transparent Proxy Troubleshooting

This document focuses on the failure modes that matter during transparent proxy validation, especially the `redirect` and `tproxy` TCP paths.

## Service Does Not Start

Symptoms:

- `veex run -c ...` exits immediately
- no listener on the redirect port

Checks:

```sh
/tmp/veex version
/tmp/veex check -c /tmp/veex-redirect-trojan.json
ss -ltnp | grep 10080
```

If `check` fails, fix the config before looking at firewall rules.

If you are validating a dual-stack `tproxy` config whose inbound listens on `::`, expect the listener to appear as either `[::]:<port>` or `*:<port>` depending on the userspace tools on that router.

## Rules Do Not Match

Symptoms:

- client traffic bypasses `veex`
- no `event=session_start` in logs

Checks:

```sh
iptables -t nat -S
nft list ruleset
```

Common causes:

- wrong client IP
- wrong destination IP
- wrong interface name
- redirect port mismatch

## `SO_ORIGINAL_DST` Fails

Symptoms:

- `event=inbound_error`
- message mentions `original dst`
- redirect listener accepts a connection but cannot restore the original destination

Checks:

```sh
logread | grep veex
strace -e getsockopt -p <veex_pid>
```

Common causes:

- the socket was not actually redirected
- the test used the wrong firewall hook
- the listener accepted a plain local connection instead of a redirected one

If logs show an IPv4-mapped peer such as `[::ffff:192.168.x.x]:port`, current `veex` retries the IPv4 original-destination socket option automatically. Persistent failure usually means the firewall delivery path is still wrong rather than a simple address-family mismatch.

## Trojan Outbound Fails

Symptoms:

- `event=session_finish ... error_kind=tls`
- `event=session_finish ... error_kind=dial`

Checks:

```sh
logread | grep veex
nslookup <trojan_host> 127.0.0.1
```

If you see certificate validation failures against a third-party endpoint and that endpoint is outside your control, use `tls.insecure=true` only for validation and document that you made that tradeoff.

## Success On Client, Failure In Logs

Symptoms:

- the client receives a successful response
- `veex` logs a failure anyway

Current known case already fixed:

- TLS peer closes without `close_notify`
- rustls reports `UnexpectedEof`
- `VeeX` now tolerates that condition only in the Trojan TLS transport layer

If you still see this pattern after updating the binary, verify that the router is actually running the new `/tmp/veex`.

## Recursive Proxying

Symptoms:

- the Trojan server becomes unreachable only when redirect rules are active
- logs show repeated attempts through `outbound=proxy`
- local management traffic loops unexpectedly

Checks:

```sh
logread | grep 'event=route_select'
```

You should see bypass logs for:

- private ranges
- loopback
- configured Trojan server addresses

If the Trojan server address is not being bypassed, restart `veex` after confirming the current DNS resolution of that hostname.

## Direct Bypass Times Out

This can still be a valid bypass result.

Example:

- log shows `outbound=direct`
- log shows `reason=configured`
- connection later times out

That means recursion prevention worked, but the direct path to that target did not complete within the timeout window.

## Minimal Diagnostic Set

Use this exact order:

```sh
/tmp/veex version
/tmp/veex check -c <config>
ss -ltnp | grep <redirect_port>
iptables -t nat -S
logread | grep veex
```

Only move to lower-level tools like `strace` once those checks fail to explain the behavior.
