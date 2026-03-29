# Transparent Proxy Validation On OpenWrt 22.03+

This guide maps the same validation model to `fw4 + nftables` systems.

It is not the primary validated path for this repository today. The primary validated path is OpenWrt 21.02 / ImmortalWrt 21.02 with `fw3 + iptables`. Use this document as a conservative starting point for newer OpenWrt releases and validate it on your own target before treating it as production guidance.

## Scope

Target class:

- OpenWrt 22.03+
- `fw4`
- `nftables`
- TCP only

## Mapping

The control-plane intent is unchanged:

- only redirect one client at a time
- only redirect one destination at a time
- keep rules temporary during validation
- confirm `original_dst`, route selection, and rollback behavior before broadening scope

`PREROUTING` still owns downstream client traffic. `OUTPUT` still applies only to router-originated traffic and should stay out of the first validation round.

## Conservative Temporary Table

Create a dedicated temporary table and chain:

```sh
nft add table inet veex_test
nft 'add chain inet veex_test prerouting { type nat hook prerouting priority dstnat; policy accept; }'
```

Single-client, single-target redirect example:

```sh
nft add rule inet veex_test prerouting iifname "br-lan" ip saddr 192.168.7.150 ip daddr 185.45.5.35 tcp dport 443 redirect to :10080
```

This corresponds to the `redirect -> trojan` validation flow described in the `iptables` guide.

## Expected Logs

Expected `veex` log sequence:

```text
event=session_start inbound=redir-in original_dst=185.45.5.35:443
event=session_finish outbound=proxy bytes_up=... bytes_down=... error_kind=none
```

For bypass validation:

```text
event=route_select outbound=direct reason=private
event=session_finish outbound=direct error_kind=none
```

## Rollback

Delete the temporary table when done:

```sh
nft delete table inet veex_test
kill -TERM "$(cat /tmp/veex-redir.pid 2>/dev/null)" 2>/dev/null || true
```

## fw4 Integration Note

If you later need persistent rules, prefer a dedicated `fw4` include owned by a downstream packaging or operations layer. Do not treat the temporary validation rules above as a drop-in persistent policy.
