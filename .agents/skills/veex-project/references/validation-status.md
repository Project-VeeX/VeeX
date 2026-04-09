# VeeX Validation Status

This reference records the current persisted validation snapshot for VeeX.

## Snapshot Date

Latest recorded snapshot: April 3, 2026.

## Recorded Coverage

- `fw3 + iptables` redirect validation has documented device closure
- redirect to direct for private destinations has recorded success evidence
- redirect to trojan has recorded success evidence
- Trojan server self-bypass has recorded validation evidence
- Phase3 documentation for TPROXY, `routing_mark`, compatibility, SOP, and regression closure has been written and reviewed

## Not Yet Closed In Recorded Material

- equivalent `fw4/nft` device validation is not yet recorded as closed
- TPROXY device closure on OpenWrt / Linux is still a required validation item
- `direct.routing_mark` no-loop validation on a real policy-routing target is still a required validation item

## Interpretation Notes

- any statement about current validation coverage should include the snapshot date
- full transparent-proxy closure should not be claimed beyond the items above unless newer recorded evidence exists
- `docs/architecture.md` remains the stable project statement; this file is only the validation-maturity snapshot
