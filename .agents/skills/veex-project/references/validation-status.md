# VeeX Validation Status

This file summarizes the current persisted validation status for VeeX.

## Snapshot Date

Latest recorded status in this skill: April 3, 2026.

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

## Response Rule

- If asked about current validation coverage, state the recorded status and the snapshot date explicitly.
- Do not claim full transparent-proxy closure beyond the items above unless newer evidence is added to the repository.
- Prefer `PROJECT_GUIDE.md` for the stable project statement and use this file when the question is specifically about validation maturity.
