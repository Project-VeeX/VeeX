# Trigger Examples

## Should Trigger

- "Explain which slice of sing-box VeeX is replacing today, and which slices it is not."
- "Should this transparent-socket logic live in `core` or `infra-linux`?"
- "Update the public architecture doc to keep `tproxy` compatibility language aligned with the current implementation boundary."
- "Restructure `README`, `architecture`, `roadmap`, and the skill so each one has a clear responsibility."
- "Should this content live in `docs/architecture.md`, `docs/roadmap.md`, or a skill reference?"
- "This looks like a docs request, but tell me first whether it belongs in public docs or in the `veex-project` skill."
- "I want to add a new VeeX config field. First tell me whether it fits the current project scope."
- "Map the responsibilities of `crates/cli`, `crates/config`, `crates/core`, and `crates/infra-linux`."
- "How should `routing_mark` differ from the `tproxy` interception mark in this project?"
- "Before coding, tell me whether this VeeX request is in scope, partially in scope, or out of scope."

## Should Not Trigger

- "Explain why my Rust code hits E0502."
- "Refactor this Rust function for readability without changing VeeX behavior or boundaries."
- "Write a generic `nftables` setup for my OpenWrt box with no VeeX context."
- "Design the UI and interaction model for `luci-app-veex`."
- "Compare Trojan, VLESS, and VMess as protocols."
- "Write a general-purpose JSON parser."

## Validation Notes

- The skill should be able to classify scope using only its own `references/` files before opening repo code or docs.
- The skill should trigger early for doc-boundary and project-scope questions, before a narrower coding skill takes over.
- The skill should also trigger when a request is deciding whether to code at all, or first settle scope and document/crate ownership.
- If the request is only about Rust syntax, ownership, async, or test style and does not need project context, the skill is over-triggering.
- If a request clearly depends on project positioning, crate boundaries, transparent-proxy docs, config-compatibility policy, or phase constraints and this skill does not trigger, the description is too weak.
- Manual validation should cover at least:
  - project scope: why DNS is still outside the current target
  - architecture boundary: why Linux transparent logic should not move back into `core`
  - source routing: when to rely on `docs/architecture.md` and `docs/roadmap.md` versus historical validation material
