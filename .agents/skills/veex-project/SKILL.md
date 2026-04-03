---
name: veex-project
description: Use when working inside the VeeX main repository and the task depends on project scope, crate boundaries, transparent-proxy documentation, config-compatibility rules, or phase/task conclusions. Trigger on requests about VeeX, veex, transparent proxy, tproxy, redirect, trojan, routing_mark, OpenWrt scope, Passwall replacement surface, repository boundaries, or whether a change fits the current project direction. Do not use for generic Rust-only questions, generic OpenWrt operations, or downstream packaging/LuCI repository work.
---

# VeeX Project

Use this skill to align on VeeX project context before editing code or docs. The job is to answer four questions quickly: what VeeX currently is, what it explicitly does not do, which crates or docs a change should touch, and which prior conclusions a new change must not violate.

## Goal

- Build the smallest useful context for VeeX product scope, repository boundaries, documentation layout, and phase constraints.
- Decide whether the request is in scope before writing code, changing docs, or proposing validation steps.
- Keep project constraints ahead of generic Rust instincts; do not let "possible to implement" override "not part of the current product".

## Boundaries

- This is a VeeX main-repo context skill. It does not cover downstream `veex-openwrt`, `luci-app-veex`, feed, or packaging repository implementation.
- This is not a replacement for `rust-skill` or narrower Rust skills. Once the problem becomes language-level, testing-level, or concurrency-level, combine this skill with a narrower Rust skill.
- For DNS, UDP, TUN, sniff, fake-ip, full `route.rules`, or full sing-box compatibility, first classify the request as out of scope or later-roadmap work before discussing implementation.
- Do not rely on `.local` task files or other temporary stage material as required inputs. If important content exists only there, migrate it into persistent project docs or skill references first.

## Workflow

1. Classify the request first:
   - Project positioning, target topology, milestone, or replacement-surface questions: read `references/project-positioning.md`
   - Phase-by-phase delivery or evolution questions: read `references/phase-map.md`
   - Code changes, crate ownership, dependency direction, or implementation landing zones: read `references/repo-map.md`
   - Stable repo sources, examples, and internal persistent references: read `references/source-map.md`, then open only the relevant files
   - Internal architecture-closure and validation-status questions: read `references/architecture-closure.md` or `references/validation-status.md`
   - Exact compatibility rules or validation evidence expectations: read `references/config-contract.md` or `references/validation-contract.md`
   - Historical constraints, phase conclusions, or likely missteps: read `references/task-derived-gotchas.md`
2. Load only the reference files required for the current question. Do not read the entire skill tree or all repo docs by default.
3. Before implementation, state explicitly:
   - whether the request is `in scope`, `partially in scope`, or `out of scope`
   - which crates, examples, or docs are most likely to change
   - whether the work requires Linux/OpenWrt device validation instead of automation only
4. If the task turns into detailed Rust design or coding, combine a narrower Rust skill, but keep this skill as the project-boundary authority.

## Output Expectations

- Lead with the conclusion and next action, then add background only if needed.
- State whether the request matches the current VeeX direction. Do not default to implementation just because the change is technically possible.
- For config-compatibility or documentation changes, identify the examples, contract docs, and validation material that must stay aligned.
- For `tproxy`, `routing_mark`, or transparent-socket changes, call out which checks still require Linux/OpenWrt device validation.

## Gotchas

- Do not describe VeeX as a full sing-box replacement. The current role is a TCP execution plane for OpenWrt-class proxy paths.
- Do not move OpenWrt packaging, `procd`, or LuCI integration back into this repository. The main repo owns Rust core, CLI, config, tests, and docs.
- Do not confuse "unknown fields are ignored" with "the feature is implemented". Ignored and supported are different states.
- Do not push Linux transparent-socket details back into `crates/core`; `core` must stay platform-agnostic.
- Do not reuse the same mark for `tproxy` interception and `direct.routing_mark`; they serve different purposes.
- Do not treat `listen="::"`, dual-stack behavior, or IPv4-mapped-IPv6 as edge cases. They are first-class real-world paths in this project.

## Resource Navigation

- `references/project-positioning.md`: product role, supported surface, non-goals, and repository boundary.
- `references/phase-map.md`: what each major phase delivered and which conclusions still carry forward.
- `references/repo-map.md`: workspace structure, crate ownership, landing zones, and dependency constraints.
- `references/source-map.md`: stable sources, examples, and internal persistent references.
- `references/architecture-closure.md`: internal boundary decisions that should keep guiding code changes.
- `references/config-contract.md`: exact compatibility rules and accepted config forms.
- `references/validation-contract.md`: event shapes, evidence expectations, and minimal diagnostics.
- `references/validation-status.md`: latest recorded validation coverage and still-open device-closure items.
- `references/task-derived-gotchas.md`: hard constraints and real failure modes extracted from phase tasks and closure notes.
- `references/trigger-examples.md`: trigger examples, non-trigger examples, and manual validation notes.
