# VeeX Source Map

## Start Here (Agent Onboarding Path)

If you are unfamiliar with the current project state, read these sources in order. Do not open the entire skill tree by default.

1. **`README.md`** — shortest public statement of what VeeX is and what it is not
2. **`docs/architecture.md`** — public architecture, current capability boundary, and stable external framing
3. **`references/repo-map.md`** — workspace crates, ownership, and implementation landing zones
4. **`references/config-contract.md`** — accepted config surface, route semantics, and tolerated-but-unimplemented fields
5. **`references/internal-architecture.md`** — internal model, anti-patterns, and design-review constraints
6. **`references/task-derived-gotchas.md`** — real failure modes already encountered in transparent-proxy and dual-stack work

For most tasks, stop after the first 2 to 4 sources unless the request clearly needs deeper project context.

After the above, open only the topic-specific sources you need:
- `docs/roadmap.md` — for phase, milestone, and evolution questions
- `references/observability-errors.md` — for tracing/event questions
- `references/architecture-closure.md` — for lower-level engineering closure questions
- `references/validation-status.md` — before claiming device validation is complete
- `references/validation-contract.md` — before writing validation evidence
- `references/trigger-examples.md` — to check whether this skill is the right trigger

## Stable Public Sources

- `README.md`
  - shortest public entrypoint
  - primary source for `what / why / how`
- `docs/architecture.md`
  - stable public architecture document
  - primary source for external boundary, core model, and current capability framing
- `docs/roadmap.md`
  - project phase history and evolution document
  - primary source for milestones, current stage, and roadmap direction
- `docs/observability.md`
  - canonical public observability and error-contract document
- `CHANGELOG.md`
  - version-by-version change history
  - authoritative source for what changed between releases
- `examples/socks-trojan.json`
- `examples/redirect-trojan.json`
- `examples/tproxy-compat.json`
  - use examples as concrete configuration starting points

## Stable Internal References

- `references/project-positioning.md`
  - compact project-scope and non-goal summary
- `references/repo-map.md`
  - crate ownership, dependency constraints, and landing zones
- `references/internal-architecture.md`
  - stable internal model, anti-patterns, and review checklist
- `references/observability-errors.md`
  - distilled skill-facing summary of current error-model and tracing contracts
- `references/architecture-closure.md`
  - internal boundary decisions that should remain stable
- `references/config-contract.md`
  - exact config-compatibility rules
- `references/validation-contract.md`
  - event contract, evidence expectations, and minimal diagnostics
- `references/validation-status.md`
  - recorded validation coverage and still-open device-closure items
- `references/task-derived-gotchas.md`
  - failure-focused project constraints

## Source Preference

- `README.md` and `docs/architecture.md` are the primary public entrypoints
- `docs/roadmap.md` is the primary source for phases, milestones, and roadmap direction
- `docs/observability.md` is the canonical public observability document, while `references/observability-errors.md` is the compact internal summary
- doc-placement questions should be answered by combining this file with the relevant target docs rather than by inventing a new document layer
- temporary stage material such as `.local` task files is not part of the active knowledge base
- if an important fact exists only in temporary material, it should be migrated into a persistent doc or reference
- when a fact appears in both a stable public guide and an internal reference, the public guide has priority unless the question is specifically about internal engineering constraints
