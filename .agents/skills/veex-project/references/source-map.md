# VeeX Source Map

## Start Here (Agent Onboarding Path)

When a new agent or you are unfamiliar with the current project state, read these references in order:

1. **`references/project-positioning.md`** — What VeeX is, what it is not, the one-line definition, supported surface, and explicit non-goals. Start here before touching any code.
2. **`references/phase-map.md`** — What each phase (1 through 4) delivered and which conclusions still carry forward. Gives historical context for why the architecture looks the way it does.
3. **`references/repo-map.md`** — The workspace crates, who owns what, and where new changes should land. Read before opening any crate code.
4. **`references/config-contract.md`** — The exact accepted config surface, bypass semantics, and which fields are tolerated-but-unimplemented. Required reading before any config-related work.
5. **`references/architecture-closure.md`** — Internal boundary decisions that are closed and should not be reopened. Read before refactoring or expanding any core abstraction.
6. **`references/task-derived-gotchas.md`** — Real failure modes already encountered. High-value reading before touching transparent proxy, routing_mark, or dual-stack paths.

After the above, use the remaining references as needed:
- `references/observability-errors.md` — for tracing/event questions
- `references/validation-status.md` — before claiming device validation is complete
- `references/validation-contract.md` — before writing validation evidence
- `references/trigger-examples.md` — to check whether this skill is the right trigger

## Stable Public Sources

- `README.md`
  - shortest public entrypoint
  - use for `what / why / how`
- `PROJECT_GUIDE.md`
  - stable project guide
  - use for repository boundary, target topology, workspace structure, runtime model, compatibility contract, and operational signals
- `CHANGELOG.md`
  - version-by-version change history
  - authoritative source for what changed between releases
- `examples/socks-trojan.json`
- `examples/redirect-trojan.json`
- `examples/tproxy-compat.json`
  - use examples as concrete configuration starting points

## Stable Internal References

- `references/phase-map.md`
  - phase-by-phase delivery summary
- `references/repo-map.md`
  - crate ownership, dependency constraints, and landing zones
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

## Usage Rules

- Prefer `README.md` and `PROJECT_GUIDE.md` before opening internal references.
- Prefer `docs/observability-and-errors.md` as the canonical repo document, and use `references/observability-errors.md` as the compact skill summary.
- Do not depend on `.local` task files or temporary stage docs as active knowledge sources for this skill.
- If important information exists only in temporary material, migrate it into a persistent doc or skill reference before relying on it.
- If a fact appears in both a stable guide and an internal reference, prefer the stable guide unless the question is specifically about internal engineering constraints.
