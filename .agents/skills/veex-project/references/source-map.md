# VeeX Source Map

## Stable Public Sources

- `README.md`
  - shortest public entrypoint
  - use for `what / why / how`
- `PROJECT_GUIDE.md`
  - stable project guide
  - use for repository boundary, target topology, workspace structure, runtime model, compatibility contract, and operational signals
- `examples/socks-trojan.json`
- `examples/redirect-trojan.json`
- `examples/tproxy-compat.json`
  - use examples as concrete configuration starting points

## Stable Internal References

- `references/phase-map.md`
  - phase-by-phase delivery summary
- `references/repo-map.md`
  - crate ownership, dependency constraints, and landing zones
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
- Do not depend on `.local` task files or temporary stage docs as active knowledge sources for this skill.
- If important information exists only in temporary material, migrate it into a persistent doc or skill reference before relying on it.
- If a fact appears in both a stable guide and an internal reference, prefer the stable guide unless the question is specifically about internal engineering constraints.
