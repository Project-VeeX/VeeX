# VeeX Internal Architecture

This reference records the internal model constraints, anti-patterns, and design-review rules for VeeX. `references/architecture-closure.md` carries the lower-level implementation closures that sit underneath this model.

## Core Model That Must Not Break

### Router = One Ordered Rule Pipeline

```text
ordered rules
  -> Upgrade (mutate context, continue)
  -> Final (terminate with decision)
default final action
```

Keep these invariants:

- no hidden pre-router or post-router decision stage
- no backtracking after a rule action runs
- no special-case branch that bypasses the same pipeline model

### RouteAction Layering Must Stay Stable

```text
RouteAction = Upgrade | Final
```

- `Upgrade`: enrich routing context and continue
- `Final`: produce the routing decision and stop

Do not let an upgrade action silently become a final decision, and do not let a final action continue the pipeline.

### Sniff = Bounded Context Enrichment

The supported sniff model is:

```text
sniff -> RouteInput.domain
```

Keep it bounded:

- no destination override
- no DNS side effects
- no transport policy side effects
- no hidden rerun of earlier rules

### Timeouts Stay Phase-Specific

Timeouts are layered by stage:

- sniff timeout
- TCP connect timeout
- TLS handshake timeout

Do not merge them into a global session deadline just for convenience.

## Hard Constraints

### Explicit Behavior Only

Routing and connection behavior must come from explicit config or a clearly documented default.

Reject:

- auto-injected bypass rules
- automatic outbound rewrites
- implicit recursion-prevention logic that the user cannot see

### No Cross-Layer Capability Smuggling

Keep ownership clear:

| Capability | Layer |
| --- | --- |
| route decision | router |
| sniff | sniff module / route upgrade |
| connect | transport |
| timeout | owning stage |

Reject patterns like:

- router performing network operations
- transport making route decisions
- outbound code owning connect-timeout policy

### No Semantic Drift

If a feature changes meaning, treat that as a design change, not a tiny implementation detail.

Examples to reject:

- sniff becoming destination rewrite
- bypass reappearing as hidden special handling
- timeout fields being reused for unrelated stages

### No Feature Smuggling

New capabilities must be explicitly modeled, clearly owned, and justified against the current project boundary. Do not sneak future ideas into today's abstractions.

## Anti-Patterns To Reject

### Implicit Bypass

Bad:

```text
system auto-adds private -> direct
```

Correct:

```text
rule + Final(Route("direct"))
```

### Sniff Override Destination

Bad:

```text
sniff domain -> resolve -> replace original target
```

This pulls DNS and routing control into a feature that is only meant to enrich context.

### Global Timeout

Bad:

```text
one timeout for the whole session
```

This destroys stage-level observability and makes failures harder to explain.

### Multi-Pass Decision Loops

Bad:

```text
sniff -> route -> sniff again -> route again
```

The routing model is intentionally single-pass.

### Router Special Cases

Bad:

```text
if private ip -> special handling path
```

Private, loopback, and link-local handling belongs in normal rules, not side channels.

### Transport-Layer Routing

Bad:

```text
transport inspects domain and changes behavior
```

That is layer contamination.

## OpenWrt / Passwall Framing

- Passwall commonly leans on kernel-space interception and bypass semantics.
- VeeX models these decisions inside an explicit user-space rule pipeline.
- VeeX handles traffic that has already entered the proxy path; it is not trying to become the whole network control plane.

## Design Review Checklist

Before accepting a design or patch, ask:

- Does this preserve the single ordered rule pipeline?
- Does this keep responsibilities in the correct layer?
- Does this introduce hidden behavior?
- Does this widen scope beyond the current proxy execution target or reintroduce a fake hierarchy between stream and packet where the code already supports both?
- Does this weaken tracing or error explainability?
