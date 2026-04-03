# VeeX Phase Map

Use this file when the task depends on what each major phase delivered, what changed between phases, or which conclusions are phase-specific versus still active.

## Phase 1

Phase 1 established the minimum executable path:

- `socks` inbound
- `trojan` outbound
- `direct` outbound
- relay
- CLI startup
- config loading and checking

The main result of this phase was proving that the core execution path and crate split were viable.

## Phase 2

Phase 2 moved the project from a local demo path toward router usability.

Key additions:

- `redirect` inbound
- Linux original-destination recovery
- stronger bypass behavior
- better runtime behavior and shutdown handling

The important phase conclusion was that system-integration knowledge had to become a first-class deliverable, not just an implementation detail.

## Phase 3

Phase 3 focused on replacing the transparent-proxy TCP execution surface in real router topologies.

Key additions:

- `tproxy` inbound
- `direct.routing_mark`
- narrower but more explicit config compatibility
- transparent-proxy engineering for dual-stack and IPv4-mapped-IPv6 realities

The important phase conclusion was that this was no longer just "add one inbound"; it required a robust Linux transparent-socket subsystem and clear validation discipline.

## Current Carry-Forward Conclusions

The following conclusions still matter across phases:

- VeeX remains a TCP execution plane, not a full proxy platform
- platform-specific transparent-proxy details must stay out of `core`
- config compatibility must stay narrow and explicit
- validation maturity must not be overstated beyond recorded evidence
- downstream OpenWrt packaging and LuCI work stay outside this repository

## Usage Rule

- Use this file for phase-aware context, not as a roadmap wishlist.
- If a phase detail matters only as historical background and not as an active constraint, prefer the current project guide and active references instead.
