---
name: rust-audit-family
disable-model-invocation: true
description: Router for the Rust-audit skill family — which of rust-audit, veyra-proof, tdd and domain-modeling to reach when.
---

# Rust-audit family

One name for the four skills that keep Rust code honest. Say what you want
done and the right skill opens; this router is the map.

| Skill | Reach it when |
|---|---|
| `rust-audit` | The question is about the code itself: stubs, fake tests, stubbed logic, panic/unsafe misuse, swallowed errors, hallucinated or typosquatted crates — and their safe fixes. |
| `veyra-proof` | The question is whether the workspace really passes: real-toolchain evidence (fmt, clippy, test, coverage, mutants) and a CI-grade pass/fail verdict. |
| `tdd` | The work is a feature or a bugfix and the tests should come first (red → green). |
| `domain-modeling` | The words or the architecture are moving: a term into `CONTEXT.md`, a decision into `docs/adr/`. |

## Fixed pairings

- An **audit** runs `rust-audit` and `veyra-proof` together on the same
  target — static triage plus toolchain evidence, one merged verdict with
  both evidence paths. The rule lives in `rust-audit`.
- Tests written or changed follow `tdd`; a change to what a term *means* is
  `domain-modeling` territory and lands in `CONTEXT.md` or an ADR.
