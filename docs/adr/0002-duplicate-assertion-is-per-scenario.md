---
status: accepted
---

# A duplicate assertion is claimed only within one scenario, and only as far
# as it is provable

R02's "duplicate assertion" used to claim redundancy for any identical assert
arguments repeated in a test, but the catalog's own fix for the smell is "vary
the input" — so repeating the same expectation after the input changed is the
cure, not the smell. Measured against the two pinned workspaces (450k lines):
562 findings, of which **495 (88%)** are the same expectation across scenarios
(typical rows of a parse-flag matrix like `test_path_separator`'s `-A5` vs
`--after-context 5`). We decided to claim a duplicate only when identical
asserts (same macro, same arguments) repeat inside ONE scenario — nothing but
other asserts between them. For the 67 same-scenario repeats that remain,
redundancy itself is not provable: every one of them has state-advancing
argument expressions (`stream.next().await`, method calls — zero pure-argument
cases), so per ADR 0001 the claim says only what is provable — the repeat —
with an explicit hedge ("redundant only if the interleaved asserts do not
advance state") and low severity.

## Considered Options

- **Blanket exemption of repeated expectations.** Rejected: it deletes a rule
  that works exactly as the catalog documents it, and the tool audits
  AI-generated code where back-to-back copy-paste duplicates are the real trap.
- **Per-test exemption list.** Rejected: an allowlist of test names cannot
  generalize and rots; the scenario boundary is what makes the claim provable.
- **Plain "duplicate" claim for the same-scenario survivors.** Rejected: the
  repeats in tokio's fused-stream tests deliberately re-check a predicate after
  the interleaved assert polled the stream; "redundant" would be an accusation
  the tool cannot justify.

## Consequences

- ripgrep@3fce3b5b total 521→321 (200 duplicate claims dropped, 1 kept),
  tokio@cdd9dae3 total 2731→2436 (295 dropped, 66 kept); every survivor was
  re-derived from raw source.
- The claim's identity includes the macro name: `assert_ne!(a, b)` and
  `assert_eq!(a, b)` assert opposites and can never be duplicates of each other.
- The rule stays armed for the provable case: identical asserts repeated
  back-to-back with pure arguments (verified through the real CLI on a crafted
  case) — the classic copy-paste artifact in generated code.
- `macro_calls` returns invocations grouped by macro name, not by position;
  any pairing of its results must sort by position first.
