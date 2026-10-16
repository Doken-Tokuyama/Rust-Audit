# A finding is false only when the tool's claim is provably wrong

R02/R03 were refined twice against pinned production workspaces
(BurntSushi/ripgrep@3fce3b5b, tokio-rs/tokio@cdd9dae3) after they reported
~1300 findings that the projects' own maintainers would reject. We classify
findings by **provability, not by volume**: a finding is a false positive when
the tool's claim is provably wrong about the code, and a true positive when it
matches the rule's documented definition (the test-smell / stub catalogs), even
if the pattern is normal style in that project. Refinement removes wrong
claims; it never weakens a rule that works as documented.

## The criterion

A finding is a **false positive** when any of these hold:

1. **The claim is provably wrong from the artifact alone.** "empty body" on a
   body that returns a string literal; "duplicate assertion" between two
   asserts whose arguments only look identical after string-masking; "ignores
   all parameters" naming a where-clause type (`F: FnOnce…`), not a parameter.
2. **The author declared intent.** `#[allow(unused_variables)]`, `_underscore`
   params, `#[should_panic]` (the panic IS the oracle), `unwrap()/expect()` as
   oracle, a comment explaining a no-op.
3. **The code is an idiom whose whole point is the "smell".** Trait-contract
   implementations (`impl Flag for X` metadata returning constants; sealed
   no-op `initialize()`), the compile-time type assertion `fn check<T: Send>()
   {}`, test-helper functions (only functions with a test attribute are
   tests), nested inner functions (they inherit the enclosing context).
4. **The language makes the smell impossible.** Assertion roulette cannot
   exist for `assert_eq!`/`assert_ne!` in Rust — the panic prints left/right
   and file:line — so only bare `assert!` counts. `assert!(false)` is a
   fail-if-reached guard, not a tautology.
5. **The artifact cannot run.** Trybuild compile-fail fixtures (sibling
   `.stderr`) must NOT compile; no quality verdict on them means anything.

It is a **true positive** when the claim is provable and no exemption applies —
even in a healthy project: duplicate assertions (identical macro+args repeated
within one scenario — ADR 0002 refines this claim),
magic-number comparisons, bare-`assert!` roulette, and cfg/macro-gated no-op
alternates (feature-off metric hooks, mock doubles) stay reported. Those are
review signals with accurate wording, not tool bugs.

When the truth is undecidable (e.g. a test delegating its assertions to
helpers), downgrade the **claim**, not the detection: report only what is
provable ("no direct oracle in its body: verify it can fail") at low severity,
never an accusation the tool cannot justify.

## Consequences

- Every heuristic change must cite a concrete misfire from a pinned real
  workspace and keep the per-project goldens and source-read invariants in
  `tests/test_production_e2e.py` honest: update them deliberately, with the
  rationale written next to the numbers.
- Shrinking the finding count is never a goal on its own; removing *wrong*
  claims is. A rule that fires 300 times correctly stays as it is.

## Considered options

- **Tune thresholds until maintainers stop complaining** (volume-driven).
  Rejected: it conflates style smells with misfires and silently weakens rules.
- **Drop rules that fire often on mature code.** Rejected: "fires a lot on real
  code" is not evidence of a false positive.
