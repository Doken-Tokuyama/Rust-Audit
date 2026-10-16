# Rust Audit

Static auditor for AI-generated Rust code: it flags traps — fake tests, stubbed
logic, supply-chain risk — as findings backed by source evidence, and reports
what it could not check as loudly as what it found.

## Language

Canonical terms are the words used in the code, CLI output and reports; the
Spanish in parentheses is how the team says them.

### Audit model

**Finding** (hallazgo):
One audit result: a rule id, severity, message, source location and evidence.
_Avoid_: issue, alert, warning, defect

**Rule** (regla):
One named check in the R01–R21 catalog, with a fixed id and severity policy.
_Avoid_: lint

**Severity** (severidad):
A finding's position on the fixed critical/high/medium/low/info ladder, from
which the `--fail-on` verdict is derived.
_Avoid_: priority

**Evidence** (evidencia):
The excerpt of audited source attached to one finding, showing the smell in
situ.
_Avoid_: using "evidence" for generated report files — those are _reports_

**Evidence run** (ejecución de evidencia):
A recorded tool invocation in the audit trail — command, exit code, duration
and output excerpt — backing what the report claims was executed.
_Avoid_: evidence (that word is the per-finding excerpt)

**Report** (informe):
The generated artifact set of one scan run (terminal, Markdown, JSON, SARIF).
_Avoid_: evidence

**Golden** (golden):
The pinned expected scan result of one pinned workspace — totals by severity
and by rule — changed only as a deliberate, explained act.
_Avoid_: snapshot, baseline

**Pinned workspace** (workspace fijado):
A real Rust project checked out at a fixed commit, audited end-to-end through
the public CLI.
_Avoid_: fixture, demo, sample project

**Not-executed report** (informe de no ejecutados):
The dated list of checks that could not run and why; a verdict without it is
incomplete.

### Judgment

**False positive** (falso positivo):
A finding whose claim is provably wrong about the code — the criterion is
[ADR 0001](docs/adr/0001-false-positive-vs-true-positive-criterion.md).
_Avoid_: noise, "fires a lot on real code" as an argument

**True positive** (verdadero positivo):
A finding that matches its rule's documented definition and survives the
ADR 0001 exemptions, even where the pattern is normal style in the project.
_Avoid_: bug (a true positive is a review signal, not necessarily a defect)

**Triage** (triaje):
The classification of findings into true and false positives against
ADR 0001, with evidence per class.
_Avoid_: audit (the audit produces the findings; the triage judges them)

**Downgraded claim** (afirmación rebajada):
What is reported when the truth is undecidable — only the provable part of the
claim, at low severity — in place of an accusation the tool cannot justify.

### Idioms and fixtures

**Contract region** (región de contrato):
An `impl Trait for Type` block or `trait` default method, where a constant
return or a no-op body is the specification, not stubbed logic.

**Type assertion** (aserción de tipos):
Code whose only purpose is that the compiler checks a bound —
`fn check<T: Send>() {}`, or `if false { let _: T = …; }`.

**Compile-fail fixture** (fixture compile-fail):
A test source that must NOT compile (trybuild, sibling `.stderr`); no quality
verdict on it means anything.

### Fix policy

**Safe fix** (arreglo seguro):
The only kind of rewrite `fix` applies — formatting and MachineApplicable
lints — under the contract that nothing is deleted, only the policy file is
added, and a failed validation rolls the edit back.
_Avoid_: autofix as an unbounded rewrite

**Rollback** (revertido):
The transactional revert of an applied fix whose validation failed.
