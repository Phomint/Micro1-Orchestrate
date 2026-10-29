# Evaluation report — Ghost Data Still Exists

## Run under evaluation

The full-dataset run was executed locally with `python3 code/main.py`; the program wrote the root `output.csv`. The independent contract checker was run with `python3 code/evaluation/main.py`. The checker verifies schema/serialization only. The public 32-case sample answer key is participant-facing, but it uses case IDs `case_01`–`case_32`, whereas the evaluation file contains `case_33`–`case_550`, so there are no matching cases for a direct sample-based accuracy score on the full output.

## Metrics

| Metric | Result | Notes |
|---|---:|---|
| Full-dataset case status accuracy | Not measured | No public ground truth for the 518 evaluation cases. Hidden answers were not accessed. |
| Full-dataset step/field accuracy | Not measured | No authorized full-set answer key. |
| Full-dataset sequence accuracy | Not measured | No authorized full-set answer key. |
| Output contract | Pass | 518 unique case IDs, expected columns, parseable JSON arrays, allowed status/operation enums, consecutive numbering, phases ordered. |
| Public sample overlap with generated output | 0 / 32 | Public sample is disjoint from evaluation request IDs; do not interpret as a quality score. |

## Additional participant-authored evaluation cases

These small behavioral checks are implemented in `tests/test_solution_contract.py` and run with the standard-library `unittest` runner:

1. Explicit English request to erase an account is recognized as an authorized deletion request.
2. Portuguese request for permanent account/data deletion is recognized.
3. Japanese request containing `完全な削除` is recognized.
4. Marketing opt-out explicitly saying not to delete the account is not authorized as deletion.
5. Access/copy-of-data request is not authorized as deletion.
6. A `NOT_FOUND` account profile is classified as an absent-state observation, not a remaining-record violation.
7. Finding steps precede remediation and verification; steps are consecutively numbered and sorted by the challenge's operation ordering.
8. Output validation detects duplicate/missing case IDs.

These are unit checks, not challenge-score estimates.

## Failures observed and improvements made

- Initial evidence classification treated absence observations and non-deletion text too coarsely. Classification, authorization patterns, and the checker were revised; tests were added and run.
- The public sample and evaluation split are disjoint, so public-sample scoring is not meaningful for the full output. The checker now reports the lack of overlap rather than fabricating accuracy.
- The evidence corpus includes screenshots, heterogeneous logs and nested records. The current implementation parses structured JSON, SQL and key/value text plus PDF text via `pdftotext`; image/OCR coverage is not implemented and must not be assumed.
- The full 518-case answer quality remains unverified; parsing and semantic coverage need further independent validation before submission.

## Integrity boundary

No organizer-only truth, hidden answer set, or generator internals were used for prediction or scoring. The report does not claim hidden-set accuracy.

## Final code audit and reproducibility check

The final redundancy audit found and removed an unreachable duplicate correlated-trace branch in `identity_match`, a duplicate deletion-request regex, and a second unused top-level `run()` implementation. The CLI continues to use `DeletionAuditAgent.run()`. These changes are non-semantic; to confirm that, the CSV output from two post-audit full runs matched each other and the saved pre-audit run byte-for-byte, with SHA-256 `eb5b958e12678b9218343d0cb68f80529cac9748f0006096ffcb5a8ae9508d8b`. Each run emitted the same 518 rows. The root `output.csv` now matches the deterministic post-audit runs.

The current public-sample comparison is 29/32 deletion statuses (90.625%), 1/32 exact step sequences (3.125%), and 716/1,170 aligned step fields (61.20%). This is development-set performance, not an estimate validated against the disjoint 518-case hidden-label set.

The latest unit-test run executed 35 tests and reported 33 failures. Thirty-one are per-case public-output disagreements; two additional assertions about `case_03` and `case_26` fail. These are prediction/oracle disagreements in the current suite, not Python exceptions or packaging failures. Therefore this audit does not certify predictive correctness or competition readiness; resolve these disagreements before describing the prediction tests as passing.
