"""Validate generated output and score against the public sample answer key only."""
from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
# Import the solution module by file path to avoid colliding with this script's
# own module name when launched as `python3 code/evaluation/main.py`.
import importlib.util

solution_spec = importlib.util.spec_from_file_location("challenge_solution", ROOT / "code" / "main.py")
if solution_spec is None or solution_spec.loader is None:
    raise RuntimeError("Could not load code/main.py")
solution = importlib.util.module_from_spec(solution_spec)
sys.modules[solution_spec.name] = solution
solution_spec.loader.exec_module(solution)
validate_output_rows = solution.validate_output_rows


def read_csv(path: Path):
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def score_public_sample(output_path: Path, dataset: Path) -> dict[str, float | int]:
    output = {row["case_id"]: row for row in read_csv(output_path)}
    truth_rows = read_csv(dataset / "sample_output.csv")
    common_ids = set(output) & {row["case_id"] for row in truth_rows}
    if not common_ids:
        return {"sample_cases": len(truth_rows), "overlapping_cases": 0, "status_accuracy": 0.0,
                "exact_step_row_accuracy": 0.0, "sequence_accuracy": 0.0,
                "step_field_accuracy": 0.0, "expected_steps": 0, "predicted_steps": 0}
    status_correct = 0
    exact_step_rows = 0
    field_correct = 0
    field_total = 0
    expected_step_total = 0
    predicted_step_total = 0
    exact_sequences = 0
    for truth in truth_rows:
        predicted = output.get(truth["case_id"])
        if not predicted:
            continue
        status_correct += predicted["deletion_status"] == truth["deletion_status"]
        expected_steps = json.loads(truth["steps_json"])
        predicted_steps = json.loads(predicted["steps_json"])
        expected_step_total += len(expected_steps)
        predicted_step_total += len(predicted_steps)
        exact_sequences += expected_steps == predicted_steps
        exact_step_rows += expected_steps == predicted_steps
        for i in range(max(len(expected_steps), len(predicted_steps))):
            expected = expected_steps[i] if i < len(expected_steps) else {}
            actual = predicted_steps[i] if i < len(predicted_steps) else {}
            for key in ("phase", "system_id", "resource_id", "operation", "state", "evidence_id"):
                field_total += 1
                field_correct += expected.get(key) == actual.get(key)
    n = len(truth_rows)
    return {
        "sample_cases": n,
        "status_correct": status_correct,
        "status_accuracy": status_correct / n if n else 0.0,
        "exact_step_rows": exact_step_rows,
        "exact_step_row_accuracy": exact_step_rows / n if n else 0.0,
        "sequence_accuracy": exact_sequences / n if n else 0.0,
        "step_field_correct": field_correct,
        "step_field_total": field_total,
        "step_field_accuracy": field_correct / field_total if field_total else 0.0,
        "expected_steps": expected_step_total,
        "predicted_steps": predicted_step_total,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, default=ROOT / "dataset")
    parser.add_argument("--output", type=Path, default=ROOT / "output.csv")
    args = parser.parse_args(argv)
    requests = read_csv(args.dataset / "deletion_requests.csv")
    rows = read_csv(args.output)
    errors = validate_output_rows(rows, [row["case_id"] for row in requests])
    print(f"Contract validation: {'PASS' if not errors else 'FAIL'}")
    for error in errors: print(f"- {error}")
    if not errors and (args.dataset / "sample_output.csv").is_file():
        print("Public sample metrics (debug only; sample key is participant-facing):")
        for key, value in score_public_sample(args.output, args.dataset).items(): print(f"{key}: {value}")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
