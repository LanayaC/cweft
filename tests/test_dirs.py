"""
--logs-dir and --results-dir: a test run can write its logs and grade its
results in folders of its own, leaving logs/ and results/ untouched.
"""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import evaluate  # noqa: E402
import generate  # noqa: E402
import patcheval_eval  # noqa: E402


def _keep_globals(monkeypatch):
    """Let monkeypatch restore whatever the flags reassign."""
    monkeypatch.setattr(generate, "LOGS_DIR", generate.LOGS_DIR)
    monkeypatch.setattr(generate, "PATCHEVAL_LOGS_DIR", generate.PATCHEVAL_LOGS_DIR)
    monkeypatch.setattr(evaluate, "LOGS_DIR", evaluate.LOGS_DIR)
    monkeypatch.setattr(evaluate, "RESULTS_CSV", evaluate.RESULTS_CSV)
    monkeypatch.setattr(patcheval_eval, "PATCHEVAL_LOGS_DIR", patcheval_eval.PATCHEVAL_LOGS_DIR)
    monkeypatch.setattr(patcheval_eval, "RESULTS_CSV", patcheval_eval.RESULTS_CSV)


def test_logs_dir_moves_both_datasets(tmp_path, monkeypatch):
    _keep_globals(monkeypatch)
    generate.set_logs_dir(tmp_path)
    assert generate.log_path_for("VUL4J-77", "L1", "m").parent == tmp_path.resolve()
    assert generate.log_path_for("CVE-2022-1992", "L1", "m").parent == \
        tmp_path.resolve() / "patcheval"


def test_generate_dry_run_reports_the_chosen_folder(tmp_path, monkeypatch, capsys):
    _keep_globals(monkeypatch)
    monkeypatch.setattr(sys, "argv", [
        "generate.py", "--models", "claude", "--vulns", "VUL4J-77", "--levels", "L1",
        "--logs-dir", str(tmp_path), "--dry-run"])
    generate.main()
    out = capsys.readouterr().out
    assert str(tmp_path.resolve()) in out
    assert "Dry run" in out
    assert list(tmp_path.glob("*.json")) == []


def test_evaluate_reads_and_writes_only_the_chosen_folders(tmp_path, monkeypatch, capsys):
    _keep_globals(monkeypatch)
    logs, results = tmp_path / "logs", tmp_path / "results"
    monkeypatch.setattr(sys, "argv", [
        "evaluate.py", "--dataset", "patcheval",
        "--logs-dir", str(logs), "--results-dir", str(results)])
    evaluate.main()
    assert patcheval_eval.PATCHEVAL_LOGS_DIR == logs.resolve() / "patcheval"
    assert patcheval_eval.RESULTS_CSV == results.resolve() / "results_patcheval.csv"
    assert evaluate.RESULTS_CSV == results.resolve() / "results.csv"
    assert "No PatchEval patch logs" in capsys.readouterr().out
