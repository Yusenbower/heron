"""Command-line interface: ``python -m heron <folder>``."""

import os
import sys

from heron.models import TriageResult
from heron.parser import parse_eml
from heron.scorer import triage


def check_mail(folder: str) -> list[TriageResult]:
    """Triage every .eml file in folder, in name order."""
    results = []
    for fn in sorted(os.listdir(folder)):
        if not fn.endswith(".eml"):
            continue
        with open(os.path.join(folder, fn), encoding="utf-8", errors="ignore") as f:
            raw = f.read()
        results.append(triage(parse_eml(raw, fn)))
    return results


def report(results: list[TriageResult]) -> None:
    """A line for each email, with its verdict and its score."""
    for r in results:
        print(f"{r.email_id:<28} {r.verdict:<10} score={r.score}")


def main(argv: list[str] | None = None) -> int:
    """Run the triage on the folder given on the command line; return the exit code."""
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        print("usage: python -m heron <folder-with-eml-files>", file=sys.stderr)
        return 2
    try:
        report(check_mail(args[0]))
    except FileNotFoundError:
        print("error: no such folder:", args[0], file=sys.stderr)
        return 2
    return 0