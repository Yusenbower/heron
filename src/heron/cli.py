"""Command-line interface: ``python -m heron <folder>``."""

import argparse
import os
import sys

from heron.models import TriageResult
from heron.parser import parse_eml
from heron.scorer import triage


def build_parser() -> argparse.ArgumentParser:
    """Return the parser of the command-line arguments."""
    parser = argparse.ArgumentParser(prog="heron", description="Triage phishing emails.")
    parser.add_argument("folder", help="a folder of .eml files")
    return parser

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
    args = build_parser().parse_args(argv)
    try:
        report(check_mail(args.folder))
    except FileNotFoundError:
        print("error: no such folder:", args.folder, file=sys.stderr)
        return 2
    return 0