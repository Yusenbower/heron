"""Command-line interface: ``python -m heron <folder>``."""

import os
import sys

from heron.models import Verdict
from heron.parser import parse_eml
from heron.scorer import triage


def check_mail(folder):
    """Score every .eml file in folder; return (file name, verdict, score) tuples."""
    verdicts = []
    for fn in os.listdir(folder):
        if not fn.endswith(".eml"):
            continue
        with open(os.path.join(folder, fn), encoding="utf-8", errors="ignore") as f:
            raw = f.read()
        result = triage(parse_eml(raw, fn))
        verdicts.append((fn, result.verdict, result.score))
    return verdicts


def report(verdicts):
    """Print the verdicts and save them to results.txt."""
    print(f"checked {len(verdicts)} mails")
    for fn, verdict, score in verdicts:
        print(f"  {fn} -> {verdict} (score {score})")
    with open("results.txt", "w", encoding="utf-8") as out:
        out.write(str(verdicts))
    flagged = [fn for fn, verdict, _ in verdicts if verdict == Verdict.PHISHING]
    print("flagged:", flagged)


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