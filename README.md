# heron

Phishing email triage: reads `.eml` files, extracts indicators, and assigns a
verdict (`benign`, `suspicious`, or `phishing`) with a score.

## Usage

The code is a package under `src/heron/`. From the repository root:

```bash
PYTHONPATH=src python3 -m heron data/samples
```

You can also pass a single `.eml` file, request machine-readable JSON output,
or list all available options:

```bash
PYTHONPATH=src python3 -m heron data/samples/prize-scam.eml
PYTHONPATH=src python3 -m heron data/samples/prize-scam.eml --json
PYTHONPATH=src python3 -m heron --help
```

## Status

Modular code: a package under `src/heron/` with one module per responsibility
(`models`, `parser`, `features`, `scorer`, `cli`). Not packaged yet: there is
no `pyproject.toml` and nothing to install.