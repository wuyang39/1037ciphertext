"""Scan the production path for plaintext reveals.

The D5 gate requires that no production module reveals a share to compute a
non-linear operator. The local reference keeps an explicit, opt-in simulation
provider so the fixed-point adapters can be checked against a float model;
that module is allowlisted here and every other hit is a finding.

Usage::

    python -m infra.reveal_scan --root . --output artifacts/evidence/reveal-scan.json
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Iterable, Sequence

from infra.evidence import write_json


PRODUCTION_ROOTS: tuple[str, ...] = (
    "mpc",
    "tee",
    "kas",
    "client",
    "crypto",
    "contracts",
    "deploy",
    "infra",
)

ALLOWLIST: dict[str, str] = {
    "mpc/secure_ops/transformer.py": (
        "local-only fixed-point reference; the enclave node runs d5_program instead"
    ),
    "mpc/secure_ops/provider.py": (
        "opt-in SimulationRevealProvider that refuses unless the context enables it"
    ),
    "mpc/secure_ops/rss.py": (
        "the reveal_allowed switch itself, defaulting to off in local_three_node"
    ),
    "mpc/secure_ops/__init__.py": "re-exports the opt-in simulation provider",
    "infra/reveal_scan.py": "this scanner's own pattern table",
    "infra/collect_evidence.py": "the forbidden-pattern table used for release scans",
    "infra/local_three_node.py": (
        "negative assertion: reveal_allowed=False must refuse the operation"
    ),
    "infra/security_negative.py": (
        "negative assertion: reveal_allowed=False must refuse the operation"
    ),
}
"""Files whose hits are policy text or refused-operation tests, never a reveal."""

MUST_BE_CLEAN: tuple[str, ...] = (
    "mpc/spu_backend/d5_program.py",
    "mpc/spu_backend/program_runtime.py",
    "mpc/spu_backend/spu_link.py",
    "tee/enclave/d5_node.py",
    "tee/enclave/node_common.py",
    "tee/enclave/spu_node.py",
    "infra/d5_three_hosts.py",
)
"""The modules the enclave node actually evaluates; none may reveal."""

PATTERNS: tuple[str, ...] = (
    "reveal(",
    "reveal_allowed",
    "simulated_reveal",
    "SimulationRevealProvider",
)


def _sources(root: Path) -> Iterable[Path]:
    for relative in PRODUCTION_ROOTS:
        base = root / relative
        if not base.is_dir():
            continue
        for path in sorted(base.rglob("*.py")):
            if "__pycache__" in path.parts:
                continue
            yield path


def scan(root: Path) -> dict[str, Any]:
    root = Path(root)
    findings: list[dict[str, Any]] = []
    allowlisted: list[dict[str, Any]] = []
    for path in _sources(root):
        relative = path.relative_to(root).as_posix()
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeDecodeError):  # pragma: no cover - defensive
            continue
        for number, line in enumerate(lines, start=1):
            hit = next((pattern for pattern in PATTERNS if pattern in line), None)
            if hit is None:
                continue
            record = {"file": relative, "line": number, "pattern": hit}
            if relative in ALLOWLIST:
                allowlisted.append(record)
            else:
                findings.append(record)
    missing = [
        name
        for name in MUST_BE_CLEAN
        if not (root / name).is_file()
    ]
    return {
        "scanned_roots": list(PRODUCTION_ROOTS),
        "patterns": list(PATTERNS),
        "allowlisted": [
            {**record, "reason": ALLOWLIST[record["file"]]} for record in allowlisted
        ],
        "must_be_clean": list(MUST_BE_CLEAN),
        "missing_modules": missing,
        "findings": findings,
        "verdict": "clean" if not findings and not missing else "reveal-in-production",
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="A1-22 reveal scan")
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--output", type=Path, default=None)
    args = parser.parse_args(argv)
    report = scan(args.root)
    if args.output is not None:
        write_json(args.output, report)
    print(json.dumps({k: report[k] for k in ("verdict", "findings")}, indent=2))
    return 0 if report["verdict"] == "clean" else 1


__all__ = [
    "ALLOWLIST",
    "MUST_BE_CLEAN",
    "PATTERNS",
    "PRODUCTION_ROOTS",
    "scan",
]


if __name__ == "__main__":
    raise SystemExit(main())
