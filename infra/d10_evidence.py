"""Assemble the D10 release bundle from the artifacts D10 produces.

The bundle is the submission-side counterpart to the run evidence: it freezes
the release archive and its manifest, the CycloneDX SBOM, the model card, the
clean-dir rehearsal, the resource-release probe, and a sweep of the tracked
repository for key material and the other things D10 says to delete.

Two honest boundaries are recorded rather than papered over:

* the resource probe can only say the addresses stopped answering; the billing
  center is an operator input and is stored as such, even when absent;
* the sweep can only exonerate what is in the repository, so it says so.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Sequence

from infra.evidence import (
    scan_sensitive_markers,
    seal_directory,
    sha256_file,
    write_json,
)


FORBIDDEN_PATH_PATTERNS = {
    "secrets-directory": re.compile(r"(^|/)secrets/"),
    "secure-directory": re.compile(r"(^|/)secure/"),
    "certificate-store": re.compile(r"(^|/)certs/"),
    "private-key-extension": re.compile(r"\.(key|p12|pfx|jks|csr)$"),
    "model-share": re.compile(r"(^|/)model_share.*\.bin$|\.share$"),
}
# A public certificate inside sealed evidence is allowed on purpose; only key
# material and the private stores above are forbidden.
EVIDENCE_CERTIFICATE = re.compile(r"^docs/evidence/.*\.pem$")
MAX_SCAN_BYTES = 8 * 1024 * 1024


class D10EvidenceError(RuntimeError):
    """The D10 bundle could not be assembled."""


def _tracked_files(root: Path) -> list[str]:
    try:
        completed = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-z"],
            capture_output=True,
            check=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise D10EvidenceError("the repository sweep needs a readable Git index") from exc
    return [raw.decode("utf-8") for raw in completed.stdout.split(b"\0") if raw]


def sweep_repository(root: Path) -> dict[str, Any]:
    """Report forbidden paths and sensitive markers in the tracked tree."""
    root = Path(root)
    forbidden_paths: list[dict[str, str]] = []
    data_markers: list[dict[str, str]] = []
    reviewed_source_markers: list[dict[str, str]] = []
    unreviewed_source_markers: list[dict[str, str]] = []
    checked = 0
    for relative in _tracked_files(root):
        for label, pattern in FORBIDDEN_PATH_PATTERNS.items():
            if pattern.search(relative) and not EVIDENCE_CERTIFICATE.match(relative):
                forbidden_paths.append({"path": relative, "rule": label})
        path = root / relative
        try:
            if not path.is_file() or path.stat().st_size > MAX_SCAN_BYTES:
                continue
            text = path.read_bytes().decode("utf-8", "ignore")
        except OSError:
            continue
        checked += 1
        unreviewed, reviewed = scan_sensitive_markers(text, path=relative)
        for label in unreviewed:
            record = {"path": relative, "marker": label}
            if relative.endswith(".py"):
                unreviewed_source_markers.append(record)
            else:
                data_markers.append(record)
        for label in reviewed:
            reviewed_source_markers.append(
                {
                    "path": relative,
                    "marker": label,
                    "reason": "listed in infra.evidence.SOURCE_MARKER_REVIEW",
                }
            )
    found = bool(forbidden_paths or data_markers or unreviewed_source_markers)
    return {
        "scope": "git-tracked files in the repository",
        "files_checked": checked,
        "forbidden_paths": forbidden_paths,
        "sensitive_markers": data_markers,
        "reviewed_source_markers": reviewed_source_markers,
        "unreviewed_source_markers": unreviewed_source_markers,
        "verdict": "found" if found else "clean",
        "boundary": (
            "This sweep can only exonerate content the repository tracks. It "
            "cannot see production keys, model shares or session state that live "
            "on an instance, so those are covered by the instance-cleanup record. "
            "Pattern hits in source files are listed separately: a dict key or a "
            "scanner self-test is not key material, and each reviewed one is "
            "named with its reason."
        ),
    }


def evidence_hashes(root: Path) -> list[dict[str, Any]]:
    """Digest every sealed bundle under ``docs/evidence``."""
    records: list[dict[str, Any]] = []
    evidence_root = Path(root) / "docs" / "evidence"
    if not evidence_root.is_dir():
        return records
    for bundle in sorted(path for path in evidence_root.iterdir() if path.is_dir()):
        index = bundle / "evidence-index.json"
        if not index.is_file():
            continue
        records.append(
            {
                "bundle": bundle.name,
                "index_sha256": sha256_file(index),
                "seal": (bundle / "evidence.sha256").read_text(encoding="ascii").split()[0]
                if (bundle / "evidence.sha256").is_file()
                else None,
                "file_count": json.loads(index.read_text(encoding="utf-8"))["file_count"],
            }
        )
    return records


def _copy(source: Path, destination: Path) -> None:
    destination.write_bytes(Path(source).read_bytes())


def run(
    *,
    root: Path,
    output_directory: Path,
    run_id: str,
    archive: Path,
    release_manifest: Path,
    release_check: Path,
    sbom: Path,
    rehearsal: Path,
    rehearsal_log: Path,
    model_card: Path,
    conclusion_map: Path,
    acceptance: Path | None = None,
    billing: Path | None = None,
) -> dict[str, Any]:
    root = Path(root).resolve()
    output = Path(output_directory)
    output.mkdir(parents=True, exist_ok=True)

    manifest = json.loads(Path(release_manifest).read_text(encoding="utf-8"))
    release_record = {
        "run_id": run_id,
        "archive": {
            "name": Path(archive).name,
            "sha256": sha256_file(archive),
            "bytes": Path(archive).stat().st_size,
        },
        "manifest": {
            "file_count": manifest["file_count"],
            "tracked_only": manifest.get("tracked_only", False),
            "release_version": manifest["release_version"],
            "sha256": sha256_file(release_manifest),
        },
    }
    write_json(output / "release.json", release_record)
    write_json(output / "release-check.json", json.loads(Path(release_check).read_text("utf-8")))
    write_json(output / "sbom.json", json.loads(Path(sbom).read_text("utf-8")))
    write_json(output / "rehearsal.json", json.loads(Path(rehearsal).read_text("utf-8")))
    _copy(rehearsal_log, output / "rehearsal.log")
    _copy(model_card, output / "model-card-gpt2.md")
    _copy(conclusion_map, output / "conclusion-map.md")
    if acceptance is not None and Path(acceptance).is_file():
        _copy(acceptance, output / "d10-release-acceptance.md")
    write_json(
        output / "evidence-hashes.json",
        {"bundles": evidence_hashes(root)},
    )
    sweep = sweep_repository(root)
    write_json(output / "secrets-sweep.json", sweep)

    check = json.loads(Path(release_check).read_text("utf-8"))
    if billing is not None and Path(billing).is_file():
        operator = json.loads(Path(billing).read_text("utf-8"))
        billing_status = "recorded"
    else:
        operator = None
        billing_status = "awaiting-operator"
    resource = {
        "run_id": run_id,
        "probe_verdict": check.get("verdict"),
        "instances_still_ours": check.get("instances_still_ours"),
        "instances_unverified": check.get("instances_unverified"),
        "probe_boundary": check.get("note"),
        "billing_status": billing_status,
        "operator_confirmation": operator,
        "boundary": (
            "Aliyun billing is not visible from this repository. The console "
            "confirmation is an operator input; until it is recorded the D10 "
            "resource gate is not signed off."
        ),
    }
    write_json(output / "resource-release.json", resource)

    summary = {
        "run_id": run_id,
        "release_version": manifest["release_version"],
        "archive_sha256": release_record["archive"]["sha256"],
        "file_count": manifest["file_count"],
        "probe_verdict": check.get("verdict"),
        "billing_status": billing_status,
        "secrets_sweep": sweep["verdict"],
        "rehearsal_verdict": json.loads(Path(rehearsal).read_text("utf-8"))["verdict"],
    }
    write_json(output / "d10-summary.json", summary)
    (output / "README.md").write_text(
        "\n".join(
            [
                "# D10 release bundle",
                "",
                f"- run: `{run_id}`",
                f"- release: `{manifest['release_version']}`",
                f"- archive sha256: `{summary['archive_sha256']}`",
                f"- files in archive: {summary['file_count']}",
                f"- resource probe: {summary['probe_verdict']}",
                f"- billing record: {summary['billing_status']}",
                f"- repository secrets sweep: {summary['secrets_sweep']}",
                f"- clean-dir rehearsal: {summary['rehearsal_verdict']}",
                "",
                "Produced by `python -m infra.d10_evidence`. The archive hash here",
                "is the release the rest of the bundle describes; the billing",
                "record stays `awaiting-operator` until the console confirmation",
                "is added.",
                "",
            ]
        ),
        encoding="utf-8",
        newline="\n",
    )
    index = seal_directory(output)
    summary["sealed"] = {"file_count": index["file_count"]}
    return summary


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="A1-22 D10 evidence bundle")
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--release-manifest", type=Path, required=True)
    parser.add_argument("--release-check", type=Path, required=True)
    parser.add_argument("--sbom", type=Path, required=True)
    parser.add_argument("--rehearsal", type=Path, required=True)
    parser.add_argument("--rehearsal-log", type=Path, required=True)
    parser.add_argument("--model-card", type=Path, required=True)
    parser.add_argument("--conclusion-map", type=Path, required=True)
    parser.add_argument("--acceptance", type=Path, default=None)
    parser.add_argument("--billing", type=Path, default=None)
    args = parser.parse_args(argv)
    try:
        summary = run(
            root=args.root,
            output_directory=args.out,
            run_id=args.run_id,
            archive=args.archive,
            release_manifest=args.release_manifest,
            release_check=args.release_check,
            sbom=args.sbom,
            rehearsal=args.rehearsal,
            rehearsal_log=args.rehearsal_log,
            model_card=args.model_card,
            conclusion_map=args.conclusion_map,
            acceptance=args.acceptance,
            billing=args.billing,
        )
    except (OSError, ValueError, KeyError, RuntimeError) as exc:
        print(f"the D10 bundle could not be assembled: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(summary, ensure_ascii=True, sort_keys=True, indent=2))
    return 0


__all__ = [
    "D10EvidenceError",
    "EVIDENCE_CERTIFICATE",
    "FORBIDDEN_PATH_PATTERNS",
    "evidence_hashes",
    "main",
    "run",
    "sweep_repository",
]


if __name__ == "__main__":
    raise SystemExit(main())
