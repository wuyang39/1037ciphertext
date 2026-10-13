"""Search one instance for the D6 session state that close was to remove.

The D6 gate does not accept "the node said it wiped the session" on its own.
After the client closes, each instance is searched for the very share prefixes
the run published as probes: the shares the client sent, and the per-step
shares the node spilled. A probe is a slice of a uniformly random additive
share, so publishing it costs nothing and searching for it turns the cleanup
into a measurement on the host rather than a claim inside the enclave.

Three surfaces are searched on every instance, which is what the phase asks
for:

* the filesystem under the session root, the instance's temp directories and
  the workspace ``out/`` tree, plus the instance's own log files;
* the kernel's process table, through ``/proc/<pid>/cmdline`` and
  ``environ``, so a leak into an argument or an environment variable shows up;
* the system journal, read from ``journalctl`` when the instance keeps one.

The scan also asserts the session directories are gone and the session root is
empty, so a run that forgot to clean up fails even if the bytes it left behind
happen not to contain a probe.

Usage::

    python -m infra.hygiene_scan \
        --probes-file /tmp/<run-id>-probes.json \
        --root /dev/shm/a122-d6 --root /tmp --root <workspace>/out \
        --expect-empty /dev/shm/a122-d6/<run-id> \
        --expect-absent /dev/shm/a122-d6/<run-id>/P0 \
        --output /tmp/<run-id>-P0-hygiene.json
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Sequence

from infra.evidence import write_json


# A share bundle for the tiny decoder is a few kilobytes; the bound only stops
# the scan from reading an unrelated gigabyte file into memory.
MAX_FILE_BYTES = 64 * 1024 * 1024
PROC_ROOT = Path("/proc")
JOURNAL_LIMIT_BYTES = 16 * 1024 * 1024


def _files_under(root: Path) -> Iterable[Path]:
    """Yield regular files below ``root`` without following symlinks."""
    if root.is_file():
        yield root
        return
    if not root.is_dir():
        return
    for directory, _subdirectories, names in os.walk(root, followlinks=False):
        for name in names:
            path = Path(directory) / name
            if path.is_symlink():
                continue
            yield path


def scan_files(
    needles: Mapping[str, bytes],
    roots: Sequence[Path],
    *,
    skip: Sequence[Path] = (),
    max_file_bytes: int = MAX_FILE_BYTES,
) -> tuple[list[dict[str, Any]], list[str]]:
    """Return one hit per file that carries a probe, plus the roots that exist."""
    skipped = {Path(path).resolve() for path in skip}
    present: list[str] = []
    hits: list[dict[str, Any]] = []
    for root in roots:
        root = Path(root)
        if not root.exists():
            continue
        present.append(str(root))
        for path in _files_under(root):
            try:
                if path.resolve() in skipped:
                    continue
                if path.stat().st_size > max_file_bytes:
                    continue
                blob = path.read_bytes()
            except OSError:
                continue
            for name, needle in needles.items():
                if needle and needle in blob:
                    hits.append(
                        {
                            "kind": "file",
                            "path": str(path),
                            "probe": name,
                            "bytes": len(blob),
                        }
                    )
                    break
    return hits, present


def scan_processes(
    needles: Mapping[str, bytes],
    *,
    proc: Path = PROC_ROOT,
) -> list[dict[str, Any]]:
    """Search every process's command line and environment for a probe."""
    hits: list[dict[str, Any]] = []
    try:
        entries = sorted(Path(proc).iterdir(), key=lambda item: item.name)
    except OSError:
        return hits
    for entry in entries:
        if not entry.name.isdigit():
            continue
        for name in ("cmdline", "environ"):
            try:
                blob = (entry / name).read_bytes()
            except OSError:
                continue
            for label, needle in needles.items():
                if needle and needle in blob:
                    hits.append(
                        {
                            "kind": "process",
                            "path": str(entry / name),
                            "probe": label,
                        }
                    )
                    break
    return hits


def scan_journal(
    needles: Mapping[str, bytes],
    *,
    since: str | None = None,
    runner: Callable[..., Any] | None = None,
) -> dict[str, Any]:
    """Search ``journalctl`` output for a probe, when the host keeps a journal."""
    command = ["journalctl", "--no-pager", "--quiet", "--output=short"]
    if since:
        command.extend(["--since", since])
    runner = runner or subprocess.run
    try:
        completed = runner(
            command,
            capture_output=True,
            timeout=300,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return {"available": False, "reason": f"{type(exc).__name__}: {exc}"}
    if completed.returncode != 0:
        reason = (completed.stderr or b"").decode("utf-8", "replace").strip()
        return {
            "available": False,
            "reason": f"journalctl exited {completed.returncode}: {reason[:200]}",
        }
    blob = (completed.stdout or b"")[-JOURNAL_LIMIT_BYTES:]
    hits = [
        {"kind": "journal", "path": "journalctl", "probe": label}
        for label, needle in needles.items()
        if needle and needle in blob
    ]
    return {"available": True, "bytes_searched": len(blob), "hits": hits}


def scan(
    *,
    probes: Sequence[str],
    roots: Sequence[Path | str],
    skip: Sequence[Path | str] = (),
    expect_absent: Sequence[Path | str] = (),
    expect_empty: Sequence[Path | str] = (),
    journal_since: str | None = None,
    with_journal: bool = True,
    with_processes: bool = True,
    proc: Path = PROC_ROOT,
    journal_runner: Callable[..., Any] | None = None,
    max_file_bytes: int = MAX_FILE_BYTES,
) -> dict[str, Any]:
    """Run every surface and return one verdict a driver can seal."""
    needles = {
        f"probe[{index}]": probe.encode("utf-8")
        for index, probe in enumerate(probes)
        if probe
    }
    file_hits, present_roots = scan_files(
        needles,
        [Path(root) for root in roots],
        skip=[Path(path) for path in skip],
        max_file_bytes=max_file_bytes,
    )
    process_hits = scan_processes(needles, proc=proc) if with_processes else []
    journal = (
        scan_journal(needles, since=journal_since, runner=journal_runner)
        if with_journal
        else {"available": False, "reason": "disabled"}
    )
    journal_hits = list(journal.get("hits") or [])
    still_present = [str(path) for path in expect_absent if Path(path).exists()]
    not_empty: list[dict[str, Any]] = []
    for directory in expect_empty:
        path = Path(directory)
        if not path.is_dir():
            continue
        entries = sorted(child.name for child in path.iterdir())
        if entries:
            not_empty.append({"path": str(path), "entries": entries[:32]})
    findings = (
        file_hits
        + process_hits
        + journal_hits
        + [{"kind": "still-present", "path": path} for path in still_present]
        + [{"kind": "not-empty", **record} for record in not_empty]
    )
    return {
        "probes": list(probes),
        "roots": [str(root) for root in roots],
        "skipped": [str(path) for path in skip],
        "roots_that_exist": present_roots,
        "expect_absent": [str(path) for path in expect_absent],
        "expect_empty": [str(path) for path in expect_empty],
        "journal": journal,
        "file_hits": file_hits,
        "process_hits": process_hits,
        "journal_hits": journal_hits,
        "still_present": still_present,
        "not_empty": not_empty,
        "findings": findings,
        "verdict": "clean" if not findings else "session-state-found",
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="A1-22 D6 hygiene scan")
    parser.add_argument("--probes-file", type=Path, required=True)
    parser.add_argument("--root", type=Path, action="append", required=True)
    parser.add_argument("--skip", type=Path, action="append", default=[])
    parser.add_argument("--expect-absent", type=Path, action="append", default=[])
    parser.add_argument("--expect-empty", type=Path, action="append", default=[])
    parser.add_argument("--journal-since", default=None)
    parser.add_argument("--no-journal", action="store_true")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        document = json.loads(args.probes_file.read_text(encoding="utf-8"))
        probes = [str(value) for value in document["probes"]]
    except (OSError, json.JSONDecodeError, KeyError, TypeError) as exc:
        print(f"the probe file could not be read: {exc}", flush=True)
        return 2
    # The report itself and the file that named the probes would otherwise be
    # hits on their own contents, which says nothing about the session.
    skip = list(args.skip) + [args.probes_file, args.output]
    report = scan(
        probes=probes,
        roots=args.root,
        skip=skip,
        expect_absent=args.expect_absent,
        expect_empty=args.expect_empty,
        journal_since=args.journal_since,
        with_journal=not args.no_journal,
    )
    write_json(args.output, report)
    print(
        json.dumps(
            {
                "verdict": report["verdict"],
                "findings": len(report["findings"]),
                "roots_that_exist": report["roots_that_exist"],
            },
            sort_keys=True,
        )
    )
    return 0 if report["verdict"] == "clean" else 1


__all__ = [
    "JOURNAL_LIMIT_BYTES",
    "MAX_FILE_BYTES",
    "PROC_ROOT",
    "scan",
    "scan_files",
    "scan_journal",
    "scan_processes",
]


if __name__ == "__main__":
    raise SystemExit(main())
