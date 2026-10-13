"""D10: record what is observable from here about the paid instances.

The acceptance instances are released from the operator's console, and no
credential in this repository can do it — Aliyun has no open API here and the
project deliberately keeps no access key. What *can* be checked, and what this
module records, is the other side of the same statement: whether each instance's
public address still answers at all, and, when it does answer, whether it still
accepts our key.

The outcomes are kept apart on purpose, because they mean different things:

* ``no_listener`` — the address refuses or times out, which is what a released
  instance looks like once its address stops being routed;
* ``unresolved`` — the name does not resolve; recorded, not folded into the
  previous case;
* ``port_open_silent`` — something accepts TCP but offers no SSH banner;
* ``ssh_banner_other`` — an SSH listener answers, but our key is refused. That
  is a live machine, and it is not ours: the address was handed to another
  tenant after release;
* ``reachable_with_our_key`` — the host still accepts our key. The instance is
  still ours and still running. Only this outcome fails D10.

A banner-only answer with no key to test against is recorded as
``ssh_unverified`` rather than assumed to be a recycled address, because from
the outside the two are indistinguishable. That keeps the summary verdict at
``unverified`` instead of ``released`` when the probe could not tell.

The probe never claims a billing state it cannot see; the console confirmation
stays an operator input in the billing record.
"""

from __future__ import annotations

import argparse
import json
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Callable, Sequence

from infra.evidence import write_json


SSH_PORT = 22
BANNER_PREFIX = "SSH-"
DEFAULT_TIMEOUT = 8.0
UNVERIFIED_VERDICTS = {"ssh_unverified", "port_open_silent"}
STILL_OURS_VERDICT = "reachable_with_our_key"


class ReleaseCheckError(ValueError):
    """A release check could not be run."""


def probe(host: str, *, port: int = SSH_PORT, timeout: float = DEFAULT_TIMEOUT) -> dict[str, Any]:
    """One TCP probe: connect, read the banner if one is offered."""
    started = time.monotonic()
    outcome: dict[str, Any] = {
        "host": host,
        "port": int(port),
        "timeout_seconds": float(timeout),
    }
    try:
        with socket.create_connection((host, int(port)), timeout=timeout) as connection:
            connection.settimeout(timeout)
            try:
                banner = connection.recv(256)
            except (socket.timeout, TimeoutError, OSError):
                banner = b""
        outcome["connected"] = True
        text = banner.decode("ascii", errors="replace").strip()
        outcome["banner"] = text if text.startswith(BANNER_PREFIX) else None
        outcome["verdict"] = "ssh_unverified" if outcome["banner"] else "port_open_silent"
    except (socket.timeout, TimeoutError):
        outcome["connected"] = False
        outcome["verdict"] = "no_listener"
        outcome["reason"] = "connect timed out"
    except ConnectionRefusedError:
        outcome["connected"] = False
        outcome["verdict"] = "no_listener"
        outcome["reason"] = "connection refused"
    except OSError as exc:
        outcome["connected"] = False
        outcome["verdict"] = "unresolved" if exc.errno in (-2, -3) else "no_listener"
        outcome["reason"] = f"{type(exc).__name__}: {exc}"
    outcome["elapsed_ms"] = round((time.monotonic() - started) * 1000, 3)
    return outcome


def identify(
    host: str,
    *,
    user: str,
    identity: str,
    port: int = SSH_PORT,
    timeout: float = DEFAULT_TIMEOUT,
    runner: Callable[..., Any] | None = None,
) -> dict[str, Any]:
    """Try one non-interactive public-key login and report whether it worked.

    The command is pinned to public-key auth with ``BatchMode`` so it can never
    fall back to a password prompt and hang on a pipe. The identity path itself
    is not returned: only whether one was used, so a sealed record stays free of
    local paths.
    """
    command = [
        "ssh",
        "-i", identity,
        "-p", str(int(port)),
        "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "PreferredAuthentications=publickey",
        "-o", "PasswordAuthentication=no",
        "-o", "IdentitiesOnly=yes",
        "-o", f"ConnectTimeout={max(1, int(round(timeout)))}",
        f"{user}@{host}",
        "exit 0",
    ]
    runner = runner or subprocess.run
    try:
        completed = runner(
            command, capture_output=True, timeout=timeout + 5, check=False
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return {
            "identity_used": True,
            "authenticated": False,
            "reason": f"{type(exc).__name__}: {exc}",
        }
    stderr = (completed.stderr or b"").decode("utf-8", "replace").strip()
    return {
        "identity_used": True,
        "authenticated": completed.returncode == 0,
        "returncode": int(completed.returncode),
        "stderr": stderr[:200] or None,
    }


def _combine(record: dict[str, Any], entry: dict[str, Any], *, timeout: float) -> dict[str, Any]:
    """Fold the SSH identification into one target's verdict."""
    identity = entry.get("identity")
    user = entry.get("user")
    if record["verdict"] == "ssh_unverified" and identity and user:
        record.update(
            identify(record["host"], user=str(user), identity=str(identity), timeout=timeout)
        )
        record["verdict"] = (
            STILL_OURS_VERDICT if record.get("authenticated") else "ssh_banner_other"
        )
    return record


def run(
    targets: Sequence[dict[str, Any]],
    *,
    timeout: float = DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """Probe every target and summarise whether any instance is still ours."""
    records = [
        _combine({**entry, **probe(str(entry["host"]), timeout=timeout)}, entry, timeout=timeout)
        for entry in targets
    ]
    verdicts = [record["verdict"] for record in records]
    still_running = [
        record for record in records if record["verdict"] == STILL_OURS_VERDICT
    ]
    unverified = [
        record for record in records if record["verdict"] in UNVERIFIED_VERDICTS
    ]
    counts = {verdict: verdicts.count(verdict) for verdict in sorted(set(verdicts))}
    if still_running:
        verdict = "still_running"
    elif unverified:
        verdict = "unverified"
    else:
        verdict = "released"
    return {
        "targets": records,
        "verdict_counts": counts,
        "instances_still_ours": len(still_running),
        "instances_unverified": len(unverified),
        "verdict": verdict,
        "note": (
            "A silent address is recorded as released. An SSH banner whose key "
            "cannot be tested is recorded as unverified; a banner that refuses "
            "our key is another tenant behind a recycled address."
        ),
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="A1-22 D10 release check")
    parser.add_argument("--targets", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    args = parser.parse_args(argv)
    try:
        targets = json.loads(args.targets.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"the target list could not be read: {exc}", file=sys.stderr)
        return 2
    if not isinstance(targets, list) or not targets:
        print("the target list must be a non-empty array", file=sys.stderr)
        return 2
    result = run(targets, timeout=args.timeout)
    write_json(args.out, result)
    print(json.dumps(result, ensure_ascii=True, sort_keys=True, indent=2))
    return 0 if result["verdict"] == "released" else 1


__all__ = [
    "BANNER_PREFIX",
    "DEFAULT_TIMEOUT",
    "ReleaseCheckError",
    "SSH_PORT",
    "identify",
    "main",
    "probe",
    "run",
]


if __name__ == "__main__":
    raise SystemExit(main())
