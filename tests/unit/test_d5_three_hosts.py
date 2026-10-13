from __future__ import annotations

import json
from pathlib import Path

import pytest

from infra.d5_three_hosts import (
    _capture_reason,
    _finalise,
    _interlock,
    _readme,
)
from infra.evidence import load_exclusions, verify_directory


ROLES = ("P0", "P1", "P2")


def _bytes(seed: int) -> str:
    return f"{seed:064x}"


def _document() -> dict:
    return {
        "run_id": "d5-unit",
        "phase": "D5",
        "mode": "enclave",
        "commit": "0" * 40,
        "roles": {
            role: {
                "instance_id": f"i-{role}",
                "private_address": f"10.0.0.{index + 1}",
                "public_address": f"192.0.2.{index + 1}",
                "brpc_port": 47100 + index,
                "share_port": 47200 + index,
            }
            for index, role in enumerate(ROLES)
        },
        "enclosure": {
            "measurements": {role: _bytes(index + 1) for index, role in enumerate(ROLES)},
            "manifest_sha256": {role: _bytes(index + 11) for index, role in enumerate(ROLES)},
            "distinct_measurements": 3,
            "enclave_size": "4G",
            "max_threads": 64,
            "stack_size": "2M",
            "template": "spu_node.manifest.template",
            "wrapper": ["gramine-sgx", "/w/d5_node"],
        },
        "captures": {
            role: {
                "path": f"d5-three-{role}.pcap",
                "bytes": 1000 + index,
                "sha256": _bytes(index + 21),
                "reason": "stays on its instance",
            }
            for index, role in enumerate(ROLES)
        },
        "verdicts": "passed",
        "cases": 1,
        "passed": 1,
        "failed": 0,
        "grid_digest": _bytes(31),
        "by_program": {
            "argmax": {"cases": 1, "passed": 1, "failed": 0, "max_abs_error": 0.0, "overflow_count": 0}
        },
        "seed": 20261013,
        "share_bytes": 1234,
        "peer_certificates_match": True,
        "certificate_mismatches": [],
    }


def _trace() -> dict:
    return {
        "inside_enclave": True,
        "attestation_available": True,
        "link_seconds": 1.5,
        "runs": [{"case": "unique", "program": "argmax", "share_bytes": 10}],
    }


def _reveal() -> dict:
    return {
        "run_id": "d5-unit",
        "verdict": "clean",
        "roles": {
            role: {"verdict": "clean", "findings": [], "allowlisted": [{"file": "x.py"}]}
            for role in ROLES
        },
    }


def test_readme_reports_the_numbers_the_run_recorded() -> None:
    document = _document()
    text = _readme(
        run_id="d5-unit", document=document, reveal=_reveal(), trace=_trace()
    )
    assert f"The run is at commit `{'0' * 40}`." in text
    assert document["enclosure"]["measurements"]["P1"] in text
    assert "38" not in text
    assert "| Cases | 1 total, 1 passed, 0 failed |" in text
    assert "share bytes 1234" in text
    assert "`distinct_measurements`: 3." in text
    assert "| P2 | `clean` | 0 | 1 |" in text
    assert document["captures"]["P0"]["sha256"] in text
    assert "| Peer certificates match | `True` |" in text


def test_capture_reason_reads_the_size_back_from_the_run() -> None:
    reason = _capture_reason(
        role="P1", value={"bytes": 51409592, "path": "/tmp/run-P1.pcap"}
    )
    assert "51409592 bytes" in reason
    assert "/tmp/run-P1.pcap" in reason
    assert "100 MB" not in reason


def _write_statuses(out_dir: Path, *, peer_digest: dict[str, dict[str, str]]) -> None:
    identities = {role: _bytes(40 + index) for index, role in enumerate(ROLES)}
    for role in ROLES:
        peers = {peer: peer_digest.get(role, {}).get(peer, identities[peer]) for peer in ROLES if peer != role}
        (out_dir / f"d5-three-{role.lower()}-node-status.json").write_text(
            json.dumps(
                {
                    "role": role,
                    "identity_sha256": identities[role],
                    "peer_certificates": peers,
                }
            ),
            encoding="utf-8",
            newline="\n",
        )


def test_interlock_accepts_one_identity_per_role(tmp_path: Path) -> None:
    _write_statuses(tmp_path, peer_digest={})
    result = _interlock(tmp_path)
    assert result["peer_certificates_match"] is True
    assert result["certificate_mismatches"] == []
    assert set(result["identity_sha256"]) == set(ROLES)


def test_interlock_reports_a_peer_that_authenticated_someone_else(
    tmp_path: Path,
) -> None:
    _write_statuses(tmp_path, peer_digest={"P0": {"P2": _bytes(99)}})
    result = _interlock(tmp_path)
    assert result["peer_certificates_match"] is False
    assert result["certificate_mismatches"] == ["P0->P2"]


def test_finalise_seals_the_external_captures_and_writes_the_readme(
    tmp_path: Path,
) -> None:
    document = _document()
    (tmp_path / "d5-communication-trace.json").write_text(
        json.dumps(_trace()), encoding="utf-8", newline="\n"
    )
    result = _finalise(
        out_dir=tmp_path,
        run_id="d5-unit",
        document=document,
        captures=document["captures"],
        reveal=_reveal(),
    )

    index = json.loads((tmp_path / "evidence-index.json").read_text(encoding="utf-8"))
    external = [entry for entry in index["files"] if entry.get("external")]
    assert [entry["path"] for entry in external] == [
        f"d5-three-{role}.pcap" for role in ROLES
    ]
    assert (tmp_path / "README.md").is_file()
    readme = (tmp_path / "README.md").read_text(encoding="utf-8")
    assert "# D5 three-instance enclave run (d5-unit)" in readme
    assert "<bundle>.exclusions.json" in readme

    exclusions = load_exclusions(tmp_path)
    assert [entry["sha256"] for entry in exclusions] == [
        document["captures"][role]["sha256"] for role in ROLES
    ]
    # An external artifact that is absent is excused only because it is named.
    verified = verify_directory(tmp_path, exclusions=exclusions)
    assert verified["excluded"] == sorted(entry["path"] for entry in external)
    assert result["index"]["file_count"] == len(index["files"])


def test_finalise_refuses_a_capture_whose_digest_is_not_a_digest(
    tmp_path: Path,
) -> None:
    document = _document()
    (tmp_path / "d5-communication-trace.json").write_text(
        json.dumps(_trace()), encoding="utf-8", newline="\n"
    )
    captures = dict(document["captures"])
    captures["P0"] = {**captures["P0"], "sha256": "not-a-digest"}
    with pytest.raises(Exception):
        _finalise(
            out_dir=tmp_path,
            run_id="d5-unit",
            document=document,
            captures=captures,
            reveal=_reveal(),
        )
