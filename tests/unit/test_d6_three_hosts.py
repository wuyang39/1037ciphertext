"""The D6 driver's own arithmetic: verdicts, probes and the sealed README."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from infra.d4_three_hosts import (
    ENCLAVE_SIGNED_MARKER,
    ROLES,
    ThreeHostError,
    enclave_sign_command,
    prepare_enclave,
    routes,
)
from infra.d6_three_hosts import (
    D6_PORTS,
    DEFAULT_PROMPT,
    MODULE,
    NODE_DIED_MARKER,
    NODE_PATTERN,
    capture_filter,
    _probes,
    _readme,
    _verdicts,
    session_root,
    wait_for_node_ready,
)


CLUSTER = {
    "P0": {"host": "172.27.172.201", "brpc_port": 47100, "share_port": 47200},
    "P1": {"host": "172.27.172.202", "brpc_port": 47101, "share_port": 47201},
    "P2": {"host": "172.27.172.203", "brpc_port": 47102, "share_port": 47202},
}


class _SigningTransport:
    """Stands in for the SSH transport so ``prepare_enclave`` can be read."""

    def __init__(self) -> None:
        self.commands: list[tuple[str, str]] = []
        self.puts: list[tuple[str, str, str]] = []
        self.gets: list[tuple[str, str, str]] = []

    def run(self, route, command, *, timeout=None, check=True):
        self.commands.append((route.role, command))
        if 'echo "repo=' in command:
            return 0, (
                "repo=/repo\npython=/venv/bin/python\n"
                "workspace=/ws\nenclave=/enclave\n"
            ), ""
        if "gramine-sgx-sign" in command:
            return 0, (
                "Measurement:\n"
                f"     {'ab' * 32}\n\n"
                f"{'cd' * 32}  d6_node.manifest\n"
                f"{'ef' * 32}  d6_node.manifest.sgx\n"
                f"{ENCLAVE_SIGNED_MARKER}\n"
            ), ""
        return 0, "", ""

    def put(self, route, local, remote):
        self.puts.append((route.role, str(local), remote))

    def get(self, route, remote, local):
        self.gets.append((route.role, remote, str(local)))
        Path(local).parent.mkdir(parents=True, exist_ok=True)
        Path(local).write_bytes(b"manifest\n")


def _steps() -> list[dict[str, object]]:
    return [
        {
            "decode_step": 1,
            "token_id": 11,
            "token_word": "cipher",
            "argmax_of_reconstructed_logits": 11,
            "argmax_match": True,
            "step_wall_ms": 812.5,
            "shares": {
                role: {"history_share_probe": f"probe-{role}"} for role in ROLES
            },
        },
        {
            "decode_step": 2,
            "token_id": 80,
            "token_word": "secret",
            "argmax_of_reconstructed_logits": 80,
            "argmax_match": True,
            "step_wall_ms": 640.25,
        },
    ]


def _document() -> dict[str, object]:
    return {
        "run_id": "d6-unit",
        "phase": "D6",
        "mode": "enclave",
        "commit": "abc123",
        "prompt": DEFAULT_PROMPT,
        "prompt_tokens": [3, 70, 71, 11, 80],
        "prompt_words": ["the", "cipher", "key", "is", "secret"],
        "session_id": "00" * 32,
        "generated_tokens": [11, 80],
        "generated_words": ["cipher", "secret"],
        "generated_text": "cipher secret",
        "roles": {
            role: {
                "instance_id": f"i-{role.lower()}",
                "private_address": f"172.27.172.20{index}",
                "public_address": f"47.0.0.{index}",
            }
            for index, role in enumerate(ROLES)
        },
        "enclosure": {
            "measurements": {role: "m" * 64 for role in ROLES},
            "manifest_sha256": {role: "d" * 64 for role in ROLES},
            "distinct_measurements": 1,
            "enclave_size": "4G",
            "max_threads": 64,
            "stack_size": "2M",
            "template": "d6_node.manifest.template",
            "wrapper": ["gramine-sgx", "/w/d6_node"],
        },
        "captures": {
            role: {"bytes": 1000 + index, "sha256": "e" * 64}
            for index, role in enumerate(ROLES)
        },
        "steps": _steps(),
        "reference_check": [
            {
                "decode_step": 1,
                "max_abs_error": 1e-9,
                "mean_abs_error": 1e-11,
                "reference_token": 11,
                "token_match": True,
                "argmax_match": True,
            }
        ],
        "negative_cases": [
            {"case": "duplicate_result_frame", "refused": True, "reason": "rejected"},
            {"case": "replayed_job_ticket", "refused": True, "reason": "rejected"},
        ],
        "node_status": {
            role: {
                "close_evidence": {
                    "spilled_files": 2,
                    "spilled_bytes_overwritten": 512,
                    "session_dir_removed": True,
                    "session_keys_wiped_bytes": 48,
                    "kv": {"entries": 0, "all_zero": True},
                }
            }
            for role in ROLES
        },
        "hygiene": {
            "roles": {
                role: {
                    "verdict": "clean",
                    "findings": [],
                    "roots_that_exist": ["/dev/shm/a122-d6"],
                    "journal": {"available": True},
                }
                for role in ROLES
            }
        },
        "session_state_before_close": {"total_files": 6, "total_bytes": 1536},
        "session_state_after_close": {"total_files": 0, "total_bytes": 0},
        "verdicts": _verdicts(
            result={
                "negative_cases": [
                    {"case": "a", "refused": True},
                    {"case": "b", "refused": True},
                ],
                "reference_verdicts": "passed",
                "shutdown_verdicts": "passed",
            },
            hygiene={"verdict": "clean"},
            tokens=2,
        ),
    }


def _reveal() -> dict[str, object]:
    return {
        "roles": {
            role: {"verdict": "clean", "findings": [], "allowlisted": []}
            for role in ROLES
        }
    }


def test_capture_filter_names_every_d6_port() -> None:
    text = capture_filter()
    assert text == " or ".join(f"port {port}" for port in D6_PORTS)
    assert "47200" in text


def test_session_root_is_under_the_tmpfs() -> None:
    assert session_root("d6-x") == "/dev/shm/a122-d6/d6-x"


def test_the_leftover_node_pattern_matches_the_node_the_driver_starts() -> None:
    """The sweep before a run has to match this driver's own node module."""
    assert re.search(NODE_PATTERN, f"{MODULE} --config /w/configs/P0.json")
    # And it must not be so loose that it also matches an unrelated process.
    assert re.search(NODE_PATTERN, "tee.enclave.spu_node") is None


class _ReadyTransport:
    """Answers the ready probe with whatever the instance's log would say."""

    def __init__(self, answers: dict[str, str]) -> None:
        self.answers = answers
        self.commands: list[str] = []

    def run(self, route, command, **kwargs):
        self.commands.append(command)
        return 0, self.answers.get(route.role, ""), ""


def test_wait_for_node_ready_collects_all_three() -> None:
    transport = _ReadyTransport(
        {role: f"A122-D6-NODE-READY {{'role': '{role}'}}" for role in ROLES}
    )
    ready = wait_for_node_ready(
        transport,                    # type: ignore[arg-type]
        routes(CLUSTER, user="jiahao"),
        logs={role: f"/tmp/{role}.log" for role in ROLES},
        timeout=5.0,
    )
    assert set(ready) == set(ROLES)
    assert "P2" in ready["P2"]


def test_wait_for_node_ready_gives_up_as_soon_as_a_node_dies() -> None:
    """A dead node writes a traceback, so the wait must stop there rather than
    sit out the whole node timeout with the other two bound to their ports."""
    transport = _ReadyTransport(
        {
            "P0": "A122-D6-NODE-READY {}",
            "P1": f"{NODE_DIED_MARKER}\nTraceback (most recent call last):\n"
            "NameError: name 'EncryptedFrame' is not defined",
            "P2": "",
        }
    )
    with pytest.raises(ThreeHostError, match="P1 died before it was ready"):
        wait_for_node_ready(
            transport,                # type: ignore[arg-type]
            routes(CLUSTER, user="jiahao"),
            logs={role: f"/tmp/{role}.log" for role in ROLES},
            timeout=5.0,
        )


def test_every_gate_clause_has_to_hold() -> None:
    good = {
        "negative_cases": [{"case": name, "refused": True} for name in ("a", "b")],
        "reference_verdicts": "passed",
        "shutdown_verdicts": "passed",
    }
    passed = _verdicts(result=good, hygiene={"verdict": "clean"}, tokens=2)
    assert passed["passed"] is True
    assert passed["two_tokens_generated"] is True
    assert passed["negatives_refused"] is True
    one_token = _verdicts(result=good, hygiene={"verdict": "clean"}, tokens=1)
    assert one_token["passed"] is False
    accepted_negative = _verdicts(
        result={
            **good,
            "negative_cases": [
                {"case": "a", "refused": True},
                {"case": "b", "refused": False},
            ],
        },
        hygiene={"verdict": "clean"},
        tokens=2,
    )
    assert accepted_negative["passed"] is False
    assert accepted_negative["negatives_refused"] is False
    dirty = _verdicts(
        result=good, hygiene={"verdict": "session-state-found"}, tokens=2
    )
    assert dirty["passed"] is False
    assert dirty["hygiene_clean"] is False
    no_negatives = _verdicts(result={"negative_cases": []}, hygiene=None, tokens=2)
    assert no_negatives["passed"] is False


def test_probes_come_from_both_sides_of_the_session() -> None:
    result = {"share_probes": ["aaa", "bbb"]}
    statuses = {
        "P0": {"close_evidence": {"spilled_probes": ["ccc", "aaa"]}},
        "P1": {"close_evidence": {"spilled_probes": ["ddd"]}},
        "P2": {"close_evidence": {}},
    }
    assert _probes(result, statuses) == ["aaa", "bbb", "ccc", "ddd"]
    assert _probes({}, {}) == []


def test_the_readme_is_written_from_the_run(tmp_path: Path) -> None:
    document = _document()
    text = _readme(document=document, reveal=_reveal())
    assert "# D6 three-instance enclave run (d6-unit)" in text
    for role in ROLES:
        assert f"| {role} | `i-{role.lower()}` |" in text
    assert "| 1 | 11 | `cipher` | 11 | `True` | 812.5 |" in text
    assert "`duplicate_result_frame` | `True` | rejected |" in text
    assert "| Files under the session root | 6 | 0 |" in text
    assert "| Gate | `True` |" in text
    assert "no undefined" not in text
    assert text.endswith("\n")


def test_the_enclave_template_carries_the_session_root() -> None:
    template = (
        Path(__file__).resolve().parents[2]
        / "tee"
        / "gramine"
        / "enclave"
        / "d6_node.manifest.template"
    ).read_text(encoding="utf-8")
    assert "@SESSION_ROOT@" in template
    assert 'path = "@SESSION_ROOT@", uri = "file:@SESSION_ROOT@"' in template
    assert '"file:@SESSION_ROOT@/"' in template
    command = enclave_sign_command(
        enclave_dir="/e",
        python="~/venv/bin/python",
        repo="/repo",
        workspace="/ws",
        node_name="d6_node",
        session_root="/dev/shm/a122-d6/d6-unit",
    )
    assert '-e "s|@SESSION_ROOT@|/dev/shm/a122-d6/d6-unit|g"' in command
    assert "gramine-sgx-sign --manifest d6_node.manifest" in command


def test_prepare_enclave_hands_the_session_root_to_every_signer(
    tmp_path: Path,
) -> None:
    """The template names @SESSION_ROOT@, so an unsubstituted token would leave
    an empty mount path and Gramine would refuse to start the enclave."""
    template = (
        Path(__file__).resolve().parents[2]
        / "tee"
        / "gramine"
        / "enclave"
        / "d6_node.manifest.template"
    )
    transport = _SigningTransport()
    result = prepare_enclave(
        transport,
        routes(CLUSTER, user="jiahao"),
        template=template,
        run_id="d6-unit",
        out_dir=tmp_path,
        node_name="d6_node",
        bundle_prefix="d6-enclave",
        session_root="/dev/shm/a122-d6/d6-unit",
        prepare_session_root=True,
    )
    signers = [
        command for _role, command in transport.commands if "gramine-sgx-sign" in command
    ]
    assert len(signers) == len(ROLES)
    for command in signers:
        assert '-e "s|@SESSION_ROOT@|/dev/shm/a122-d6/d6-unit|g"' in command
    # The directory is staged before the manifest resolves it, on every rank.
    prepared = [
        command
        for _role, command in transport.commands
        if "mkdir -p /dev/shm/a122-d6/d6-unit" in command
    ]
    assert len(prepared) == len(ROLES)
    assert result["wrapper"][0] == "gramine-sgx"
    assert result["measurements"] == {role: "ab" * 32 for role in ROLES}
