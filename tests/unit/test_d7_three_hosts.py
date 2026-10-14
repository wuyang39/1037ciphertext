"""The D7 driver's wiring to the node it starts and waits for.

The driver and the node are separate modules with separate constants, and the
run only works while they still agree about the lines that pass between them,
so those are pinned here rather than discovered after a sign-and-run cycle.
"""

from __future__ import annotations

import re
from pathlib import Path
from types import SimpleNamespace

import pytest

import tee.enclave.d6_node as d6_node
import tee.enclave.d7_node as d7_node
from infra.d4_three_hosts import ROLES, enclave_sign_command
from infra.d7_three_hosts import (
    D7_PORTS,
    DONE_MARKER,
    MODULE,
    NODE_PATTERN,
    READY_MARKER,
    capture_filter,
    session_root,
)


TEMPLATE = (
    Path(__file__).resolve().parents[2]
    / "tee"
    / "gramine"
    / "enclave"
    / "d7_node.manifest.template"
)


def test_the_driver_and_the_node_announce_the_same_markers() -> None:
    """A marker one module writes and the other never greps stalls the run."""
    assert READY_MARKER == d7_node.READY_MARKER
    assert DONE_MARKER == d7_node.DONE_MARKER
    # And the D7 lines are their own, so a D7 log cannot be read as a D6 one.
    assert READY_MARKER != d6_node.READY_MARKER
    assert DONE_MARKER != d6_node.DONE_MARKER


def test_the_d7_node_hands_its_markers_to_the_shared_state_machine(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The D7 node delegates to the D6 runner, so it has to pass its lines in."""
    captured: dict[str, object] = {}

    def fake_run_node(config: object, **kwargs: object) -> int:
        captured.update(kwargs)
        return 0

    monkeypatch.setattr(d7_node, "run_node", fake_run_node)
    monkeypatch.setattr(d7_node, "build_d7_programs", lambda config: object())
    assert d7_node.run_d7_node(SimpleNamespace()) == 0
    assert captured["ready_marker"] == d7_node.READY_MARKER
    assert captured["done_marker"] == d7_node.DONE_MARKER


def test_the_leftover_node_pattern_matches_the_node_the_driver_starts() -> None:
    assert re.search(NODE_PATTERN, f"{MODULE} --config /w/configs/P0.json")
    assert re.search(NODE_PATTERN, "tee.enclave.d6_node") is None
    assert re.search(NODE_PATTERN, "tee.enclave.spu_node") is None


def test_session_root_is_under_the_tmpfs() -> None:
    assert session_root("d7-x") == "/dev/shm/a122-d7/d7-x"


def test_the_capture_covers_every_port_the_run_opens() -> None:
    filter_text = capture_filter()
    for port in D7_PORTS:
        assert f"port {port}" in filter_text


def test_the_enclave_template_carries_the_session_root() -> None:
    template = TEMPLATE.read_text(encoding="utf-8")
    assert "@SESSION_ROOT@" in template
    assert 'path = "@SESSION_ROOT@", uri = "file:@SESSION_ROOT@"' in template
    command = enclave_sign_command(
        enclave_dir="/e",
        python="~/venv/bin/python",
        repo="/repo",
        workspace="/ws",
        node_name="d7_node",
        session_root="/dev/shm/a122-d7/d7-unit",
    )
    assert '-e "s|@SESSION_ROOT@|/dev/shm/a122-d7/d7-unit|g"' in command
    assert "gramine-sgx-sign --manifest d7_node.manifest" in command


def test_the_template_names_every_path_the_instances_resolve() -> None:
    template = TEMPLATE.read_text(encoding="utf-8")
    for token in ("@PYTHON@", "@UV_ROOT@", "@SITE@", "@REPO@", "@WORKSPACE@",
                  "@LIBSPU@", "@ENCLAVE_SIZE@", "@MAX_THREADS@", "@STACK_SIZE@"):
        assert token in template, token


def test_the_cluster_roles_match_the_run_roles() -> None:
    assert tuple(ROLES) == ("P0", "P1", "P2")
