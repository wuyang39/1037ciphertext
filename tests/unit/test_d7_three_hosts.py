"""The D7 driver's wiring to the node it starts and waits for.

The driver and the node are separate modules with separate constants, and the
run only works while they still agree about the lines that pass between them,
so those are pinned here rather than discovered after a sign-and-run cycle.
"""

from __future__ import annotations

import re
import shlex
from pathlib import Path
from types import SimpleNamespace

import pytest

import tee.enclave.d6_node as d6_node
import tee.enclave.d7_node as d7_node
from infra.d4_three_hosts import (
    ROLES,
    ThreeHostError,
    capture_command,
    enclave_sign_command,
)
from infra.d7_three_hosts import (
    CAPTURE_BUFFER_KIB,
    D7_PORTS,
    DONE_MARKER,
    MODULE,
    NODE_PATTERN,
    READY_MARKER,
    assert_capture_headroom,
    capture_filter,
    capture_headroom_error,
    scrub_script,
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


def test_the_capture_filter_is_the_one_the_command_actually_uses() -> None:
    """The driver declares its ports; the filter and the analysis must agree.

    The capture helper used to build its filter from the D4 six-port list, so a
    run that opened more ports was analysed against a set it had never filtered
    on. Both sides now come from ``D7_PORTS``.
    """
    command = capture_command(
        iface="eth0",
        pcap="/tmp/p.pcap",
        log="/tmp/p.log",
        buffer_kib=CAPTURE_BUFFER_KIB,
        ports=D7_PORTS,
    )
    assert shlex.quote(capture_filter()) in command


def test_the_scrub_script_expands_the_home_directory() -> None:
    """A quoted tilde is a literal directory name, so the scrub would miss.

    The first sealed D7 run reported `share_removed: true` for three instances
    whose 92 MB share files were still on disk, because every home-relative path
    in the scrub script had gone through `shlex.quote`. Anything that starts at
    `~` has to render as `"$HOME/..."` for the remote shell to expand it.
    """
    script = scrub_script(
        role_root="~/a122-d7/three/workspace",
        dist_root="~/a122-d7/dist",
        role="P1",
    )
    assert (
        'share="$HOME/a122-d7/three/workspace/shares/P1.json"' in script
    )
    assert "'~/" not in script
    assert '"$HOME/a122-d7/dist"' in script
    assert '"$HOME/a122-d7/three/workspace/pki/nodes/C"' in script
    # The pre-removal overwrite is what makes the removal unrecoverable.
    assert "dd if=/dev/zero" in script
    # And the verification has to look at a size only a share reaches.
    assert "-size +1048576c" in script


def test_the_capture_ring_is_refused_when_the_kernel_would_clamp_it() -> None:
    """``tcpdump -B`` is silently clamped, so a small ring has to stop the run.

    The D7 decode pushes about a gigabyte through each host in seconds. A ring
    clamped to the stock ``net.core.rmem_max`` drops segments, the analyser
    cannot reassemble the stream, and the sealed capture reads as a violation
    that never happened. Checking first turns that into a message instead.
    """
    wanted = CAPTURE_BUFFER_KIB * 1024
    assert capture_headroom_error(wanted, buffer_kib=CAPTURE_BUFFER_KIB) is None
    assert capture_headroom_error(wanted + 1, buffer_kib=CAPTURE_BUFFER_KIB) is None
    problem = capture_headroom_error(wanted - 1, buffer_kib=CAPTURE_BUFFER_KIB)
    assert problem is not None
    assert str(wanted) in problem
    # The stock 212992-byte cap is the case the check exists for.
    assert capture_headroom_error(212992, buffer_kib=CAPTURE_BUFFER_KIB) is not None


class _FakeTransport:
    """A transport that answers every host with the same ``rmem_max``."""

    def __init__(self, body: str, status: int = 0) -> None:
        self.body = body
        self.status = status
        self.commands: list[str] = []

    def run(self, _route: object, command: str, **_kwargs: object) -> tuple[int, str, str]:
        self.commands.append(command)
        return self.status, self.body, ""


def test_a_host_with_a_clamped_ring_stops_the_run_before_the_capture() -> None:
    routes = {role: object() for role in ROLES}
    assert_capture_headroom(
        _FakeTransport(f"{CAPTURE_BUFFER_KIB * 1024}\n"),
        routes,
        buffer_kib=CAPTURE_BUFFER_KIB,
    )
    with pytest.raises(ThreeHostError, match="rmem_max"):
        assert_capture_headroom(
            _FakeTransport("212992\n"), routes, buffer_kib=CAPTURE_BUFFER_KIB
        )
    # A host that cannot be read is not assumed fine either.
    with pytest.raises(ThreeHostError, match="could not read"):
        assert_capture_headroom(
            _FakeTransport("", status=1), routes, buffer_kib=CAPTURE_BUFFER_KIB
        )


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
