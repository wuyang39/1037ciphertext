"""The D10 release probe has to distinguish the outcomes it records."""

from __future__ import annotations

import json
import socket
from types import SimpleNamespace

from infra import d10_release_check as d10


class _FakeConnection:
    """A minimal socket stand-in for one banner read."""

    def __init__(self, banner: bytes, *, raise_on_recv: Exception | None = None):
        self._banner = banner
        self._raise_on_recv = raise_on_recv
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        self.closed = True
        return False

    def settimeout(self, _timeout):
        return None

    def recv(self, _size):
        if self._raise_on_recv is not None:
            raise self._raise_on_recv
        return self._banner


def _connect_returning(banner: bytes, *, raise_on_recv: Exception | None = None):
    def _fake(_address, timeout=None):  # noqa: ARG001 - mirrors socket signature
        return _FakeConnection(banner, raise_on_recv=raise_on_recv)

    return _fake


def _raising(exc: Exception):
    def _fake(_address, timeout=None):  # noqa: ARG001 - mirrors socket signature
        raise exc

    return _fake


def test_probe_records_an_ssh_banner(monkeypatch):
    monkeypatch.setattr(
        d10.socket, "create_connection", _connect_returning(b"SSH-2.0-OpenSSH_8.9\r\n")
    )
    result = d10.probe("198.51.100.7")
    assert result["verdict"] == "ssh_unverified"
    assert result["connected"] is True
    assert result["banner"] == "SSH-2.0-OpenSSH_8.9"


def test_probe_open_port_without_a_banner_is_silent(monkeypatch):
    monkeypatch.setattr(d10.socket, "create_connection", _connect_returning(b""))
    result = d10.probe("198.51.100.7")
    assert result["verdict"] == "port_open_silent"
    assert result["banner"] is None


def test_probe_refused_connection_is_no_listener(monkeypatch):
    monkeypatch.setattr(
        d10.socket, "create_connection", _raising(ConnectionRefusedError())
    )
    result = d10.probe("198.51.100.7")
    assert result["verdict"] == "no_listener"
    assert result["reason"] == "connection refused"


def test_probe_timeout_is_no_listener(monkeypatch):
    monkeypatch.setattr(d10.socket, "create_connection", _raising(socket.timeout()))
    result = d10.probe("198.51.100.7")
    assert result["verdict"] == "no_listener"
    assert result["reason"] == "connect timed out"


def test_probe_unresolved_name_is_kept_apart(monkeypatch):
    monkeypatch.setattr(
        d10.socket, "create_connection", _raising(OSError(-2, "Name or service not known"))
    )
    result = d10.probe("no-such-name.example")
    assert result["verdict"] == "unresolved"


def test_identify_reports_an_accepted_key():
    def _runner(_command, **_kwargs):
        return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")

    result = d10.identify("198.51.100.7", user="jiahao", identity="/tmp/key", runner=_runner)
    assert result == {
        "identity_used": True,
        "authenticated": True,
        "returncode": 0,
        "stderr": None,
    }


def test_identify_reports_a_refused_key():
    def _runner(_command, **_kwargs):
        return SimpleNamespace(returncode=255, stdout=b"", stderr=b"Permission denied")

    result = d10.identify("198.51.100.7", user="jiahao", identity="/tmp/key", runner=_runner)
    assert result["authenticated"] is False
    assert result["returncode"] == 255
    assert result["stderr"] == "Permission denied"


def test_run_is_released_when_nothing_answers(monkeypatch):
    monkeypatch.setattr(d10.socket, "create_connection", _raising(ConnectionRefusedError()))
    report = d10.run([{"host": "203.0.113.10"}, {"host": "203.0.113.11"}])
    assert report["verdict"] == "released"
    assert report["instances_still_ours"] == 0
    assert report["verdict_counts"] == {"no_listener": 2}


def test_run_is_still_running_when_our_key_still_works(monkeypatch):
    monkeypatch.setattr(
        d10.socket, "create_connection", _connect_returning(b"SSH-2.0-OpenSSH_9.6\r\n")
    )
    monkeypatch.setattr(
        d10, "identify", lambda *a, **k: {"identity_used": True, "authenticated": True}
    )
    report = d10.run(
        [{"host": "203.0.113.10", "user": "jiahao", "identity": "/tmp/key"}]
    )
    assert report["verdict"] == "still_running"
    assert report["instances_still_ours"] == 1


def test_run_accepts_a_banner_that_refuses_our_key(monkeypatch):
    monkeypatch.setattr(
        d10.socket, "create_connection", _connect_returning(b"SSH-2.0-OpenSSH_9.6\r\n")
    )
    monkeypatch.setattr(
        d10, "identify", lambda *a, **k: {"identity_used": True, "authenticated": False}
    )
    report = d10.run(
        [{"host": "203.0.113.10", "user": "jiahao", "identity": "/tmp/key"}]
    )
    assert report["verdict"] == "released"
    assert report["targets"][0]["verdict"] == "ssh_banner_other"


def test_run_stays_unverified_when_a_banner_cannot_be_tested(monkeypatch):
    monkeypatch.setattr(
        d10.socket, "create_connection", _connect_returning(b"SSH-2.0-OpenSSH_9.6\r\n")
    )
    report = d10.run([{"host": "203.0.113.10"}])
    assert report["verdict"] == "unverified"
    assert report["instances_unverified"] == 1


def test_run_flags_a_silent_open_port_as_unverified(monkeypatch):
    monkeypatch.setattr(d10.socket, "create_connection", _connect_returning(b""))
    report = d10.run([{"host": "203.0.113.10"}])
    assert report["verdict"] == "unverified"


def test_main_writes_the_report_and_returns_zero_for_released(monkeypatch, tmp_path):
    monkeypatch.setattr(d10.socket, "create_connection", _raising(ConnectionRefusedError()))
    targets = tmp_path / "targets.json"
    targets.write_text(json.dumps([{"host": "203.0.113.10"}]), encoding="utf-8")
    out = tmp_path / "report.json"
    assert d10.main(["--targets", str(targets), "--out", str(out)]) == 0
    assert json.loads(out.read_text(encoding="utf-8"))["verdict"] == "released"


def test_main_returns_one_when_an_instance_is_still_ours(monkeypatch, tmp_path):
    monkeypatch.setattr(
        d10.socket, "create_connection", _connect_returning(b"SSH-2.0-OpenSSH_9.6\r\n")
    )
    monkeypatch.setattr(
        d10, "identify", lambda *a, **k: {"identity_used": True, "authenticated": True}
    )
    targets = tmp_path / "targets.json"
    targets.write_text(
        json.dumps([{"host": "203.0.113.10", "user": "jiahao", "identity": "/tmp/key"}]),
        encoding="utf-8",
    )
    out = tmp_path / "report.json"
    assert d10.main(["--targets", str(targets), "--out", str(out)]) == 1


def test_main_rejects_an_empty_target_list(tmp_path, capsys):
    targets = tmp_path / "targets.json"
    targets.write_text("[]", encoding="utf-8")
    assert d10.main(["--targets", str(targets), "--out", str(tmp_path / "o.json")]) == 2
    assert "non-empty" in capsys.readouterr().err


def test_main_rejects_malformed_targets(tmp_path, capsys):
    targets = tmp_path / "targets.json"
    targets.write_text("{not json", encoding="utf-8")
    assert d10.main(["--targets", str(targets), "--out", str(tmp_path / "o.json")]) == 2
    assert "could not be read" in capsys.readouterr().err
