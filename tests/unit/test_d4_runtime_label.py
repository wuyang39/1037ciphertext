from __future__ import annotations

from pathlib import Path

from tee.enclave.spu_node import runtime_label


def test_runtime_label_names_the_host_process(tmp_path: Path) -> None:
    """A plain process may not be described as an enclave in the trace."""
    label, inside = runtime_label(tmp_path / "no-attestation-here")
    assert inside is False
    assert "host process" in label
    assert "enclave" not in label
    assert label.startswith("SPU/YACL/BRPC over TLS 1.3")


def test_runtime_label_names_the_enclave_when_attestation_is_mounted(
    tmp_path: Path,
) -> None:
    label, inside = runtime_label(tmp_path)
    assert inside is True
    assert "Gramine-SGX enclave" in label
