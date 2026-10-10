from __future__ import annotations

from pathlib import Path

from infra.build_model_package import (
    build_local_model_package,
    build_tiny_model,
    verify_local_model_package,
)
from model.export import export_model


def test_local_model_package_is_deterministic_and_verifiable(tmp_path: Path) -> None:
    bundle = export_model(build_tiny_model(), model_version="tiny-package-v1")
    result = build_local_model_package(
        bundle,
        output_dir=tmp_path / "package",
        share_epoch=7,
        share_seed=11,
        encrypt_with_local_seed="unit-test-local-key",
    )
    assert result["share_count"] == 3
    assert result["encrypted_share_count"] == 3
    verification = verify_local_model_package(tmp_path / "package")
    assert verification["valid"] is True
    assert verification["share_epoch"] == 7
