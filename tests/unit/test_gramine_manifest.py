from __future__ import annotations

from pathlib import Path

import pytest

from infra.validate_gramine_manifest import (
    ManifestValidationError,
    REQUIRED_VALUES,
    render_template,
    validate_manifest_text,
)


def test_gramine_template_renders_and_validates(tmp_path: Path) -> None:
    template = Path("tee/gramine/a122.manifest.template").read_text(encoding="utf-8")
    values = {name: f"/{name}" if name.endswith(("dir", "path")) else name for name in REQUIRED_VALUES}
    values["entrypoint"] = "/app/a122-worker"
    values["release_id"] = "release-v1"
    values["role"] = "P0"
    values["share_epoch"] = 7
    values["enclave_size"] = "4G"
    values["python_runtime_path"] = "/usr/bin/python3"
    rendered, details = render_template(template, values)
    validate_manifest_text(rendered)
    assert details["placeholder_count"] > 0

    with pytest.raises(ManifestValidationError, match="forbidden"):
        validate_manifest_text(
            rendered.replace(
                "sgx.debug = false",
                "sgx.debug = " + "true",
            )
        )
