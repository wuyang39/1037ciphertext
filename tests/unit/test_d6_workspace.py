"""The D6 workspace stages everything one run needs, and says where."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Sequence

from infra.d6_vectors import WEIGHT_TENSORS
from infra.d6_workspace import DEFAULT_SESSION_BASE, build_workspace
from tee.enclave.d6_node import D6NodeConfig, load_weight_shares


ROLES = ("P0", "P1", "P2")


def _cluster() -> dict[str, dict[str, Any]]:
    return {
        role: {
            "host": f"172.27.172.20{index}",
            "brpc_port": 47100 + index,
            "share_port": 47200 + index,
            "instance_id": f"i-{role.lower()}",
            "public_address": f"47.0.0.{index}",
        }
        for index, role in enumerate(ROLES)
    }


def _stub_splitter(value: Any) -> Sequence[str]:
    """The dealer's split, replaced by three strings that stay distinguishable."""
    assert value is not None
    return ["share-P0", "share-P1", "share-P2"]


def test_the_workspace_carries_its_shares_and_names_its_session_dirs(
    tmp_path: Path,
) -> None:
    root = tmp_path / "workspace"
    manifest = build_workspace(
        root,
        run_id="d6-unit",
        cluster=_cluster(),
        session_root="/dev/shm/a122-d6/d6-unit",
        splitter=_stub_splitter,
    )
    # The slices travel with the workspace, so one tarball is the whole run
    # and the enclave's trusted workspace pins the exact shares it loads.
    for role in ROLES:
        assert (root / "shares" / f"{role}.json").is_file()
        assert manifest["shares"][role] == str(root / "shares" / f"{role}.json")
    assert manifest["session_root"] == "/dev/shm/a122-d6/d6-unit"
    assert manifest["session_dirs"] == {
        role: f"/dev/shm/a122-d6/d6-unit/{role}" for role in ROLES
    }

    node = json.loads(Path(manifest["configs"]["P0"]).read_text(encoding="utf-8"))
    config = D6NodeConfig.from_document(node)
    assert config.session_dir == Path("/dev/shm/a122-d6/d6-unit/P0")
    assert config.spill_session_state is True
    assert config.role == "P0"
    shares = load_weight_shares(config.weights_path)
    assert shares == {name: "share-P0" for name, _kind in WEIGHT_TENSORS}
    # A node holds the public halves only: it cannot mint the ticket or the
    # client certificate it is asked to verify.
    assert node["kas_public_key"] == manifest["sm2_public_keys"]["kas"]
    assert (
        node["client_authority_public_key"]
        == manifest["sm2_public_keys"]["client_authority"]
    )

    client = json.loads(Path(manifest["configs"]["C"]).read_text(encoding="utf-8"))
    assert set(client["nodes"]) == set(ROLES)
    for role in ROLES:
        assert client["nodes"][role]["share_host"] == _cluster()[role]["host"]
        assert client["nodes"][role]["share_port"] == _cluster()[role]["share_port"]
        assert client["nodes"][role]["identity_public_key"] == (
            manifest["sm2_public_keys"]["nodes"][role]
        )

    kas = json.loads((root / "kas.json").read_text(encoding="utf-8"))
    assert kas["kas_public_key"] == manifest["sm2_public_keys"]["kas"]
    assert kas["kas_signing_private_key"] != kas["kas_public_key"]
    assert Path(kas["client_transport"]["certificate"]).is_file()
    # The two private halves the node must not hold stay in kas.json.
    node_text = json.dumps(node)
    assert kas["kas_signing_private_key"] not in node_text
    assert kas["client_authority_private_key"] not in node_text


def test_the_session_root_defaults_to_the_host_tmpfs(tmp_path: Path) -> None:
    manifest = build_workspace(
        tmp_path / "workspace",
        run_id="d6-default",
        cluster=_cluster(),
        splitter=_stub_splitter,
    )
    assert manifest["session_root"] == f"{DEFAULT_SESSION_BASE}/d6-default"
    assert manifest["session_dirs"]["P2"] == f"{DEFAULT_SESSION_BASE}/d6-default/P2"


def test_a_short_cluster_is_refused(tmp_path: Path) -> None:
    cluster = _cluster()
    del cluster["P2"]
    try:
        build_workspace(
            tmp_path / "workspace",
            run_id="d6-unit",
            cluster=cluster,
            splitter=_stub_splitter,
        )
    except ValueError as exc:
        assert "P2" in str(exc)
    else:  # pragma: no cover - the guard has to fire
        raise AssertionError("a cluster without P2 was accepted")
