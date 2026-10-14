"""The D7 dealer path: what each node is handed, and what it must not be.

These cases run the real staging code over a real (tiny) GPT-2 export, with a
stand-in for the SPU splitter. The frozen checkpoint is 548 MB and lives
outside the repository, so the cases verify that source when it is present and
skip with a reason when it is not -- the same rule the other D7 cases follow.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any, Sequence

import pytest

import infra.d7_stage as d7_stage
from infra.d7_stage import D7StageError, stage
from infra.d7_vectors import D7_CANDIDATE_SIZE
from infra.d7_workspace import ROLES


FROZEN_GPT2 = Path(__file__).resolve().parents[2] / "artifacts" / "gpt2-frozen"
PROMPT = "the cipher key is secret"
CLUSTER = {
    role: {
        "host": f"172.27.172.{201 + index}",
        "brpc_port": 47100 + index,
        "share_port": 47200 + index,
    }
    for index, role in enumerate(ROLES)
}


def _fake_splitter(values: Any) -> Sequence[str]:
    """Stand in for libspu's MakeShares: three distinguishable strings."""
    size = str(len(values))
    return (f"s0:{size}", f"s1:{size}", f"s2:{size}")


@pytest.fixture(scope="module")
def exported_run(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """One real export, built the way the frozen run was built.

    The dealer re-derives the candidate table from the published rule and
    refuses an export that disagrees, so the run under test uses the same
    ``D7_CANDIDATE_SIZE`` the frozen run used rather than a convenient smaller
    one. The export is shared because it is the slow part.
    """
    if not (FROZEN_GPT2 / "vocab.json").is_file():
        pytest.skip("the frozen GPT-2 checkpoint is not present")
    from model.export import export_gpt2_run

    destination = tmp_path_factory.mktemp("d7-export") / "run"
    export_gpt2_run(
        source_directory=FROZEN_GPT2,
        output_directory=destination,
        model_version="d7-stage-test",
        layers=1,
        sequence=8,
        candidate_size=D7_CANDIDATE_SIZE,
        prompt=PROMPT,
    )
    return destination


def _stage(exported_run: Path, tmp_path: Path, **overrides: Any) -> dict[str, Any]:
    arguments: dict[str, Any] = {
        "run_id": "d7-stage-test",
        "root": tmp_path / "three" / "workspace",
        "client_dir": tmp_path / "client",
        "export_dir": exported_run,
        "tokenizer_dir": FROZEN_GPT2,
        "cluster": CLUSTER,
        "prompt": PROMPT,
        "dist_root": tmp_path / "dist",
        "session_root": "/dev/shm/a122-d7/d7-stage-test",
        "max_new_tokens": 3,
        "splitter": _fake_splitter,
    }
    arguments.update(overrides)
    return stage(**arguments)


def test_stage_ships_exactly_one_share_to_every_node(
    exported_run: Path, tmp_path: Path
) -> None:
    document = _stage(exported_run, tmp_path)

    assert document["candidate_size"] == D7_CANDIDATE_SIZE + 4
    assert document["prompt_tokens"] == [1169, 38012, 1994, 318, 3200]
    for role in ROLES:
        bundle = document["bundles"][role]
        assert bundle["shared_with_this_node"] == [f"{role}.json"]
        assert f"shares/{role}.json" in bundle["files"]
        for other in ROLES:
            if other != role:
                assert f"shares/{other}.json" not in bundle["files"]
                assert f"pki/nodes/{other}/{other}-key.pem" not in bundle["files"]
        # The digest the driver checks a fetch against is the file it wrote.
        from infra.evidence import sha256_file

        assert bundle["tarball_sha256"] == sha256_file(Path(bundle["tarball"]))


def test_stage_keeps_the_client_material_out_of_the_measured_trees(
    exported_run: Path, tmp_path: Path
) -> None:
    document = _stage(exported_run, tmp_path)
    workspace = Path(document["workspace"])
    client_dir = Path(document["client_dir"])

    # The nodes measure and mount the tree they are handed, so the KAS signing
    # key and the client's private key live beside the dealer's workspace.
    assert client_dir != workspace
    assert workspace not in client_dir.parents
    for name in ("C-key.pem", "C-cert.pem", "C-ca-bundle.pem", "kas.json", "C.json"):
        assert (client_dir / name).is_file()
    kas = json.loads((client_dir / "kas.json").read_text(encoding="utf-8"))
    assert kas["kas_signing_private_key"]

    # What actually reaches a node is the tarball, and neither the client's
    # private key nor the KAS signing key may be inside it.
    for role in ROLES:
        shipped = document["bundles"][role]["files"]
        assert not [name for name in shipped if "kas.json" in name], role
        assert not [name for name in shipped if "C-key.pem" in name], role
        assert not [name for name in shipped if name.startswith("pki/nodes/C/")], role
        tree = Path(document["bundles"][role]["tree"])
        assert not list(tree.rglob("kas.json")), role
        assert not list(tree.rglob("C-key.pem")), role


def test_stage_refuses_a_tree_that_carries_two_shares(
    exported_run: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real_tree = d7_stage._node_tree

    def leaky(**arguments: Any) -> None:
        real_tree(**arguments)
        # Smuggle a peer's share into the tree, the way a copy-and-paste error
        # in the dealer's tree writer would.
        role = arguments["role"]
        peer = "P1" if role != "P1" else "P2"
        workspace = Path(arguments["workspace"])
        target = Path(arguments["target"])
        shutil.copyfile(
            workspace / "shares" / f"{peer}.json",
            target / "shares" / f"{peer}.json",
        )

    monkeypatch.setattr(d7_stage, "_node_tree", leaky)
    with pytest.raises(D7StageError, match="another party's shares"):
        _stage(exported_run, tmp_path)


def test_the_staged_configs_are_the_documents_the_two_ends_parse(
    exported_run: Path, tmp_path: Path
) -> None:
    """The dealer writes the plans and manifests; the ends read them back.

    Both the node and the client parse the model manifest into a D7 one rather
    than the D6 one, so this walks the real staged documents through the same
    entry points the processes call.
    """
    from client.d7_session import D7Client  # noqa: F401 - import check only
    from contracts.d7_session import D7ModelManifest, D7SessionPlan
    from tee.enclave.d6_node import load_weight_shares
    from tee.enclave.d7_node import D7NodeConfig, build_d7_programs

    document = _stage(exported_run, tmp_path)
    workspace = Path(document["workspace"])
    # The client reads its configuration from beside the workspace, not from
    # inside it: the node that drives the session replaces its workspace with
    # the stripped tree it was sent, and the dealer's copy is gone by then.
    client_document = json.loads(
        (Path(document["client_dir"]) / "C.json").read_text(encoding="utf-8")
    )
    client_plan = D7SessionPlan.from_dict(client_document["plan"])
    client_model = D7ModelManifest.from_dict(client_document["model"])

    for role in ROLES:
        node_document = json.loads(
            (workspace / "configs" / f"{role}.json").read_text(encoding="utf-8")
        )
        config = D7NodeConfig.from_document(node_document)
        assert config.role == role
        assert config.model.vocab_size == document["candidate_size"]
        assert config.model.model_hash == document["model_hash"]
        assert config.model.to_dict() == client_model.to_dict()
        assert config.plan.to_dict() == client_plan.to_dict()
        # One program per decoding step, and every tensor the program names is
        # one this node was handed a share of.
        programs = build_d7_programs(config)
        assert len(programs.programs) == config.plan.max_new_tokens
        assert programs.kv_max_layers == 1
        shares = load_weight_shares(config.weights_path)
        assert set(programs.weight_tensors) <= set(shares)
