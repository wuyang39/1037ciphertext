"""Provision the D7 workspace, then stage exactly one tree per node.

``infra.d7_workspace`` builds the whole run in one place, the way a dealer
does. This module is the step that decides what each node is allowed to
receive, and it deliberately sends less than the workspace holds:

* a node gets its **own** share file and no other, so no instance can add two
  shares together and name a weight;
* a node gets its own SM2 key and the CA-signed certificates of its peers --
  never a peer's private key;
* the client's own material, including the KAS signing key, is copied to a
  directory outside the node workspace, because the workspace is a tree the
  enclave measures and mounts.

The three trees are written as tarballs ready to be fetched, and the summary
records the digest of each so the distributed bytes can be checked against what
the driver sent.

Usage::

    python -m infra.d7_stage --run-id d7-enclave-3host-<stamp> \
        --root $HOME/a122-d7/three/workspace --client-dir $HOME/a122-d7/client \
        --export-dir $HOME/a122-d7/export --tokenizer-dir $HOME/a122-d7/tokenizer \
        --cluster-file /tmp/<run-id>-cluster.json \
        --session-root /dev/shm/a122-d7/<run-id> --dist-root $HOME/a122-d7/dist \
        --prompt "the cipher key is secret" --output /tmp/<run-id>-stage.json
"""

from __future__ import annotations

import argparse
import json
import shutil
import tarfile
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from infra.d7_workspace import CLIENT, ROLES, D7WorkspaceError, build_workspace
from infra.evidence import sha256_file, write_json


class D7StageError(ValueError):
    """The per-node trees could not be assembled."""


def _copy_file(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)


def _node_tree(
    *,
    workspace: Path,
    target: Path,
    role: str,
    manifest: Mapping[str, Any],
) -> None:
    """Write one node's tree: its share, its config, and public peer material."""
    if target.exists():
        shutil.rmtree(target)
    _copy_file(Path(manifest["shares"][role]), target / "shares" / f"{role}.json")
    _copy_file(Path(manifest["configs"][role]), target / "configs" / f"{role}.json")
    _copy_file(workspace / "workspace.json", target / "workspace.json")
    for material in sorted((workspace / "pki" / "nodes" / role).glob("*")):
        _copy_file(material, target / "pki" / "nodes" / role / material.name)
    for peer in ROLES:
        if peer == role:
            continue
        certificate = workspace / "pki" / "nodes" / peer / f"{peer}-cert.pem"
        _copy_file(
            certificate, target / "pki" / "nodes" / peer / f"{peer}-cert.pem"
        )


def _tar(tree: Path, destination: Path) -> None:
    """Pack one tree with its top directory named ``workspace``."""
    if destination.exists():
        destination.unlink()
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(destination, "w:gz") as archive:
        archive.add(tree, arcname="workspace", recursive=True)


def stage(
    *,
    run_id: str,
    root: Path,
    client_dir: Path,
    export_dir: Path,
    tokenizer_dir: Path,
    cluster: Mapping[str, Mapping[str, Any]],
    prompt: str,
    dist_root: Path,
    session_root: str | None = None,
    max_new_tokens: int | None = None,
    splitter: Callable[[Any], Sequence[str]] | None = None,
) -> dict[str, Any]:
    """Provision the run, then write one tarball per node.

    ``splitter`` is the same seam ``build_workspace`` offers: only the share
    split needs the SPU runtime, so the rest of the dealer path -- the digest
    checks, the candidate table, the per-node trees and the tarballs -- can be
    exercised without libspu.
    """
    root = Path(root)
    client_dir = Path(client_dir)
    dist_root = Path(dist_root)
    kwargs: dict[str, Any] = {}
    if max_new_tokens is not None:
        kwargs["max_new_tokens"] = int(max_new_tokens)
    if splitter is not None:
        kwargs["splitter"] = splitter
    manifest = build_workspace(
        root,
        run_id=run_id,
        cluster=cluster,
        export_dir=export_dir,
        tokenizer_dir=tokenizer_dir,
        prompt=prompt,
        session_root=session_root,
        client_dir=client_dir,
        **kwargs,
    )
    # The client's material is moved out of the workspace: a node measures and
    # mounts that tree, and the KAS signing key must not be inside it.
    client_dir.mkdir(parents=True, exist_ok=True)
    for name in ("C-cert.pem", "C-key.pem", "C-ca-bundle.pem"):
        _copy_file(root / "pki" / "nodes" / CLIENT / name, client_dir / name)
    _copy_file(root / "kas.json", client_dir / "kas.json")

    dist_root.mkdir(parents=True, exist_ok=True)
    children = [root, root / "pki", root / "shares", root / "configs"]
    if (root / "workspace.json").is_file():
        children.append(root / "workspace.json")
    if (root / "kas.json").is_file():
        children.append(root / "kas.json")
    if (root / "client").exists():
        children.append(root / "client")
    if (root / "out").exists():
        children.append(root / "out")
    bundles: dict[str, Any] = {}
    for role in ROLES:
        tree = dist_root / role / "workspace"
        _node_tree(workspace=root, target=tree, role=role, manifest=manifest)
        tarball = dist_root / f"{role}.tgz"
        _tar(tree, tarball)
        present = sorted(
            path.relative_to(tree).as_posix()
            for path in tree.rglob("*")
            if path.is_file()
        )
        # What this node's own tree actually carries, which is the thing the
        # leak check below is about: the dealer's ``shares`` directory holds
        # all three, and only the one copied into ``tree`` is shipped.
        extra = {
            role: sorted(
                path.name
                for path in (tree / "shares").glob("*.json")
            )
        }
        bundles[role] = {
            "tree": str(tree),
            "tarball": str(tarball),
            "tarball_bytes": tarball.stat().st_size,
            "tarball_sha256": sha256_file(tarball),
            "files": present,
            "shared_with_this_node": extra[role],
        }
    for role, bundle in bundles.items():
        leaked = [
            name
            for name in bundle["shared_with_this_node"]
            if name != f"{role}.json"
        ]
        if leaked:
            raise D7StageError(
                f"{role} would receive another party's shares: {', '.join(leaked)}"
            )
    document = {
        "run_id": run_id,
        "workspace": str(root),
        "client_dir": str(client_dir),
        "dist_root": str(dist_root),
        "session_root": manifest["session_root"],
        "model_manifest_hash": manifest["plan"]["model_manifest_hash"],
        "model_hash": manifest["model"]["model_hash"],
        "candidate_size": len(manifest["candidate_tokens"]),
        "prompt_tokens": manifest["prompt_tokens"],
        "plan": manifest["plan"],
        "bundles": bundles,
        # A reader can compare the option beside each leaf directory above.
        "provisioned_children": [path.name for path in children],
    }
    return document


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="A1-22 D7 per-node staging")
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--client-dir", required=True, type=Path)
    parser.add_argument("--export-dir", required=True, type=Path)
    parser.add_argument("--tokenizer-dir", required=True, type=Path)
    parser.add_argument("--cluster-file", required=True, type=Path)
    parser.add_argument("--dist-root", required=True, type=Path)
    parser.add_argument("--prompt", required=True)
    parser.add_argument("--session-root", default=None)
    parser.add_argument("--max-new-tokens", type=int, default=None)
    parser.add_argument("--output", type=Path, default=None)
    args = parser.parse_args(argv)
    cluster = json.loads(Path(args.cluster_file).read_text(encoding="utf-8"))
    try:
        document = stage(
            run_id=args.run_id,
            root=args.root,
            client_dir=args.client_dir,
            export_dir=args.export_dir,
            tokenizer_dir=args.tokenizer_dir,
            cluster=cluster,
            prompt=args.prompt,
            dist_root=args.dist_root,
            session_root=args.session_root,
            max_new_tokens=args.max_new_tokens,
        )
    except (OSError, D7WorkspaceError, D7StageError, ValueError) as exc:
        print(json.dumps({"error": f"{type(exc).__name__}: {exc}"}, sort_keys=True))
        return 1
    if args.output is not None:
        write_json(Path(args.output), document)
    print(
        json.dumps(
            {
                "run_id": document["run_id"],
                "model_hash": document["model_hash"],
                "model_manifest_hash": document["model_manifest_hash"],
                "candidate_size": document["candidate_size"],
                "prompt_tokens": document["prompt_tokens"],
                "dist_root": document["dist_root"],
                "tarballs": {
                    role: document["bundles"][role]["tarball_bytes"]
                    for role in ROLES
                },
            },
            sort_keys=True,
        )
    )
    return 0


__all__ = ["D7StageError", "main", "stage"]


if __name__ == "__main__":
    raise SystemExit(main())
