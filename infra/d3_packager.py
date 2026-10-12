"""Build the Gramine encrypted-FS store from a KAS-derived disk key.

This tool stands in for the packaging step that runs inside the KAS trust
domain: it derives ``K_disk_i`` exactly as the online release endpoint does,
turns it into the 16-byte Gramine protected-files key, and encrypts the
plaintext model share into the store. The key only ever exists in a mode-0600
file under a memory-backed directory, which is overwritten and unlinked before
the tool returns.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from crypto.enclave_key import protected_files_key
from infra.evidence import sha256_file, write_json
from kas.storage_keys import derive_storage_key


def _key_file_directory() -> Path:
    for candidate in (Path("/dev/shm"), Path(tempfile.gettempdir())):
        if candidate.is_dir() and os.access(candidate, os.W_OK):
            return candidate
    raise RuntimeError("no writable memory-backed directory for the disk key")


def _scrub(path: Path) -> None:
    try:
        size = path.stat().st_size
        with path.open("r+b") as handle:
            handle.write(b"\x00" * size)
            handle.flush()
            os.fsync(handle.fileno())
    except OSError:
        pass
    finally:
        path.unlink(missing_ok=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--master-hex", required=True)
    parser.add_argument("--role", default="P0")
    parser.add_argument("--release-id", required=True)
    parser.add_argument("--share-epoch", type=int, required=True)
    parser.add_argument("--purpose", default="model-store")
    parser.add_argument("--plaintext-dir", type=Path, required=True)
    parser.add_argument("--store-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--pf-crypt",
        default="gramine-sgx-pf-crypt",
    )
    parser.add_argument(
        "--scrub-plaintext",
        action="store_true",
        help="overwrite and delete the plaintext share once the store exists",
    )
    args = parser.parse_args(argv)

    try:
        master = bytes.fromhex(args.master_hex)
    except ValueError as exc:
        raise SystemExit("--master-hex must be hexadecimal") from exc
    if len(master) < 32:
        raise SystemExit("--master-hex must contain at least 32 bytes")

    key, key_id = derive_storage_key(
        storage_key_master=master,
        role=args.role,
        release_id=args.release_id,
        share_epoch=args.share_epoch,
        purpose=args.purpose,
    )
    pf_key = protected_files_key(key)

    plaintext_dir = args.plaintext_dir.resolve()
    store_dir = args.store_dir.resolve()
    store_dir.parent.mkdir(parents=True, exist_ok=True)
    if store_dir.exists():
        shutil.rmtree(store_dir)
    store_dir.mkdir(parents=True)

    handle = tempfile.NamedTemporaryFile(
        dir=_key_file_directory(),
        prefix="a122-pfkey-",
        delete=False,
    )
    key_path = Path(handle.name)
    try:
        os.chmod(key_path, 0o600)
        handle.write(pf_key)
        handle.flush()
        os.fsync(handle.fileno())
        handle.close()
        completed = subprocess.run(
            [
                args.pf_crypt,
                "encrypt",
                "-i",
                str(plaintext_dir),
                "-o",
                str(store_dir),
                "-w",
                str(key_path),
            ],
            check=False,
            capture_output=True,
            text=True,
        )
    finally:
        try:
            handle.close()
        except OSError:
            pass
        _scrub(key_path)

    if completed.returncode != 0:
        raise SystemExit(
            "gramine-sgx-pf-crypt failed: "
            + (completed.stderr.strip() or completed.stdout.strip())
        )

    record = {
        "role": args.role,
        "release_id": args.release_id,
        "share_epoch": args.share_epoch,
        "purpose": args.purpose,
        "key_id": key_id,
        "plaintext_dir": str(plaintext_dir),
        "store_dir": str(store_dir),
        "plaintext_files": [
            {
                "name": path.name,
                "bytes": path.stat().st_size,
                "sha256": sha256_file(path),
            }
            for path in sorted(plaintext_dir.iterdir())
            if path.is_file()
        ],
        "store_files": [
            {
                "name": path.name,
                "bytes": path.stat().st_size,
                "sha256": sha256_file(path),
            }
            for path in sorted(store_dir.iterdir())
            if path.is_file()
        ],
    }
    if args.scrub_plaintext:
        for path in sorted(plaintext_dir.iterdir()):
            if path.is_file():
                _scrub(path)
    write_json(args.output, record)
    print(json.dumps({"key_id": key_id, "store_files": len(record["store_files"])}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
