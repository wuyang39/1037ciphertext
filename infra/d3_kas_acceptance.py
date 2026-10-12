"""Drive the D3 KAS-sealed storage-key acceptance cases on a real SGX host.

The shell entry point prepares the artifacts (model package, KAS secrets,
signed enclave, encrypted store) and then hands control to this module. The
module owns everything that needs the enclave, the KAS, and the case grid:

* it measures the signed enclave from a real DCAP Quote and writes the release
  policy the KAS will enforce;
* it starts the KAS (good policy) and a second KAS (deliberately wrong
  measurement);
* it runs every accept and deny case and records the raw results in
  ``cases.json`` for the evidence collector.
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import json
import os
import secrets
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

from infra.evidence import sha256_file, write_json


BEGIN_MARKER = "A1_22_ENCFS_BEGIN"
END_MARKER = "A1_22_ENCFS_END"
DEFAULT_READY_TIMEOUT = 240.0


class AcceptanceError(RuntimeError):
    """A case could not be driven to a conclusive result."""


@dataclass
class EnclaveOutput:
    """Parsed ``key=value`` output of one enclave Worker run."""

    label: str
    exit_status: int | None
    fields: dict[str, int | str]
    text: str
    complete: bool

    def get(self, name: str, default: object = None) -> object:
        return self.fields.get(name, default)


@dataclass
class Context:
    """Everything the case grid needs, resolved from the shell entry point."""

    root: Path
    work: Path
    out: Path
    python: str
    system_python: str
    release_id: str
    share_epoch: int
    model_version: str
    model_manifest_hash: str
    precision_plan_hash: str
    storage_master_hex: str
    kas_dir: Path
    verifier_bin: Path
    enclave_dir: Path
    control_root: Path
    store_dir: Path
    share_name: str
    key_name: str
    repo_guest_dir: str
    control_guest_dir: str
    secure_guest_dir: str
    kas_port: int
    cloud_region: str
    instance_id: str
    claims: dict[str, object] = field(default_factory=dict)
    cases: dict[str, object] = field(default_factory=dict)
    kas_processes: dict[int, subprocess.Popen] = field(default_factory=dict)
    kas_starts: int = 0

    @property
    def good_base_url(self) -> str:
        return f"http://127.0.0.1:{self.kas_port}"

    @property
    def wrong_base_url(self) -> str:
        return f"http://127.0.0.1:{self.kas_port + 1}"


def _http_post(
    base_url: str,
    path: str,
    payload: dict[str, object],
    *,
    timeout: float = 30.0,
) -> tuple[int, dict[str, object]]:
    request = urllib.request.Request(
        base_url + path,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        try:
            document = json.loads(raw)
        except json.JSONDecodeError:
            document = {"detail": raw}
        return exc.code, document
    except urllib.error.URLError as exc:
        raise AcceptanceError(f"KAS is unreachable at {base_url}: {exc}") from exc


def parse_enclave_output(label: str, text: str) -> EnclaveOutput:
    fields: dict[str, int | str] = {}
    exit_status: int | None = None
    for line in text.splitlines():
        line = line.rstrip("\r")
        if line.startswith("# gramine-sgx exit status: "):
            exit_status = int(line.rsplit(" ", 1)[1])
            continue
        name, separator, value = line.partition("=")
        if not separator or not name or " " in name:
            continue
        fields[name] = int(value) if value.isdigit() else value
    return EnclaveOutput(
        label=label,
        exit_status=exit_status,
        fields=fields,
        text=text,
        complete=END_MARKER in text,
    )


class EnclaveSession:
    """One enclave Worker run against one KAS challenge."""

    def __init__(
        self,
        ctx: Context,
        name: str,
        *,
        base_url: str,
        epoch: int | None = None,
        model_version: str | None = None,
        release_timeout: int = 6,
    ) -> None:
        self._ctx = ctx
        self.name = name
        self.base_url = base_url
        self.epoch = ctx.share_epoch if epoch is None else epoch
        self.model_version = (
            ctx.model_version if model_version is None else model_version
        )
        self.release_timeout = release_timeout
        self.control = ctx.control_root / name
        self.control_guest = ctx.control_guest_dir
        self.challenge: dict[str, object] = {}
        self.quote: bytes = b""
        self.public_key: str = ""
        self.process: subprocess.Popen | None = None
        self._stdout_path = ctx.out / f"{name}.txt"

    @property
    def output(self) -> EnclaveOutput:
        text = self._stdout_path.read_text(encoding="utf-8", errors="replace")
        return parse_enclave_output(self.name, text)

    def __enter__(self) -> "EnclaveSession":
        self.control.mkdir(parents=True, exist_ok=True)
        status, document = _http_post(
            self.base_url,
            "/v1/challenge",
            {"role": "P0", "release_id": self._ctx.release_id},
        )
        if status != 201:
            raise AcceptanceError(f"{self.name}: challenge refused with {status}")
        self.challenge = document
        (self.control / "nonce.hex").write_text(
            str(document["nonce"]) + "\n",
            encoding="ascii",
        )
        write_json(
            self.control / "challenge.json",
            {"status": status, "body": document},
        )
        command = [
            "gramine-sgx",
            "./encfs_worker",
            f"{self._ctx.repo_guest_dir}/tee/enclave/encfs_worker.py",
            "--control-dir",
            self.control_guest,
            "--key-name",
            self._ctx.key_name,
            "--guest-file",
            f"{self._ctx.secure_guest_dir}/{self._ctx.share_name}",
            "--role",
            "P0",
            "--release-id",
            self._ctx.release_id,
            "--share-epoch",
            str(self.epoch),
            "--model-version",
            self.model_version,
            "--model-manifest-hash",
            self._ctx.model_manifest_hash,
            "--precision-plan-hash",
            self._ctx.precision_plan_hash,
            "--release-timeout",
            str(self.release_timeout),
        ]
        handle = self._stdout_path.open("wb")
        self.process = subprocess.Popen(
            command,
            cwd=self._ctx.enclave_dir,
            stdout=handle,
            stderr=subprocess.STDOUT,
        )
        self._wait_for_ready()
        return self

    def _wait_for_ready(self) -> None:
        deadline = time.monotonic() + DEFAULT_READY_TIMEOUT
        quote_path = self.control / "quote.bin"
        key_path = self.control / "enclave_public_key.hex"
        while time.monotonic() < deadline:
            if quote_path.is_file() and key_path.is_file():
                if quote_path.stat().st_size and key_path.stat().st_size:
                    self.quote = quote_path.read_bytes()
                    self.public_key = key_path.read_text(encoding="ascii").strip()
                    return
            if self.process is not None and self.process.poll() is not None:
                raise AcceptanceError(
                    f"{self.name}: the enclave exited before publishing a Quote"
                )
            time.sleep(0.2)
        raise AcceptanceError(f"{self.name}: timed out waiting for the Quote")

    def request_seal(
        self,
        *,
        epoch: int | None = None,
        base_url: str | None = None,
        challenge: dict[str, object] | None = None,
        quote: bytes | None = None,
        public_key: str | None = None,
    ) -> tuple[int, dict[str, object]]:
        return _http_post(
            base_url or self.base_url,
            "/v1/release-storage-key-sealed",
            {
                "challenge_id": str((challenge or self.challenge)["challenge_id"]),
                "role": "P0",
                "release_id": self._ctx.release_id,
                "share_epoch": self.epoch if epoch is None else epoch,
                "purpose": "model-store",
                "enclave_public_key": public_key or self.public_key,
                "dcap_quote_b64": base64.b64encode(
                    self.quote if quote is None else quote
                ).decode("ascii"),
            },
        )

    def deliver(self, sealed_hex: str, *, tamper: bool = False) -> None:
        raw = bytearray(bytes.fromhex(sealed_hex))
        if tamper:
            raw[-1] ^= 0x5A
        (self.control / "sealed.hex").write_text(bytes(raw).hex() + "\n", encoding="ascii")

    def finish(self, *, kill: bool = False, timeout: float = 420.0) -> EnclaveOutput:
        if self.process is not None and self.process.poll() is None:
            if kill:
                self.process.send_signal(signal.SIGKILL)
            else:
                try:
                    self.process.wait(timeout=timeout)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait(timeout=30)
        return self.output


def measure_enclave(ctx: Context) -> dict[str, object]:
    """Run the signed enclave once and read its claims from the DCAP verifier."""
    control = ctx.control_root / "bootstrap"
    control.mkdir(parents=True, exist_ok=True)
    (control / "nonce.hex").write_text(
        secrets.token_bytes(32).hex() + "\n",
        encoding="ascii",
    )
    command = [
        "gramine-sgx",
        "./encfs_worker",
        f"{ctx.repo_guest_dir}/tee/enclave/encfs_worker.py",
        "--control-dir",
        ctx.control_guest_dir,
        "--key-name",
        ctx.key_name,
        "--guest-file",
        f"{ctx.secure_guest_dir}/{ctx.share_name}",
        "--role",
        "P0",
        "--release-id",
        ctx.release_id,
        "--share-epoch",
        str(ctx.share_epoch),
        "--model-version",
        ctx.model_version,
        "--model-manifest-hash",
        ctx.model_manifest_hash,
        "--precision-plan-hash",
        ctx.precision_plan_hash,
        "--release-timeout",
        "1",
    ]
    completed = subprocess.run(
        command,
        cwd=ctx.enclave_dir,
        check=False,
        capture_output=True,
        text=True,
        timeout=600,
    )
    (ctx.out / "bootstrap-quote.txt").write_text(
        completed.stdout + completed.stderr,
        encoding="utf-8",
    )
    quote_path = control / "quote.bin"
    if not quote_path.is_file():
        raise AcceptanceError("the bootstrap run never published a Quote")
    verified = subprocess.run(
        [str(ctx.verifier_bin), "--quote", str(quote_path), "--json"],
        check=False,
        capture_output=True,
        text=True,
    )
    (ctx.out / "enclave-quote-verify.json").write_text(
        verified.stdout,
        encoding="utf-8",
    )
    (ctx.out / "enclave-quote-verify.stderr.txt").write_text(
        verified.stderr,
        encoding="utf-8",
    )
    if verified.returncode != 0:
        raise AcceptanceError(
            "the enclave Quote failed DCAP verification: " + verified.stderr.strip()
        )
    claims = json.loads(verified.stdout)
    claims["quote_bytes"] = quote_path.stat().st_size
    claims["quote_sha256"] = sha256_file(quote_path)
    return claims


def write_policies(ctx: Context, claims: dict[str, object]) -> tuple[Path, Path]:
    """Write the enforced policy and the deliberately wrong-measurement policy."""
    expires_at = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=6)).replace(
        microsecond=0
    ).isoformat()

    def manifest(mrenclave: str) -> dict[str, object]:
        return {
            "release_id": ctx.release_id,
            "mrenclave": mrenclave,
            "mrsigner": str(claims["mrsigner"]),
            "min_isvsvn": int(claims["isvsvn"]),
            "debug_allowed": False,
            "spu_build_hash": str(claims["mrenclave"]),
            "model_version": ctx.model_version,
            "model_manifest_hash": ctx.model_manifest_hash,
            "precision_plan_hash": ctx.precision_plan_hash,
            "expires_at": expires_at,
        }

    good = ctx.kas_dir / "release-policy.json"
    wrong = ctx.kas_dir / "release-policy-wrong-measurement.json"
    write_json(good, {"releases": [manifest(str(claims["mrenclave"]))]})
    write_json(wrong, {"releases": [manifest("00" * 32)]})
    return good, wrong


def start_kas(ctx: Context, policy: Path, port: int, label: str) -> subprocess.Popen:
    stop_kas_port(ctx, port)
    ctx.kas_starts += 1
    env = dict(os.environ)
    env.update(
        {
            "PYTHONPATH": str(ctx.root),
            "KAS_CA_KEY_PATH": str(ctx.kas_dir / "kas-ca-key.pem"),
            "KAS_CA_CERT_PATH": str(ctx.kas_dir / "kas-ca-cert.pem"),
            "KAS_RELEASE_POLICY_PATH": str(policy),
            "KAS_DCAP_VERIFY_BIN": str(ctx.verifier_bin),
            "KAS_TICKET_SIGNING_KEY_PATH": str(ctx.kas_dir / "ticket-signing-key.hex"),
            "KAS_STORAGE_KEY_MASTER_HEX": ctx.storage_master_hex,
            "KAS_HOST": "127.0.0.1",
            "KAS_PORT": str(port),
        }
    )
    log = (ctx.out / f"kas-{label}-{ctx.kas_starts}.log").open("wb")
    process = subprocess.Popen(
        [ctx.python, "-m", "kas"],
        cwd=ctx.root,
        env=env,
        stdout=log,
        stderr=subprocess.STDOUT,
    )
    ctx.kas_processes[port] = process
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(
                f"http://127.0.0.1:{port}/healthz", timeout=2
            ) as response:
                if response.status == 200:
                    return process
        except (urllib.error.URLError, OSError):
            time.sleep(0.3)
    raise AcceptanceError(f"the KAS on port {port} did not become healthy")


def stop_kas_port(ctx: Context, port: int) -> None:
    process = ctx.kas_processes.pop(port, None)
    if process is not None and process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            process.kill()


def stop_kas(ctx: Context) -> None:
    for port in list(ctx.kas_processes):
        process = ctx.kas_processes.pop(port)
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                process.kill()


def _record(ctx: Context, name: str, document: dict[str, object]) -> dict[str, object]:
    ctx.cases[name] = document
    write_json(ctx.out / f"case-{name}.json", document)
    return document


def case_accept(ctx: Context) -> dict[str, object]:
    with EnclaveSession(ctx, "accept-kas-sealed-release", base_url=ctx.good_base_url) as session:
        status, body = session.request_seal()
        record: dict[str, object] = {
            "seal_status": status,
            "key_id": body.get("key_id"),
            "startup_hash": body.get("startup_hash"),
        }
        if status == 200:
            session.deliver(str(body["sealed_bundle_hex"]))
        output = session.finish()
    record["enclave"] = output.fields
    record["enclave_exit_status"] = output.exit_status
    record["enclave_complete"] = output.complete
    return _record(ctx, "accept-kas-sealed-release", record)


def case_missing_sealed(ctx: Context) -> dict[str, object]:
    with EnclaveSession(
        ctx,
        "deny-missing-sealed",
        base_url=ctx.good_base_url,
        release_timeout=3,
    ) as session:
        status, body = session.request_seal()
        # Deliberately never deliver the sealed key.
        output = session.finish()
    record = {
        "seal_status": status,
        "sealed_delivered": False,
        "key_id": body.get("key_id"),
        "enclave": output.fields,
        "enclave_exit_status": output.exit_status,
        "enclave_complete": output.complete,
    }
    return _record(ctx, "deny-missing-sealed", record)


def case_tampered_sealed(ctx: Context) -> dict[str, object]:
    with EnclaveSession(ctx, "deny-tampered-sealed", base_url=ctx.good_base_url) as session:
        status, body = session.request_seal()
        if status == 200:
            session.deliver(str(body["sealed_bundle_hex"]), tamper=True)
        output = session.finish()
    record = {
        "seal_status": status,
        "sealed_delivered": status == 200,
        "tampered": True,
        "enclave": output.fields,
        "enclave_exit_status": output.exit_status,
        "enclave_complete": output.complete,
    }
    return _record(ctx, "deny-tampered-sealed", record)


def case_wrong_epoch(ctx: Context) -> dict[str, object]:
    with EnclaveSession(
        ctx,
        "deny-wrong-epoch",
        base_url=ctx.good_base_url,
        epoch=ctx.share_epoch + 1,
    ) as session:
        # The enclave claims a different epoch than the one the KAS seals.
        status, body = session.request_seal(epoch=ctx.share_epoch)
        if status == 200:
            session.deliver(str(body["sealed_bundle_hex"]))
        output = session.finish()
    record = {
        "seal_status": status,
        "sealed_delivered": status == 200,
        "enclave_claimed_epoch": ctx.share_epoch + 1,
        "enclave": output.fields,
        "enclave_exit_status": output.exit_status,
        "enclave_complete": output.complete,
    }
    return _record(ctx, "deny-wrong-epoch", record)


def case_wrong_startup(ctx: Context) -> dict[str, object]:
    with EnclaveSession(
        ctx,
        "deny-wrong-startup",
        base_url=ctx.good_base_url,
        model_version="unregistered-model",
    ) as session:
        status, body = session.request_seal()
        if status == 200:
            session.deliver(str(body["sealed_bundle_hex"]))
        output = session.finish()
    record = {
        "seal_status": status,
        "sealed_delivered": status == 200,
        "enclave_claimed_model_version": "unregistered-model",
        "enclave": output.fields,
        "enclave_exit_status": output.exit_status,
        "enclave_complete": output.complete,
    }
    return _record(ctx, "deny-wrong-startup", record)


def case_replay_challenge(ctx: Context) -> dict[str, object]:
    with EnclaveSession(ctx, "deny-replay-challenge", base_url=ctx.good_base_url) as session:
        first_status, first_body = session.request_seal()
        second_status, second_body = session.request_seal()
        if first_status == 200:
            session.deliver(str(first_body["sealed_bundle_hex"]))
        output = session.finish()
    record = {
        "first_seal_status": first_status,
        "first_key_id": first_body.get("key_id"),
        "second_seal_status": second_status,
        "second_detail": second_body.get("detail"),
        "enclave": output.fields,
        "enclave_exit_status": output.exit_status,
        "enclave_complete": output.complete,
    }
    return _record(ctx, "deny-replay-challenge", record)


def case_second_seal(ctx: Context) -> dict[str, object]:
    with EnclaveSession(ctx, "deny-second-seal", base_url=ctx.good_base_url) as first:
        first_status, first_body = first.request_seal()
        if first_status == 200:
            first.deliver(str(first_body["sealed_bundle_hex"]))
        with EnclaveSession(
            ctx,
            "deny-second-seal-retry",
            base_url=ctx.good_base_url,
        ) as second:
            second_status, second_body = second.request_seal()
            second.finish(kill=True)
        output = first.finish()
    record = {
        "first_seal_status": first_status,
        "first_key_id": first_body.get("key_id"),
        "second_seal_status": second_status,
        "second_detail": second_body.get("detail"),
        "enclave": output.fields,
        "enclave_exit_status": output.exit_status,
        "enclave_complete": output.complete,
    }
    return _record(ctx, "deny-second-seal", record)


def case_wrong_measurement(ctx: Context) -> dict[str, object]:
    with EnclaveSession(
        ctx,
        "deny-wrong-measurement",
        base_url=ctx.wrong_base_url,
    ) as session:
        status, body = session.request_seal()
        session.finish(kill=True)
    record = {
        "seal_status": status,
        "detail": body.get("detail"),
        "enclave_quote_delivered": bool(session.quote),
    }
    return _record(ctx, "deny-wrong-measurement", record)


CASE_FUNCTIONS = (
    case_accept,
    case_missing_sealed,
    case_tampered_sealed,
    case_wrong_epoch,
    case_wrong_startup,
    case_replay_challenge,
    case_second_seal,
    case_wrong_measurement,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--python", default=sys.executable)
    parser.add_argument("--system-python", default="/usr/bin/python3")
    parser.add_argument("--release-id", required=True)
    parser.add_argument("--share-epoch", type=int, required=True)
    parser.add_argument("--model-version", required=True)
    parser.add_argument("--model-manifest-hash", required=True)
    parser.add_argument("--precision-plan-hash", required=True)
    parser.add_argument("--storage-master-hex", required=True)
    parser.add_argument("--key-name", default="a122_disk")
    parser.add_argument("--share-name", default="model-share-P0.bin")
    parser.add_argument("--kas-port", type=int, default=18443)
    parser.add_argument("--cloud-region", default="cn-shanghai")
    parser.add_argument("--instance-id", default="unknown")
    args = parser.parse_args(argv)

    ctx = Context(
        root=args.root,
        work=args.work,
        out=args.out,
        python=args.python,
        system_python=args.system_python,
        release_id=args.release_id,
        share_epoch=args.share_epoch,
        model_version=args.model_version,
        model_manifest_hash=args.model_manifest_hash,
        precision_plan_hash=args.precision_plan_hash,
        storage_master_hex=args.storage_master_hex,
        kas_dir=args.work / "kas",
        verifier_bin=args.work / "bin" / "a122_dcap_verify",
        enclave_dir=args.work / "enclave",
        control_root=args.work / "control",
        store_dir=args.work / "store",
        share_name=args.share_name,
        key_name=args.key_name,
        repo_guest_dir="/app",
        control_guest_dir="/control",
        secure_guest_dir="/secure",
        kas_port=args.kas_port,
        cloud_region=args.cloud_region,
        instance_id=args.instance_id,
    )
    ctx.control_root.mkdir(parents=True, exist_ok=True)

    try:
        ctx.claims = measure_enclave(ctx)
        good_policy, wrong_policy = write_policies(ctx, ctx.claims)
        start_kas(ctx, good_policy, ctx.kas_port, "good")
        start_kas(ctx, wrong_policy, ctx.kas_port + 1, "wrong-measurement")
        for case in CASE_FUNCTIONS:
            # Each case needs a clean one-release ledger for its node and
            # epoch; deny-second-seal is the case that exercises the ledger.
            if case is not case_wrong_measurement:
                start_kas(ctx, good_policy, ctx.kas_port, "good")
            print(f"==> case {case.__name__}", flush=True)
            case(ctx)
    finally:
        stop_kas(ctx)
        write_json(
            ctx.out / "cases.json",
            {
                "run_id": args.out.parent.name,
                "claims": ctx.claims,
                "cases": ctx.cases,
            },
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
