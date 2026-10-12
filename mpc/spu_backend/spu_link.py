"""Real SPU (YACL/BRPC) link construction and share transport.

D4 replaces the policy-only mock channel with the shipping SecretFlow-SPU
runtime: the wheel bundles ``libspu.so`` (YACL + BRPC + OpenSSL), and the Python
binding exposes ``link.create_brpc`` together with the client/server SSL
options. This module owns

* loading ``libspu`` without importing JAX (the enclave mounts the extension
  directly, so the LibOS does not need the JAX dependency tree),
* the fail-closed policy gate that runs before a link may be created,
* the MHLO program, runtime config, and per-party share encoding, and
* the small node runtime that the enclave process drives.

Everything here refuses to degrade silently: a missing certificate, a peer SAN
that does not match its role, a disabled TLS context, or a TLS version below
1.3 raises before any socket is opened.
"""

from __future__ import annotations

import base64
import datetime as dt
import importlib
import importlib.machinery
import importlib.util
import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from mpc.spu_backend.spu_ops import (
    FXP_FRACTION_BITS,
    SPU_OPERATORS,
    build_program,
)


MIN_TLS_VERSION = "TLS1.3"
SERVER_VERIFY_DEPTH = 4
CLIENT_VERIFY_DEPTH = 4
"""BRPC treats a negative verify depth as "do not check the peer certificate".

The D4 link therefore always uses a non-negative depth on both sides: a peer
that presents no certificate, or one that does not chain to the KAS CA, is
rejected during the TLS handshake instead of being allowed in.
"""


class SpuBackendError(RuntimeError):
    """The SPU backend is unavailable or violated its security policy."""


def _cache_extension(name: str, path: Path) -> Any:
    existing = sys.modules.get(name)
    if existing is not None:
        return existing
    loader = importlib.machinery.ExtensionFileLoader(name, str(path))
    spec = importlib.util.spec_from_loader(name, loader)
    if spec is None:  # pragma: no cover - defensive
        raise SpuBackendError(f"cannot build an import spec for {path}")
    module = importlib.util.module_from_spec(spec)
    # pybind modules register their submodules (``link``) while executing, so
    # the parent has to be visible in sys.modules first.
    sys.modules[name] = module
    loader.exec_module(module)
    return module


def discover_libspu_path() -> Path:
    """Locate the bundled ``libspu.so`` without importing the ``spu`` package."""
    override = os.environ.get("A122_LIBSPU_PATH")
    if override:
        path = Path(override)
        if not path.is_file():
            raise SpuBackendError(f"A122_LIBSPU_PATH does not exist: {path}")
        return path
    try:
        spec = importlib.util.find_spec("spu")
    except (ImportError, ValueError) as exc:  # pragma: no cover - defensive
        raise SpuBackendError("the spu package is not installed") from exc
    if spec is None or spec.origin is None:
        raise SpuBackendError(
            "the spu package is not installed; D4 needs SecretFlow-SPU 0.9.5"
        )
    path = Path(spec.origin).parent / "libspu.so"
    if not path.is_file():
        raise SpuBackendError(f"the spu package has no libspu.so at {path}")
    return path


def load_libspu(libspu_path: str | Path | None = None) -> tuple[Any, Any]:
    """Return ``(libspu, libspu.link)`` without pulling in JAX."""
    path = Path(libspu_path) if libspu_path is not None else discover_libspu_path()
    module = _cache_extension("libspu", path)
    link = importlib.import_module("libspu.link")
    if not hasattr(module, "RuntimeWrapper") or not hasattr(link, "create_brpc"):
        raise SpuBackendError(
            "the loaded libspu has no RuntimeWrapper/create_brpc; "
            "D4 requires SecretFlow-SPU 0.9.5"
        )
    return module, link


@dataclass(frozen=True)
class SpuEndpoint:
    """One SPU party and the address its BRPC listener binds."""

    role: str
    host: str
    port: int

    def __post_init__(self) -> None:
        if self.role not in {"P0", "P1", "P2"}:
            raise SpuBackendError("SPU endpoint role must be P0, P1, or P2")
        if not self.host:
            raise SpuBackendError("SPU endpoint host must not be empty")
        if not 1 <= self.port <= 65535:
            raise SpuBackendError("SPU endpoint port is out of range")

    @property
    def address(self) -> str:
        return f"{self.host}:{self.port}"

    @property
    def san(self) -> str:
        return f"spiffe://a122/{self.role}"

    def to_dict(self) -> dict[str, Any]:
        return {"role": self.role, "host": self.host, "port": self.port}


@dataclass(frozen=True)
class NodeIdentity:
    """The certificate material one node keeps inside its enclave."""

    role: str
    certificate_path: Path
    private_key_path: Path
    ca_bundle_path: Path


@dataclass(frozen=True)
class SpuLinkPolicy:
    """Fail-closed policy for one SPU link."""

    role: str
    endpoints: tuple[SpuEndpoint, ...]
    min_version: str = MIN_TLS_VERSION
    require_client_certificate: bool = True
    enable_ssl: bool = True
    allow_brpc_builtin_services: bool = False
    server_verify_depth: int = SERVER_VERIFY_DEPTH
    client_verify_depth: int = CLIENT_VERIFY_DEPTH
    partition_id: str = "a122-d4"
    connect_retry_times: int = 120
    connect_retry_interval_ms: int = 500

    def __post_init__(self) -> None:
        if self.role not in {"P0", "P1", "P2"}:
            raise SpuBackendError("SPU role must be P0, P1, or P2")
        if [endpoint.role for endpoint in self.endpoints] != ["P0", "P1", "P2"]:
            raise SpuBackendError("D4 requires the ordered P0/P1/P2 topology")
        if self.min_version != MIN_TLS_VERSION:
            raise SpuBackendError("TLS versions below 1.3 are forbidden")
        if not self.require_client_certificate:
            raise SpuBackendError("client certificates are mandatory")
        if not self.enable_ssl:
            raise SpuBackendError("the SPU link must not run without TLS")
        if self.allow_brpc_builtin_services:
            raise SpuBackendError("BRPC builtin services must remain disabled")
        if self.server_verify_depth < 0 or self.client_verify_depth < 0:
            raise SpuBackendError(
                "a negative verify depth disables peer certificate checks"
            )
        if not self.partition_id:
            raise SpuBackendError("the SPU partition id must not be empty")
        if self.connect_retry_times < 1:
            raise SpuBackendError("the link needs at least one connect attempt")
        if self.connect_retry_interval_ms < 1:
            raise SpuBackendError("the connect retry interval must be positive")

    @property
    def rank(self) -> int:
        for index, endpoint in enumerate(self.endpoints):
            if endpoint.role == self.role:
                return index
        raise SpuBackendError("the local role is not part of the topology")

    @property
    def peer_roles(self) -> tuple[str, ...]:
        return tuple(
            endpoint.role for endpoint in self.endpoints if endpoint.role != self.role
        )

    def peer_sans(self) -> tuple[str, ...]:
        return tuple(f"spiffe://a122/{role}" for role in self.peer_roles)

    def to_dict(self) -> dict[str, Any]:
        return {
            "partition_id": self.partition_id,
            "role": self.role,
            "rank": self.rank,
            "endpoints": [endpoint.to_dict() for endpoint in self.endpoints],
            "min_version": self.min_version,
            "require_client_certificate": self.require_client_certificate,
            "enable_ssl": self.enable_ssl,
            "allow_brpc_builtin_services": self.allow_brpc_builtin_services,
            "server_verify_depth": self.server_verify_depth,
            "client_verify_depth": self.client_verify_depth,
            "connect_retry_times": self.connect_retry_times,
            "connect_retry_interval_ms": self.connect_retry_interval_ms,
        }


def _load_certificate(path: Path) -> Any:
    from cryptography import x509

    try:
        return x509.load_pem_x509_certificate(Path(path).read_bytes())
    except (OSError, ValueError) as exc:
        raise SpuBackendError(f"certificate is not valid PEM: {path}") from exc


def certificate_role(certificate: Any) -> str:
    """Return the A1-22 role encoded in a certificate SAN."""
    from cryptography import x509

    try:
        san = certificate.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value
    except x509.ExtensionNotFound as exc:
        raise SpuBackendError("node certificate has no SAN extension") from exc
    for uri in san.get_values_for_type(x509.UniformResourceIdentifier):
        if isinstance(uri, str) and uri.startswith("spiffe://a122/"):
            return uri.rsplit("/", 1)[-1]
    raise SpuBackendError("node certificate has no A1-22 SPIFFE SAN")


def certificate_fingerprint(certificate: Any) -> str:
    from cryptography.hazmat.primitives import hashes

    return certificate.fingerprint(hashes.SHA256()).hex()


def verify_peer_certificates(
    policy: SpuLinkPolicy,
    peer_certificates: Mapping[str, Path],
    *,
    ca_bundle_path: Path,
    now: dt.datetime | None = None,
) -> dict[str, str]:
    """Fail closed unless every peer certificate is a valid, role-bound leaf.

    The gate rejects a peer whose certificate does not chain to the configured
    CA, is outside its validity window, or carries a SAN for another role. It
    runs before the link is created so a wrong certificate can never be trusted
    by the runtime.
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

    current = (now or dt.datetime.now(dt.timezone.utc)).astimezone(dt.timezone.utc)
    ca = _load_certificate(ca_bundle_path)
    try:
        basic = ca.extensions.get_extension_for_class(x509.BasicConstraints).value
    except x509.ExtensionNotFound as exc:
        raise SpuBackendError("the configured CA bundle is not a CA") from exc
    if not basic.ca:
        raise SpuBackendError("the configured CA bundle is not a CA")

    fingerprints: dict[str, str] = {}
    for role in policy.peer_roles:
        path = peer_certificates.get(role)
        if path is None:
            raise SpuBackendError(f"no certificate provisioned for peer {role}")
        leaf = _load_certificate(path)
        expected_san = f"spiffe://a122/{role}"
        if expected_san not in [
            uri
            for uri in leaf.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            ).value.get_values_for_type(x509.UniformResourceIdentifier)
        ]:
            raise SpuBackendError(
                f"peer {role} certificate SAN does not match its role"
            )
        not_before = leaf.not_valid_before_utc
        not_after = leaf.not_valid_after_utc
        if not not_before <= current <= not_after:
            raise SpuBackendError(f"peer {role} certificate is outside its window")
        ca_public = ca.public_key()
        try:
            if isinstance(ca_public, ec.EllipticCurvePublicKey):
                ca_public.verify(
                    leaf.signature,
                    leaf.tbs_certificate_bytes,
                    ec.ECDSA(leaf.signature_hash_algorithm),
                )
            elif isinstance(ca_public, rsa.RSAPublicKey):
                ca_public.verify(
                    leaf.signature,
                    leaf.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    leaf.signature_hash_algorithm,
                )
            else:
                raise SpuBackendError("unsupported KAS CA key algorithm")
        except SpuBackendError:
            raise
        except Exception as exc:
            raise SpuBackendError(
                f"peer {role} certificate was not signed by the KAS CA"
            ) from exc
        fingerprints[role] = certificate_fingerprint(leaf)
    return fingerprints


def verify_local_identity(
    policy: SpuLinkPolicy,
    identity: NodeIdentity,
) -> dict[str, str]:
    """Fail closed unless the local identity matches the configured role."""
    leaf = _load_certificate(identity.certificate_path)
    san_role = certificate_role(leaf)
    if san_role != identity.role or identity.role != policy.role:
        raise SpuBackendError(
            "the local certificate SAN does not match the configured role"
        )
    fingerprint = certificate_fingerprint(leaf)
    for path in (identity.private_key_path, identity.ca_bundle_path):
        if not Path(path).is_file():
            raise SpuBackendError(f"identity material is missing: {path}")
    return {"role": identity.role, "sha256": fingerprint}


def build_link_desc(
    libspu: Any,
    *,
    policy: SpuLinkPolicy,
    identity: NodeIdentity,
    present_client_certificate: bool = True,
) -> Any:
    """Create the BRPC link descriptor with the required TLS settings.

    ``present_client_certificate`` exists only so the acceptance can run the
    "no client certificate" negative case: the local side stops proving its
    identity while the peers keep a non-negative verify depth. A correctly
    configured peer must fail that handshake.
    """
    link = importlib.import_module("libspu.link")
    desc = link.Desc()
    desc.id = policy.partition_id
    desc.connect_retry_times = policy.connect_retry_times
    desc.connect_retry_interval_ms = policy.connect_retry_interval_ms
    for endpoint in policy.endpoints:
        desc.add_party(endpoint.role, endpoint.address)
    desc.enable_ssl = True
    certificate = str(identity.certificate_path)
    private_key = str(identity.private_key_path)
    ca_bundle = str(identity.ca_bundle_path)
    desc.server_ssl_opts.cert.certificate_path = certificate
    desc.server_ssl_opts.cert.private_key_path = private_key
    desc.server_ssl_opts.verify.ca_file_path = ca_bundle
    desc.server_ssl_opts.verify.verify_depth = policy.server_verify_depth
    desc.client_ssl_opts.verify.ca_file_path = ca_bundle
    desc.client_ssl_opts.verify.verify_depth = policy.client_verify_depth
    if present_client_certificate:
        desc.client_ssl_opts.cert.certificate_path = certificate
        desc.client_ssl_opts.cert.private_key_path = private_key
    return desc


def create_link(libspu: Any, desc: Any, rank: int) -> Any:
    """Open the BRPC link for one party (this call also binds the listener)."""
    link = importlib.import_module("libspu.link")
    try:
        return link.create_brpc(desc, rank)
    except Exception as exc:  # pragma: no cover - exercised on the servers
        raise SpuBackendError(f"the BRPC link could not be established: {exc}") from exc


def runtime_config(
    libspu: Any,
    *,
    fraction_bits: int = FXP_FRACTION_BITS,
    protocol: str = "SEMI2K",
    field: str = "FM64",
) -> Any:
    """Build the fixed-point runtime configuration used by every D4 run."""
    if protocol != "SEMI2K":
        raise SpuBackendError("D4 pins the semi-honest SEMI2K protocol")
    if field != "FM64":
        raise SpuBackendError("D4 pins the FM64 fixed-point field")
    return libspu.RuntimeConfig(
        protocol=libspu.ProtocolKind.SEMI2K,
        field=libspu.FieldType.FM64,
        fxp_fraction_bits=fraction_bits,
    )


def compile_program(
    libspu: Any,
    *,
    batch: int,
    rows: int,
    cols: int,
    ir_type: str = "STABLEHLO",
) -> bytes:
    """Compile the six-operator MHLO program into SPU bytecode."""
    source_ir = getattr(libspu, ir_type, None)
    if source_ir is None:
        raise SpuBackendError(f"libspu does not expose the {ir_type} IR type")
    text = build_program(batch, rows, cols)
    source = libspu.CompilationSource(
        ir_type=source_ir,
        ir_txt=text.encode("utf-8"),
        input_visibility=[libspu.VIS_SECRET, libspu.VIS_SECRET],
    )
    try:
        return libspu.compile(source, libspu.CompilerOptions())
    except Exception as exc:
        raise SpuBackendError(f"the SPU compiler rejected the D4 program: {exc}") from exc


def make_executable(libspu: Any, code: bytes) -> Any:
    return libspu.Executable(
        name="a122_d4",
        input_names=["x", "y"],
        output_names=list(SPU_OPERATORS),
        code=code,
    )


def make_io(libspu: Any, config: Any) -> Any:
    return libspu.IoWrapper(3, config)


def encode_share(share: Any) -> str:
    """Encode one SPU share for transport over the mTLS share channel."""
    return json.dumps(
        {
            "meta": base64.b64encode(share.meta).decode("ascii"),
            "chunks": [
                base64.b64encode(chunk).decode("ascii") for chunk in share.share_chunks
            ],
        },
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    )


def decode_share(libspu: Any, payload: str | bytes) -> Any:
    try:
        document = json.loads(payload)
        share = libspu.Share()
        share.meta = base64.b64decode(document["meta"], validate=True)
        share.share_chunks = [
            base64.b64decode(chunk, validate=True) for chunk in document["chunks"]
        ]
    except (KeyError, TypeError, ValueError) as exc:
        raise SpuBackendError("a transported share is malformed") from exc
    return share


class SpuNodeRuntime:
    """One enclave-side SPU runtime: link, compiler output, and IO helper."""

    def __init__(
        self,
        *,
        libspu: Any,
        policy: SpuLinkPolicy,
        identity: NodeIdentity,
        batch: int,
        rows: int,
        cols: int,
        fraction_bits: int = FXP_FRACTION_BITS,
        executor: Any | None = None,
        present_client_certificate: bool = True,
    ) -> None:
        self.policy = policy
        self.identity = identity
        self.batch = batch
        self.rows = rows
        self.cols = cols
        self.libspu = libspu
        self.present_client_certificate = present_client_certificate
        self.identity_fingerprint = verify_local_identity(policy, identity)
        self.config = runtime_config(libspu, fraction_bits=fraction_bits)
        self.io = make_io(libspu, self.config)
        self.code = compile_program(libspu, batch=batch, rows=rows, cols=cols)
        self.executable = make_executable(libspu, self.code)
        self._executor = executor
        self._runtime: Any | None = None

    def start(self) -> Any:
        """Create the BRPC link and the SPU runtime slice."""
        desc = build_link_desc(
            self.libspu,
            policy=self.policy,
            identity=self.identity,
            present_client_certificate=self.present_client_certificate,
        )
        context = create_link(self.libspu, desc, self.policy.rank)
        self._runtime = self.libspu.RuntimeWrapper(context, self.config)
        self._executor = context
        return context

    @property
    def context(self) -> Any:
        if self._executor is None:
            raise SpuBackendError("the SPU link has not been started")
        return self._executor

    def run(self, *, x_share: Any, y_share: Any) -> dict[str, Any]:
        if self._runtime is None:
            raise SpuBackendError("the SPU runtime has not been started")
        self._runtime.SetVar("x", x_share)
        self._runtime.SetVar("y", y_share)
        self._runtime.Run(self.executable)
        return {name: self._runtime.GetVar(name) for name in SPU_OPERATORS}

    def barrier(self) -> None:
        self.context.barrier()

    def stop(self) -> None:
        # The barrier and the link stop are collective: they only complete once
        # the other parties arrive too, which is why the node tells its peers
        # the grid is over before it calls this. A peer that has already left
        # turns the barrier into a bounded retry storm, so a failure there is
        # logged and the local teardown still runs.
        with_barrier = getattr(self.context, "barrier", None)
        if with_barrier is not None:
            try:
                with_barrier()
            except Exception:  # pragma: no cover - peer left early
                pass
        stop = getattr(self.context, "stop_link", None)
        if stop is not None:
            try:
                stop()
            except Exception:
                # A peer that already left makes the final link teardown
                # noisy; the grid is finished by then, so the error is not
                # allowed to change the verdict.
                pass


def split_inputs(
    libspu: Any,
    io: Any,
    *,
    x: Any,
    y: Any,
) -> tuple[Sequence[Any], Sequence[Any]]:
    """Split both secrets into one share per party (the data-owner step)."""
    try:
        x_shares = io.MakeShares(x, int(libspu.VIS_SECRET))
        y_shares = io.MakeShares(y, int(libspu.VIS_SECRET))
    except Exception as exc:  # pragma: no cover - server side
        raise SpuBackendError(f"the input shares could not be produced: {exc}") from exc
    if len(x_shares) != 3 or len(y_shares) != 3:
        raise SpuBackendError("SPU returned an unexpected number of shares")
    return x_shares, y_shares


def reconstruct(libspu: Any, io: Any, shares: Sequence[Any]) -> Any:
    try:
        return io.Reconstruct(list(shares))
    except Exception as exc:  # pragma: no cover - server side
        raise SpuBackendError(f"the output shares could not be reconstructed: {exc}") from exc


__all__ = [
    "CLIENT_VERIFY_DEPTH",
    "MIN_TLS_VERSION",
    "SERVER_VERIFY_DEPTH",
    "NodeIdentity",
    "SpuBackendError",
    "SpuEndpoint",
    "SpuLinkPolicy",
    "SpuNodeRuntime",
    "build_link_desc",
    "certificate_fingerprint",
    "certificate_role",
    "compile_program",
    "create_link",
    "decode_share",
    "discover_libspu_path",
    "encode_share",
    "load_libspu",
    "make_executable",
    "make_io",
    "reconstruct",
    "runtime_config",
    "split_inputs",
    "verify_local_identity",
    "verify_peer_certificates",
]
