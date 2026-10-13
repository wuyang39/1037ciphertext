# D4 three-instance enclave run on one staged tree (2026-10-13T17:15Z)

Sealed evidence directory for the run that closes the "three instances, three
measurements" gap in [../../d4-acceptance.md](../../d4-acceptance.md) section 7.
It is the same three-instance positive run as
[../d4-enclave-3host-20261013T052121Z](../d4-enclave-3host-20261013T052121Z) --
P0/P1/P2 on separate instances, every node inside its own `gramine-sgx` enclave,
the 1,024-vector grid, and one `tcpdump` per instance -- except that all three
signed and loaded **one byte-identical staged tree**, so all three report **one
MRENCLAVE** instead of three:

| Role | Instance | Private | Public |
| --- | --- | --- | --- |
| P0 | `iZuf6bjvfplpwleemaipwmZ` | `172.27.172.201` | `106.14.207.224` |
| P1 | `iZuf6bd6qnhgtveg5khyf1Z` | `172.27.172.202` | `47.117.34.67` |
| P2 | `iZuf6bd6qnhgtveg5khygdZ` | `172.27.172.203` | `47.116.200.143` |

The run is at commit `eacb7a6` with the `infra/d4_three_hosts.py` change that
keeps host-side helpers from writing bytecode into the tree a manifest measures.

## What each file says

| File | Content |
| --- | --- |
| `d4-three-summary.json` | Machine-readable summary: grid, per-role capture verdicts, the enclosure block with the three measurements, and the certificate interlock |
| `d4-enclave-p{0,1,2}-sign.txt`, `d4-enclave.manifest` | What each instance's `gramine-sgx-sign` printed and the manifest it signed |
| `d4-three-<role>-tls-summary.txt` | Each instance's own TLS analysis of its own capture |
| `d4-three-p{0,1,2}-node.log`, `d4-three-p{0,1,2}-node-status.json` | The node log and status of each role |
| `d4-three-rss-vectors.json`, `d4-three-communication-trace.json` | The 1,024 vector results and the redacted communication trace |
| `evidence-index.json`, `evidence.sha256` | The seal over the directory |

The raw captures stay on their instances under `/tmp/`; the three
`d4-three-P{0,1,2}.pcap` entries in `<bundle>.exclusions.json` record their size
and digest, and the derived per-instance TLS summaries are committed.

## Results

| 项目 | 结果 |
| --- | --- |
| `rss_vectors` | 1024/1024, grid digest `96b6c83502203292840fd9836f0efbe6f5fe49225aa5b110a6f2b3c27f3695d5` |
| Per-role verdicts | P0 `passed`, P1/P2 `served` 16 batches each |
| Link setup | 5.749 s; share bytes 706252 |
| Runtime | `inside_enclave: true`, `attestation_available: true` |
| Captures | P0/P1/P2 all `tls13_only`, non-TLS payload 0 bytes; TLS 1.3 flows 42 / 23 / 23 |
| Packet counts | 70885 / 70386 / 70280 |
| Certificate interlock | 6/6, `peer_certificates_match: true` |
| Teardown | all three roles `teardown_finished: true` |

## One measurement for the three ranks

| 项目 | 值 |
| --- | --- |
| MRENCLAVE (P0 = P1 = P2) | `8749c1dbba7743fef93dde104a95ae023dbbd76b46631a4f79afc8326d603f77` |
| `spu_node.manifest` sha256 (P0 = P1 = P2) | `f1745b0544859b1b205b7becb2f3e111a4cfa139ce8f07f236921ffcc4e7fa68` |
| `distinct_measurements` | 1 |

## How the staged tree was built

Gramine hashes the whole contents of every trusted directory into the manifest,
so the three instances measure one enclave only when the interpreter, the venv,
the repo and the workspace are the same bytes at the same absolute paths. The
staging used for this run:

1. **Repo.** Each instance produced the tree with
   `git -C ~/1037ciphertext archive HEAD | tar -x -C ~/a122-shared/repo`, which
   is deterministic for a commit and drops the per-host `.git` history. A
   minimal `.git` (HEAD, one ref, `objects/`, `refs/`, `config`) records the
   commit so the runner's commit check still passes.
2. **Venv.** P0 packed `~/a122-venv311` once, and P1/P2 fetched the same tarball
   (236,679,933 bytes) from a transient `python3 -m http.server` on P0's private
   address, so the staged `~/a122-shared/a122-venv311` is the same bytes
   everywhere. The venv relocates cleanly: its `bin/python` is a symlink to the
   shared uv interpreter, and `pyvenv.cfg` moves with it.
3. **Bytecode.** `__pycache__` trees differ between hosts because the bytecode
   header carries the source mtime, and the instances installed the interpreter
   and the wheels at different times. They were purged from the staged repo,
   the staged venv and the uv interpreter tree on all three, and every
   host-side helper (the provision step, the ABI probe inside the signer, the
   pcap analysis and the plaintext probe) now runs with
   `PYTHONDONTWRITEBYTECODE=1` so a run cannot put host-specific bytecode back.
4. **Workspace.** `infra.d4_three_hosts` already provisions it once on P0 and
   carries the tarball to the other two, so it was identical before this change.

After staging, the trees agreed on all three: repo
`82ce36a92bfd7263a7ab5a18c1ca1bd8664bbcb3f6d291ec078f04f13358116d`, venv
`64cdb67c95522a67c501491dbc8643387105dede862bd46ffe1529fcac6b13de`, uv
interpreter tree
`374e148b5b736c61dc3d3099c5f55953aa9f6ebf7d80e658d4f51344172eff2c`.
The staged manifests render byte-for-byte identically before signing, which is
the property this bundle demonstrates.

## How the run was driven

```bash
python -m infra.d4_three_hosts run \
  --cluster <cluster.json> \
  --out-dir artifacts/server/d4-enclave-shared-3host-20261013T1715Z \
  --run-id d4-enclave-shared-3host-20261013T1715Z \
  --ssh-key <key> --ssh-user jiahao --ssh-key-password <pass> \
  --repo ~/a122-shared/repo \
  --python ~/a122-shared/a122-venv311/bin/python \
  --workspace ~/a122-shared/ws/workspace \
  --enclave-dir ~/a122-shared/enclave \
  --expect-commit eacb7a690000af060a6127d620c8c1d692a13700 \
  --enclave-template tee/gramine/enclave/spu_node.manifest.template
```

Only exit statuses, refusal text, byte counts, measurements and probe outcomes
leave the instances.
