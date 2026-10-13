# D4 cross-host enclave evidence (2026-10-13T05:21:21Z)

Sealed evidence directory for the D4 run driven by
[infra/d4_three_hosts.py](../../../infra/d4_three_hosts.py) at commit `63937a0`,
with P0, P1 and P2 on three separate instances and every node process started by
`gramine-sgx`:

| Role | Instance | Private | Public |
| --- | --- | --- | --- |
| P0 | `iZuf6bjvfplpwleemaipwmZ` | `172.27.172.201` | `106.14.207.224` |
| P1 | `iZuf6bd6qnhgtveg5khyf1Z` | `172.27.172.202` | `47.117.34.67` |
| P2 | `iZuf6bd6qnhgtveg5khygdZ` | `172.27.172.203` | `47.116.200.143` |

The three instances were restarted on 2026-10-13 and came back with new elastic
addresses, which is why they differ from the 2026-10-12 run's table. The private
addresses, and therefore the mesh the nodes build, did not change.

Each instance rendered and signed the node manifest after the workspace had
landed on it, then ran its rank as `gramine-sgx <manifest>`, so the SPU/YACL/BRPC
TLS 1.3 traffic crossed the VPC private network from inside three enclaves. The
conclusions and the limits are in [../../d4-acceptance.md](../../d4-acceptance.md).

## What each file says

| File | Content |
| --- | --- |
| `d4-three-summary.json` | Machine-readable summary: roles, grid, runtime label, the enclosure block, per-role capture facts, certificate cross-check |
| `d4-enclave-p{0,1,2}-sign.txt` | What each instance's `gramine-sgx-sign` printed: attributes, memory map, measurement, manifest digests |
| `d4-enclave.manifest` | The rendered manifest. The three instances measured one each; the per-host digests are in the sign logs |
| `d4-three-P{0,1,2}-tls-summary.txt` | One host's own capture, with its digest and size in the header, then the full flow/handshake/session breakdown |
| `d4-three-p{0,1,2}-node-status.json` | Per-role link duration, batches served, identity digest, peer certificate digests, teardown state |
| `d4-three-p{0,1,2}-node.log` | Raw stdout of that instance's node process |
| `d4-three-rss-vectors.json` | The 1,024 vectors P0 drove, with the fixed-point reference |
| `d4-three-communication-trace.json` | Round and byte counts, endpoints, and the runtime label; no shares, keys or inputs |
| `evidence-index.json`, `evidence.sha256` | The seal over the directory |

## The three enclaves are not one measurement

`enclosure.measurements` in the summary lists a measurement per role, and
`shared_measurement` is `false`:

| Role | MRENCLAVE |
| --- | --- |
| P0 | `4726519aaaed3cddc14d702e3bbddcb286928e4a017770873e022a19ba3ed58a` |
| P1 | `1a28fc08a86bbbfbb2314b0caa284b03435d560372d227f6dfd55a1d58c3a61f` |
| P2 | `e398551a9dcde72cf1b41793c94014a86f1b29ab02cbf2206fcc72536e09ebcd` |

Gramine seals whole trusted directories, so a measurement covers its own
instance's checkout, venv, interpreter and workspace. Those trees are equal in
the parts that matter - all three instances were on the same commit with a
clean `git status`, and the runner refuses to start otherwise - but they are not
byte-identical: a checkout that has been fetched a different number of times has
a different `.git`, and an interpreter directory that has been imported from has
different `__pycache__` entries. Three signatures of three real trees is the
honest result; the loopback run shows the same three parties sharing one
measurement when they share one tree
([../d4-enclave-20261013T0530Z](../d4-enclave-20261013T0530Z)).

## The captures are not in this repository

The three captures are indexed but not shipped, so the bundle also names them in
[../d4-enclave-3host-20261013T052121Z.exclusions.json](../d4-enclave-3host-20261013T052121Z.exclusions.json):

| Capture | Bytes | SHA-256 |
| --- | --- | --- |
| `d4-three-P0.pcap` | 145,054,142 | `e20b6898c82b839af3798268210ee357bef3734e1ae714cc5d9aadca1a2ec886` |
| `d4-three-P1.pcap` | 143,475,921 | `0adbfb1e3ea22f09b319151a94ef43dc151ca61cc87d73303c0d77470d7e55a5` |
| `d4-three-P2.pcap` | 143,478,805 | `34a4a61e101c93bc9215a15a9c7854923c23937648a36b24156d3307a7ca9126` |

They stay in `/tmp/d4-enclave-3host-20261013T052121Z-P{0,1,2}.pcap` on their own
instance because GitHub rejects blobs above 100 MB. Each capture is checked
against the index if it is present, so copying one back can only tighten the
check:

```bash
python -c "
from pathlib import Path
from infra.evidence import load_exclusions, verify_directory
root = Path('docs/evidence/d4-enclave-3host-20261013T052121Z')
index = verify_directory(root, exclusions=load_exclusions(root))
print(index['file_count'], index['excluded'])
"
```

## How the run was driven

One command produced the whole bundle, from the operations machine:

```bash
python -m infra.d4_three_hosts run \
    --cluster deploy/d4-three-hosts.json \
    --out-dir docs/evidence/d4-enclave-3host-20261013T052121Z \
    --run-id d4-enclave-3host-20261013T052121Z \
    --ssh-key ~/.ssh/a122_id_sgx \
    --enclave-template tee/gramine/enclave/spu_node.manifest.template
```

`--enclave-template` is what turns a host-process run into an enclave run: after
distributing the workspace the runner renders and signs the manifest on every
instance, generates the signing key once on the driver's host so the three
ranks share a signer, and starts each rank with `gramine-sgx`. Without it the
same command reproduces
[../d4-3host-20261012T152216Z](../d4-3host-20261012T152216Z).
