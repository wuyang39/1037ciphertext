# D4 cross-host evidence (2026-10-12T15:22:16Z)

Sealed evidence directory for the D4 run driven by
[infra/d4_three_hosts.py](../../../infra/d4_three_hosts.py) at commit
`bcd8935`, with P0, P1 and P2 on three separate instances:

| Role | Instance | Private | Public |
| --- | --- | --- | --- |
| P0 | `iZuf6bjvfplpwleemaipwmZ` | `172.27.172.201` | `47.116.200.143` |
| P1 | `iZuf6bd6qnhgtveg5khyf1Z` | `172.27.172.202` | `47.117.34.67` |
| P2 | `iZuf6bd6qnhgtveg5khygdZ` | `172.27.172.203` | `106.15.54.240` |

Every node ran on its own instance, so the SPU/YACL/BRPC TLS 1.3 traffic
crossed the VPC private network instead of loopback, and each host captured its
own leg. The conclusions and the limits are in
[../../d4-acceptance.md](../../d4-acceptance.md).

## What each file says

| File | Content |
| --- | --- |
| `d4-three-summary.json` | Machine-readable summary: roles, grid, runtime label, per-role capture facts, certificate cross-check |
| `d4-three-P{0,1,2}-tls-summary.txt` | One host's own capture, with its digest and size in the header, then the full flow/handshake/session breakdown |
| `d4-three-p{0,1,2}-node-status.json` | Per-role link duration, batches served, identity digest, peer certificate digests, teardown state |
| `d4-three-p{0,1,2}-node.log` | Raw stdout of that instance's node process |
| `d4-three-rss-vectors.json` | The 1,024 vectors P0 drove, with the fixed-point reference |
| `d4-three-communication-trace.json` | Round and byte counts, endpoints, and the runtime label; no shares, keys or inputs |
| `evidence-index.json`, `evidence.sha256` | The seal over the directory |

The three captures are indexed but not shipped, so the bundle also names them
in
[../d4-3host-20261012T152216Z.exclusions.json](../d4-3host-20261012T152216Z.exclusions.json):

| Capture | Bytes | SHA-256 |
| --- | --- | --- |
| `d4-three-P0.pcap` | 144,817,498 | `1d62c96516c56c62bf2881892ae23dd2632efa465b137beb4a09f23ce08120e5` |
| `d4-three-P1.pcap` | 143,226,938 | `6fe69e52756137608bdc43924e3ffc69ca26df7581ffba9041c40ac4a260d549` |
| `d4-three-P2.pcap` | 143,216,390 | `9739bb92af40cc06cc3836023bd6a90fcdf57207fcd8f5417eab0cfd16cff9b8` |

They stay in `/tmp/d4-3host-20261012T152216Z-P{0,1,2}.pcap` on their own
instance because GitHub rejects blobs above 100 MB. Each capture is checked
against the index if it is present, so copying one back can only tighten the
check:

```bash
python -c "
from pathlib import Path
from infra.evidence import load_exclusions, verify_directory
root = Path('docs/evidence/d4-3host-20261012T152216Z')
index = verify_directory(root, exclusions=load_exclusions(root))
print(index['file_count'], index['excluded'])
"
```

## How the run was driven

One command produced the whole bundle:

```bash
python -m infra.d4_three_hosts run \
  --cluster deploy/d4-three-hosts.example.json \
  --out-dir docs/evidence/d4-3host-20261012T152216Z \
  --run-id d4-3host-20261012T152216Z \
  --ssh-key <key> --ssh-user jiahao
```

The instances have no key to each other, so the operator host provisioned the
workspace on P0, shipped the same tar to P1 and P2 at the same absolute path,
checked every instance out at the expected commit, started `tcpdump -i eth0` on
all three, started P1/P2 before P0, waited for the driver's completion marker,
then collected the per-role summaries. `deploy/run_d4_three_hosts.sh` is the
scripted form of the same sequence.

Only byte counts, roles, digests and timings left the hosts.

To re-derive one host's verdict from its capture, run the analyser on that
instance:

```bash
python -m infra.pcap_tls /tmp/d4-3host-20261012T152216Z-P0.pcap --d4-ports
```
