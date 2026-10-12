# D4 cross-host evidence (2026-10-12T14:31:39Z)

Sealed evidence directory for the D4 run that put P0, P1 and P2 on three
separate instances at commit `d048827`:

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
in [../d4-3host-20261012T143139Z.exclusions.json](../d4-3host-20261012T143139Z.exclusions.json):

| Capture | Bytes | SHA-256 |
| --- | --- | --- |
| `d4-three-P0.pcap` | 144,791,448 | `4e73cabdb4cd6bdc0cdd597d87bcc326881d0d318457029e1ba09894539f656a` |
| `d4-three-P1.pcap` | 143,211,316 | `557b2b67a5901426a77f11029d47a5c6ebfba23799ca3bf91b0215f3ae159979` |
| `d4-three-P2.pcap` | 143,195,726 | `24d3170021874e747f98d3104e7f5af3ddf4ad0805b4da3544a333509d27e1c1` |

They stay in `/tmp/d4-three-P{0,1,2}.pcap` on their own instance because GitHub
rejects blobs above 100 MB. Each capture is checked against the index if it is
present, so copying one back can only tighten the check:

```bash
python -c "
from pathlib import Path
from infra.evidence import load_exclusions, verify_directory
root = Path('docs/evidence/d4-3host-20261012T143139Z')
index = verify_directory(root, exclusions=load_exclusions(root))
print(index['file_count'], index['excluded'])
"
```

## How the run was driven

The instances have no key to each other, so the operator host provisioned the
workspace on P0, shipped the same tar to P1 and P2 at the same absolute path,
started `tcpdump -i eth0` on all three, then started P1/P2 before P0. Only
byte counts, roles, digests and timings left the hosts. `deploy/run_d4_three_hosts.sh`
is the scripted form of the same sequence.

To re-derive one host's verdict from its capture, run the analyser on that
instance:

```bash
python -m infra.pcap_tls /tmp/d4-three-P0.pcap --d4-ports
```
