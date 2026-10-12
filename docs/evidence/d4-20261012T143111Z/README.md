# D4 acceptance evidence (2026-10-12T14:31:11Z)

Sealed evidence directory for the D4 run produced on SGX2
(`iZuf6bd6qnhgtveg5khyf1Z`, `cn-shanghai`) from commit `d048827`:

```bash
cd ~/1037ciphertext
PYTHON=~/a122-venv311/bin/python bash deploy/run_d4_accept.sh
```

The run places P0/P1/P2 on one host as three separate processes that speak the
real SPU 0.9.5 / YACL / BRPC stack over TLS 1.3, drives 1,024 grid vectors from
P0, runs every refusal case, and captures the loopback traffic. The conclusions
and the limits of this run are in [../../d4-acceptance.md](../../d4-acceptance.md).

## What each file says

| File | Content |
| --- | --- |
| `d4-summary.json` | Run summary: verdicts, grid digest, certificate digests, capture statistics |
| `tls-summary.txt` | Every TCP flow on the six protocol ports, its TLS records and handshake messages |
| `rss-vectors.json` | The 1,024 vectors: 16 batches of 64, each with the RSS result and the fixed-point reference |
| `communication-trace.json` | Round and byte counts without shares, keys or inputs; carries the runtime label |
| `deny-*.txt` | The five refusal cases, with the reason each one was rejected |
| `case-*.json` | The same four refusal cases as machine-readable verdicts |
| `node-status-p{0,1,2}.json` | Per-role link duration, peer certificate digests, teardown state |
| `node-log-p{0,1,2}.txt` | Raw stdout of each node process, including every batch line |
| `material-ledger.json` | One-time consumption of each role's preprocessing material |
| `p{0,1,2}-cert.pem` | The three public node certificates |
| `logs/` | Raw stdout of every node process, including the refused starts |
| `evidence-index.json`, `evidence.sha256` | The seal over the directory |

## The runtime label is measured, not assumed

`communication-trace.json` reports
`transport: "SPU/YACL/BRPC over TLS 1.3 in a host process"` and
`inside_enclave: false`, because `tee/enclave/spu_node.py` asks whether
`/dev/attestation` exists on the host that runs it. On this instance it does
not, so the run does not claim to have executed inside an enclave.

## The capture is not in this repository

`tls-pcap.pcap` is 216,264,133 bytes, sha256
`f0b06cbcb38bd7afe92ec466d0b1c318bf8ee16e93f314414f508d2ef114fbd5`. GitHub
rejects blobs above 100 MB, so the raw capture stays on the instance that
produced it and only its digest and derived summary are committed. The bundle
names it in
[../d4-20261012T143111Z.exclusions.json](../d4-20261012T143111Z.exclusions.json),
so this directory holds every indexed file except that one and the seal still
verifies:

```bash
python -c "
from pathlib import Path
from infra.evidence import load_exclusions, verify_directory
root = Path('docs/evidence/d4-20261012T143111Z')
index = verify_directory(root, exclusions=load_exclusions(root))
print(index['file_count'], index['excluded'])
"
```

Copy the capture back next to the other files to re-verify the whole seal:

```bash
scp jiahao@47.117.34.67:/home/jiahao/1037ciphertext/artifacts/server/d4-20261012T143111Z/d4/tls-pcap.pcap .
cd docs/evidence/d4-20261012T143111Z && sha256sum -c evidence.sha256
```

An excluded file that is present is still checked against the index, so
restoring the capture can only tighten the result.

`tls-summary.txt` is derived from that capture by `infra/pcap_tls.py`, so the
TLS-only verdict can be recomputed from the raw artifact rather than trusted:

```bash
python -m infra.pcap_tls tls-pcap.pcap --d4-ports \
    --probe-endpoint 127.0.0.1:47101 --probe-endpoint 127.0.0.1:47102 \
    --probe-endpoint 127.0.0.1:47201 --probe-endpoint 127.0.0.1:47202 \
    --probe-marker $'A1-22-PLAINTEXT-PROBE\r\n'
```
