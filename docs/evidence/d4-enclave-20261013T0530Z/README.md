# D4 enclave evidence (2026-10-13T05:30Z)

Sealed evidence directory for the D4 run produced on the instance
`iZuf6bd6qnhgtveg5khygdZ` (private `172.27.172.203`, public `47.116.200.143`,
`cn-shanghai`) from commit `560deff`:

```bash
cd ~/1037ciphertext
PYTHON=~/a122-venv311/bin/python bash deploy/run_d4_gramine.sh \
    d4-enclave-20261013T0530Z
```

This is the same grid and the same refusal cases as
[../d4-20261012T143111Z](../d4-20261012T143111Z), except that P0, P1 and P2 are
each started by `gramine-sgx` from one signed manifest, so all three SPU
parties run inside the LibOS enclave. The measurement the three processes share
is
`b28084fe356bb41100fbb45d0223ec703881334937da9e7568cbcc1e6445e4d4`
(`spu_node-sign.txt` prints it while sealing). The conclusions and the limits
are in [../../d4-acceptance.md](../../d4-acceptance.md).

## What each file says

| File | Content |
| --- | --- |
| `d4-summary.json` | Run summary: verdicts, grid digest, certificate digests, the `inside_enclave` runtime label, capture statistics |
| `d4-enclave-acceptance.txt` | The transcript of the acceptance command |
| `d4-enclave-provision.json` | The provisioning step that built the PKI, the vectors and the three role configs |
| `d4-enclave-env.txt` | Gramine version, interpreter, `libspu.so`, the SGX devices and the manifest parameters |
| `spu_node.manifest`, `spu_node-sign.txt` | The signed manifest's text and the signer's own output, measurement included |
| `tls-summary.txt` | Every TCP flow on the six protocol ports, its TLS records and handshake messages |
| `rss-vectors.json` | The 1,024 vectors: 16 batches of 64, each with the RSS result and the fixed-point reference |
| `communication-trace.json` | Round and byte counts without shares, keys or inputs; carries the runtime label |
| `deny-*.txt`, `case-*.json` | The refusal cases, with the reason each one was rejected |
| `node-status-p{0,1,2}.json` | Per-role link duration, peer certificate digests, teardown state |
| `node-log-p{0,1,2}.txt`, `logs/` | Raw stdout of each node process, including the refused starts |
| `material-ledger.json` | One-time consumption of each role's preprocessing material |
| `p{0,1,2}-cert.pem` | The three public node certificates |
| `evidence-index.json`, `evidence.sha256` | The seal over the directory |

## The runtime label is measured, not assumed

`communication-trace.json` reports
`transport: "SPU/YACL/BRPC over TLS 1.3 inside a Gramine-SGX enclave"` and
`inside_enclave: true`, because `tee/enclave/spu_node.py` asks whether
`/dev/attestation` is readable by the process that runs it. The same three
parties ran as ordinary host processes a day earlier and reported `false` from
the same check ([../d4-20261012T143111Z](../d4-20261012T143111Z)).

The certificates are still this run's local PKI: releasing them from a verified
DCAP Quote is the KAS step that has not been built yet.

## One file was re-sealed after the tail landed

`d4-enclave-acceptance.txt` is the shell's transcript of the acceptance command,
and the runner seals the directory before it prints its verdicts. That transcript
therefore kept growing after the index was written, so this directory was sealed
again when it was pulled back and the index describes the whole file.
`deploy/run_d4_gramine.sh` no longer redirects into the sealed directory: it
writes the transcript next to the bundle and copies it in before a final seal.

## The capture is not in this repository

`tls-pcap.pcap` is 216,779,569 bytes, sha256
`4f770345cae217bce61e109115460936522a9263dfc759c6ca723c5a01ffd2bc`. GitHub
rejects blobs above 100 MB, so the raw capture stays on the instance that
produced it and only its digest and derived summary are committed. The bundle
names it in
[../d4-enclave-20261013T0530Z.exclusions.json](../d4-enclave-20261013T0530Z.exclusions.json),
so this directory holds every indexed file except that one and the seal still
verifies:

```bash
python -c "
from pathlib import Path
from infra.evidence import load_exclusions, verify_directory
root = Path('docs/evidence/d4-enclave-20261013T0530Z')
index = verify_directory(root, exclusions=load_exclusions(root))
print(index['file_count'], index['excluded'])
"
```

An excluded file that is present is still checked against the index, so
restoring the capture can only tighten the result. `tls-summary.txt` is derived
from that capture by `infra/pcap_tls.py`, which reassembles each flow by TCP
sequence number before parsing it, so the TLS-only verdict can be recomputed
from the raw artifact rather than trusted:

```bash
python -m infra.pcap_tls tls-pcap.pcap --d4-ports \
    --probe-endpoint 127.0.0.1:47101 --probe-endpoint 127.0.0.1:47102 \
    --probe-endpoint 127.0.0.1:47201 --probe-endpoint 127.0.0.1:47202 \
    --probe-marker $'A1-22-PLAINTEXT-PROBE\r\n'
```
