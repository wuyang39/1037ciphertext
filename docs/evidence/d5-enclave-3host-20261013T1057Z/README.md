# D5 three-instance enclave run (d5-enclave-3host-20261013T1057Z)

Sealed evidence for the D5 gate: the private Tiny Decoder Transformer
Block, its non-linear operators and their secure Argmax evaluated by
P0/P1/P2 on three separate instances with every node inside its own
`gramine-sgx` enclave.

| Role | Instance | Private | Public |
| --- | --- | --- | --- |
| P0 | `iZuf6bjvfplpwleemaipwmZ` | `172.27.172.201` | `106.14.207.224` |
| P1 | `iZuf6bd6qnhgtveg5khyf1Z` | `172.27.172.202` | `47.117.34.67` |
| P2 | `iZuf6bd6qnhgtveg5khygdZ` | `172.27.172.203` | `47.116.200.143` |

The run is at commit `4f17822bbf8ef9a57a0e56ae5d56a1f364f3a3ae`.

## What each file says

| File | Content |
| --- | --- |
| `d5-summary.json` | Machine-readable summary: roles, block geometry, per-program errors, the enclosure block and the capture digests |
| `d5-operator-errors.json` | The per-program and per-run error table the operator machine read back from P0 |
| `d5-case-results.json` | One record per case: max/mean/relative error, overflow count, tolerance, verdict, peer RTTs and TLS version |
| `d5-communication-trace.json` | Per-case elapsed milliseconds and share bytes, the link settings, and the attestation facts |
| `d5-reveal-scan.json` | The production-reveal scan each of the three trees was checked against |
| `d5-enclave-p{0,1,2}-sign.txt`, `d5-enclave.manifest` | What each instance's `gramine-sgx-sign` printed and the manifest it signed |
| `d5-three-<role>-tls-summary.txt` | Each instance's own TLS analysis of its own capture |
| `d5-three-p{0,1,2}-node.log`, `d5-three-p{0,1,2}-node-status.json` | The node log and status of each role |
| `evidence-index.json`, `evidence.sha256` | The seal over the directory |

The raw captures stay on their instances under `/tmp/`; the three
`d5-three-P{0,1,2}.pcap` entries in `<bundle>.exclusions.json` record
their size and digest, and the per-instance TLS summaries are
committed.

## Results

| Item | Result |
| --- | --- |
| Cases | 38 total, 38 passed, 0 failed |
| Verdict | `passed` |
| Grid digest | `0dca84b60da01202269696d1de25bdfa1617155c28e3df881b93a61d6c8eea8d` |
| `argmax` | 8/8 passed, max_abs_error 0, overflow_count 0 |
| `block` | 9/9 passed, max_abs_error 0.000703752, overflow_count 0 |
| `gelu` | 6/6 passed, max_abs_error 0.0536346, overflow_count 0 |
| `layernorm` | 7/7 passed, max_abs_error 0.00109047, overflow_count 0 |
| `softmax` | 8/8 passed, max_abs_error 0.00255688, overflow_count 0 |

Every tolerance the cases were judged against is carried in
`d5-case-results.json`; the two-sided budget of the GELU tail is in its
`tail_error_per_input` and `approximation_error` fields.

## Runtime

| Item | Value |
| --- | --- |
| `inside_enclave` | `True` |
| `attestation_available` | `True` |
| Link setup | 5.313 s, share bytes 272494 |
| Cases traced | 38 |
| Peer certificates match | `True` |
| Certificate mismatches | 0 |

## Enclosure

| Role | MRENCLAVE | `d5_node.manifest` sha256 |
| --- | --- | --- |
| P0 | `83d40e4435dba334f9075b9cc0baa65e504062c1bf266e86140489853ff050eb` | `b5a3d0d2f0990cff0942ca9485b272cfdf932d7c1b80f4950d5485835a258085` |
| P1 | `c784b44dacf4977af3cf0e00f89275b0496c3a95f1baab08457922126e0e260a` | `9f965688c696aae3aff7826d742c860d3922353958465c7d585183f5fe93d3b9` |
| P2 | `3b7014bbe088501d90a0e159faf243a24f3dc57538c33f2aabf3f51984bf34d0` | `38c28aee25da210dbd035d0a35106c48aed9e679ab469054331d9a4fee66745e` |

`distinct_measurements`: 3.
Each instance signed the tree it really loaded, so the driver's
default run measures three trees rather than pretending they are one;
`infra/d4_three_hosts.py` is what stages a byte-identical tree across
the three instances when a single shared measurement is the point.

| Item | Value |
| --- | --- |
| `sgx.enclave_size` | 4G |
| `sgx.max_threads` | 64 |
| `sys.stack.size` | 2M |
| Template | `spu_node.manifest.template` |
| Launcher | `gramine-sgx /home/jiahao/a122-enclave/d5-enclave-3host-20261013T1057Z/d5_node` |

## Reveal scan

| Role | Verdict | Findings | Allowlisted hits |
| --- | --- | --- | --- |
| P0 | `clean` | 0 | 34 |
| P1 | `clean` | 0 | 34 |
| P2 | `clean` | 0 | 34 |

The scan runs on every instance against the tree that instance signed,
so a plaintext reveal left in the production path on any one of them
fails the run instead of being sealed as a footnote.

## Captures

| Role | Bytes | SHA-256 |
| --- | --- | --- |
| P0 | 51710490 | `04c6c4f9df57de5eaf076732dfa3733255aa174b748889645a91fa97e5499b86` |
| P1 | 51353714 | `724e53c8da338944d33f34a7970a37423cd640a05efb2330ba4f257b98452bfd` |
| P2 | 51356458 | `11eb0c2fd378c7cefda2874ff990623bc063442b3821266bb68f46d5cb0f20a0` |
