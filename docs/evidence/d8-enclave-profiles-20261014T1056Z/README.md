# D8 network profiles: the D7 workload under stated conditions

Run `d8-enclave-profiles-20261014T1056Z`: profiles recorded through 2026-10-14T11:12:14Z, commit `df01452ef187a5bcf223dd082afce511508a7579`.

## What ran

- Model: `gpt2-1l-cand1028-v1` (model hash `c0394f5002ee79e2a9119d85e44d756dcd8b3aa930934919e2cf7f871df85ad9`)
- Blocks stacked: 1, candidate vocabulary: 1028 ids. The geometry is D7's, unchanged; this bundle measures it, it does not widen it.
- Prompt: `the cipher key is secret`
- Profiles, in order: `lan`, `wan-40ms`, `wan-80ms`
- The delay and the rate are installed with `tc` on each instance's egress towards its peers after the nodes are ready and removed in a `finally`, so a profile labelled 40 ms measures about 80 ms round trip. The round trip the run's own ping measured is reported next to the injected number in `d8-report.md`; a profile whose delay did not appear fails the run instead of appearing in the table.

## Verdicts

| profile | tokens | token agreement | hygiene | shares scrubbed | captures |
| --- | --- | --- | --- | --- | --- |
| lan | 3200,3200,3200 | `True` | clean | clean | tls13_only |
| wan-40ms | 3200,3200,3200 | `True` | clean | clean | tls13_only |
| wan-80ms | 3200,3200,3200 | `True` | clean | clean | tls13_only |

## What this does not cover

- no per-process EPC residency counter: this kernel exposes the EPC section size in its ring buffer but no per-process accounting file, and the run does not invent one
- no on-enclave approximation or quantization ablation: the program D7 froze has no runtime switch for either, so a comparison would need a second frozen program and is left for the next pass
- length buckets and batch size are not exercised by the one-layer probe geometry
- the rate and delay are injected with tc on the peer subnet and reported from the ping the run took, not from a network model
