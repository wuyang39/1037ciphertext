# D4 enclave fail-closed negatives, repeated three times (2026-10-13T09:07Z)

Sealed evidence directory for a repeatability check of the fail-closed half of
D4. Where [../d4-enclave-negs-3host-20261013T052407Z](../d4-enclave-negs-3host-20261013T052407Z)
replayed the four negative cases once inside enclaves, this bundle replays the
same four cases three independent times and gathers the runs side by side, so a
single accidental pass cannot be mistaken for the intended behaviour.

Each repeat is a full three-instance run driven by
`python -m infra.d4_three_hosts negatives --enclave-template ...`, with P0, P1
and P2 on separate instances and every driver and every strict peer inside its
own `gramine-sgx` enclave, at commit `eacb7a6`:

| Repeat | Run id | Started |
| --- | --- | --- |
| run-1 | `d4-enclave-negs-r1-3host-20261013T080442Z` | 08:04:42Z |
| run-2 | `d4-enclave-negs-rp2-3host-20261013T0845Z` | 08:45Z |
| run-3 | `d4-enclave-negs-rp3-3host-20261013T0855Z` | 08:55Z |

| Role | Instance | Private | Public |
| --- | --- | --- | --- |
| P0 | `iZuf6bjvfplpwleemaipwmZ` | `172.27.172.201` | `106.14.207.224` |
| P1 | `iZuf6bd6qnhgtveg5khyf1Z` | `172.27.172.202` | `47.117.34.67` |
| P2 | `iZuf6bd6qnhgtveg5khygdZ` | `172.27.172.203` | `47.116.200.143` |

The conclusions and the limits are in [../../d4-acceptance.md](../../d4-acceptance.md),
section 7.

## What each file says

| File | Content |
| --- | --- |
| `repeatability.json` | The aggregate: one entry per repeat with its case table, refused flags and the three MRENCLAVE values, plus `all_runs_refused` |
| `run-<n>/d4-negatives-summary.json` | That repeat's own machine-readable summary, exactly as the runner sealed it |
| `run-<n>/d4-negatives-plaintext-probes.json` | That repeat's four plaintext probes and whether every listener accepted a TCP connection |
| `run-<n>/d4-enclave-p{0,1,2}-sign.txt` | What each instance's `gramine-sgx-sign` printed during that repeat |
| `evidence-index.json`, `evidence.sha256` | The seal over the directory |

The raw node logs stay in `artifacts/server/` on the operator machine; this
bundle keeps the per-repeat summaries and the sign logs, which are what the
repetition is meant to compare.

## Results

All three repeats refused all four cases. `all_runs_refused` is true and every
repeat has an empty `unexpected_cases`:

| Case | run-1 | run-2 | run-3 |
| --- | --- | --- | --- |
| `wrong-ca` | refused, exit 3 (8.20 s) | refused, exit 3 (8.25 s) | refused, exit 3 (8.16 s) |
| `wrong-san` | refused, exit 3 (8.14 s) | refused, exit 3 (8.16 s) | refused, exit 3 (8.25 s) |
| `no-client-cert` | refused, exit 3 (76.58 s) | refused, exit 3 (78.33 s) | refused, exit 3 (76.25 s) |
| `tls-disabled` | refused, exit 3 (8.19 s) | refused, exit 3 (8.44 s) | refused, exit 3 (8.31 s) |

The refusal text is the same in every repeat: `peer P2 certificate was not
signed by the KAS CA`, `peer P2 certificate SAN does not match its role`, `the
BRPC link could not be established` and `the SPU link must not run without
TLS`. Each repetition starts a fresh enclave per peer, so the per-case time is
an enclave start, not a decision cost.

The plaintext probe connected from P0 to all four listeners on P1/P2 every
time (`all_listeners_connected` is true in all three repeats) and none of them
answered in plaintext (`any_plaintext_service` is false in all three).

## Measurements are stable across repeats, still three per run

Within a repeat the three instances still sign their own trusted tree, so a
repeat reports three MRENCLAVE values. Across the three repeats each instance
reproduces its own value byte for byte:

| Role | MRENCLAVE (identical in run-1, run-2, run-3) |
| --- | --- |
| P0 | `eecd9c8e19832fa4669db81327d51ea9f403885a1de02481d829cd3600034de4` |
| P1 | `83219c425fed157d228973ebcdf18926f07b2797a51744f9092f62fe8efab0fc` |
| P2 | `32880b8a59bbeb61873f991f105bf14a4f1726c0f3657b0a9653c191b5cc49eb` |

So the measurement is reproducible run to run for a fixed tree, which is what
the repetition is there to show. The values still differ between instances
because each instance measures its own checkout and interpreter tree; making
the three agree would need one staged, byte-identical tree on all three, which
this run did not do.

## How the repeats were driven

```bash
python -m infra.d4_three_hosts negatives \
  --cluster deploy/d4-three-hosts.json \
  --out-dir artifacts/server/d4-enclave-negs-r<k>-3host \
  --run-id d4-enclave-negs-r<k>-3host-<timestamp> \
  --ssh-key <key> --ssh-user jiahao --ssh-key-password <pass> \
  --enclave-template tee/gramine/enclave/spu_node.manifest.template
```

Only exit statuses, refusal text, byte counts, measurements and probe outcomes
leave the instances.
