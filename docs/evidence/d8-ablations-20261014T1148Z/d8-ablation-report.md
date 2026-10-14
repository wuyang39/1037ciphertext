# D8 ablation: the same D7 workload under controlled runtime arms

Run `d8-ablations-20261014T1148Z`: arms recorded through 2026-10-14T11:56:48Z, commit `b1f87bae5b9822d704e1b17ca924c7fbebc45bec`.

Every arm is the D7 program, the D7 shares and the D7 geometry. Only
the fixed-point width or the named SPU approximation switches differ,
and nothing is injected into the network, so the arms are compared
under identical conditions.

| arm | what moved | client wall s | vs control | worst max_abs_error | vs control | tokens | token agreement | wire MB (3 hosts) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `baseline` | fxp 18 | 16.247 | 1.0 | 0.06548119270815178 | 1.0 | 3200,3200,3200 | passed | 3760.0 |
| `baseline-repeat` | fxp 18 | 16.185 | 0.9962 | 0.06608011008293602 | 1.0091 | 3200,3200,3200 | passed | 3760.2 |
| `approx-low` | enable_lower_accuracy_rsqrt=True, fxp_div_goldschmidt_iters=1, fxp_exp_iters=2 | 16.395 | 1.0091 | 7.272384400570399 | 111.0607 | 3200,3200,3200 | passed | 3755.8 |
| `fxp-12` | fxp 12 | 16.68 | 1.0267 | 0.9066048637898447 | 13.8453 | 3200,3200,3200 | passed | 3759.9 |

## Per-step latency (ms)

- `baseline` client: 5236.413, 5187.998, 5179.502
  - P0 node: 4682.115, 4705.377, 4721.627
  - P1 node: 4688.719, 4760.64, 4711.839
  - P2 node: 4831.914, 4806.072, 4748.664
- `baseline-repeat` client: 5409.951, 4944.214, 4966.994
  - P0 node: 4855.826, 4456.174, 4507.638
  - P1 node: 4919.989, 4535.752, 4478.39
  - P2 node: 5058.43, 4560.288, 4541.501
- `approx-low` client: 5770.876, 4997.168, 4975.66
  - P0 node: 5308.131, 4515.492, 4510.948
  - P1 node: 5213.248, 4565.245, 4509.474
  - P2 node: 5249.993, 4611.268, 4541.87
- `fxp-12` client: 5910.269, 5045.615, 5079.953
  - P0 node: 5355.827, 4565.162, 4621.741
  - P1 node: 5349.208, 4619.552, 4626.8
  - P2 node: 5534.222, 4662.275, 4627.608

## Per-step fidelity

| arm | step 1 | step 2 | step 3 | worst mean_abs_error |
| --- | --- | --- | --- | --- |
| `baseline` | 0.06548119270815178 | 0.06091278952293777 | 0.06524469138176414 | 0.014617784934217136 |
| `baseline-repeat` | 0.06429863655580803 | 0.06368225973778152 | 0.06608011008293602 | 0.0142674186634539 |
| `approx-low` | 7.164021967714067 | 7.187499550281281 | 7.272384400570399 | 4.20970263153357 |
| `fxp-12` | 0.9066048637898447 | 0.764661113910619 | 0.8401652310972878 | 0.18521292564438316 |

## Did each arm land?

Each node echoes the runtime it opened with on its ready line, and the
client records the one it was built with. An arm whose settings did not
reach all four processes is listed here as a failure rather than
counted as a measurement.

| arm | landed | problems |
| --- | --- | --- |
| `baseline` | `True` | - |
| `baseline-repeat` | `True` | - |
| `approx-low` | `True` | - |
| `fxp-12` | `True` | - |

## Verdicts

| arm | hygiene | shares scrubbed | captures |
| --- | --- | --- | --- |
| `baseline` | clean | clean | tls13_only |
| `baseline-repeat` | clean | clean | tls13_only |
| `approx-low` | clean | clean | tls13_only |
| `fxp-12` | clean | clean | tls13_only |

## What this does not cover

- one run per arm: the spread of a single take is not separated except by the repeated control arm
- the nonlinear arms move the SPU runtime's own approximation switches; an arm that replaces the emitted MHLO operators with a different polynomial is still a second frozen program and is not in this table
- no per-process EPC residency counter exists on this kernel, so the arms are compared on time, traffic and fidelity only
- length buckets and batch size are not exercised by the one-layer probe geometry
