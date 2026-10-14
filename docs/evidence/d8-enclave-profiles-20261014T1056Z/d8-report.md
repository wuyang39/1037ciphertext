# D8: the D7 workload under a stated network profile

Run `d8-enclave-profiles-20261014T1056Z`: profiles recorded through 2026-10-14T11:12:14Z, commit `df01452ef187a5bcf223dd082afce511508a7579`.

Every figure below is read back from the sealed traces of the runs it
describes: the client's own step timing, the nodes' step reporting, and
each instance's own analysis of the capture it took.

## Profiles

| profile | client wall s | slowdown | wire MB (3 hosts) | retransmits | gaps | tokens | worst max_abs_error | capture verdict |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| lan | 16.534 | 1.0 | 3760.1 | 686 | 0 | 3200,3200,3200 | 0.06548119270815178 | tls13_only |
| wan-40ms | 164.21 | 9.93 | 3760.0 | 274 | 0 | 3200,3200,3200 | 0.06498910666496727 | tls13_only |
| wan-80ms | 274.871 | 16.62 | 3760.0 | 136 | 0 | 3200,3200,3200 | 0.06563760520012352 | tls13_only |

The delay is injected on each instance's egress towards its peers, so a
profile labelled 40 ms measures about 80 ms round trip; the table above
carries that measured round trip next to the injected number. `lan`
injects nothing and the run takes no ping for it, so its row stays
empty: it is the baseline the other two are compared against.

| profile | injected delay per instance (ms) | measured round trip (ms) |
| --- | --- | --- |
| lan | - | - |
| wan-40ms | 40 | 80.16 |
| wan-80ms | 80 | 160.15 |

## Per-step latency (ms)

- `lan` client: 5380.712, 5285.279, 5219.595
  - P0 node: 5001.217, 4797.575, 4760.427
  - P1 node: 4821.503, 4849.526, 4750.519
  - P2 node: 4860.821, 4895.692, 4783.789
- `wan-40ms` client: 56483.73, 52328.255, 53259.576
  - P0 node: 55651.989, 51777.387, 52729.178
  - P1 node: 55354.794, 51698.689, 52604.112
  - P2 node: 55386.909, 51733.955, 52618.781
- `wan-80ms` client: 93980.034, 89053.249, 88083.096
  - P0 node: 92866.986, 88384.29, 87429.214
  - P1 node: 92293.545, 88181.358, 87177.856
  - P2 node: 92488.097, 88218.5, 87198.108

## Host resources

| role | cpu model | vCPU | mem total MB | EPC section | enclave device |
| --- | --- | --- | --- | --- | --- |
| P0 | Intel(R) Xeon(R) Platinum 8369B CPU @ 2.70GHz | 4 | 7523 | EPC section 0x240000000-0x42fffffff | /dev/sgx_enclave |
| P1 | Intel(R) Xeon(R) Platinum 8369B CPU @ 2.70GHz | 4 | 7523 | EPC section 0x240000000-0x42fffffff | /dev/sgx_enclave |
| P2 | Intel(R) Xeon(R) Platinum 8369B CPU @ 2.70GHz | 4 | 7523 | EPC section 0x240000000-0x42fffffff | /dev/sgx_enclave |

| profile | role | samples | cpu mean % | cpu peak % | enclave RSS peak MB | enclave CPU s | mem available min MB |
| --- | --- | --- | --- | --- | --- | --- | --- |
| lan | P0 | 55 | 30.93 | 65.71 | 16 | 49.88 | 6273 |
| lan | P1 | 50 | 28.92 | 65.4 | 17 | 50.22 | 6470 |
| lan | P2 | 46 | 30.87 | 64.53 | 16 | 48.68 | 6500 |
| wan-40ms | P0 | 347 | 7.62 | 33.17 | 16 | 62.52 | 6263 |
| wan-40ms | P1 | 342 | 7.49 | 48.53 | 17 | 67.16 | 6452 |
| wan-40ms | P2 | 337 | 7.66 | 46.08 | 16 | 65.88 | 6477 |
| wan-80ms | P0 | 562 | 5.99 | 35.78 | 16 | 72.81 | 6246 |
| wan-80ms | P1 | 561 | 5.23 | 30.73 | 17 | 71.34 | 6450 |
| wan-80ms | P2 | 557 | 5.1 | 28.64 | 16 | 69.38 | 6469 |

## What this does not cover

- no per-process EPC residency counter: this kernel exposes the EPC section size in its ring buffer but no per-process accounting file, and the run does not invent one
- no on-enclave approximation or quantization ablation: the program D7 froze has no runtime switch for either, so a comparison would need a second frozen program and is left for the next pass
- length buckets and batch size are not exercised by the one-layer probe geometry
- the rate and delay are injected with tc on the peer subnet and reported from the ping the run took, not from a network model
