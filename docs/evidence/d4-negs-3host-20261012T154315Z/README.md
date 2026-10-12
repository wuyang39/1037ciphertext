# D4 cross-host fail-closed evidence (2026-10-12T15:43:15Z)

Sealed evidence directory for the fail-closed half of D4, driven by
`python -m infra.d4_three_hosts negatives` at commit `a2d8026`. The peers ran
strict on their own instances while the driver ran a mutated configuration on
P0, so every refusal below happened across the VPC, not on loopback:

| Role | Instance | Private | Public |
| --- | --- | --- | --- |
| P0 | `iZuf6bjvfplpwleemaipwmZ` | `172.27.172.201` | `47.116.200.143` |
| P1 | `iZuf6bd6qnhgtveg5khyf1Z` | `172.27.172.202` | `47.117.34.67` |
| P2 | `iZuf6bd6qnhgtveg5khygdZ` | `172.27.172.203` | `106.15.54.240` |

The workspace is the one provisioned by run `d4-3host-20261012T152216Z` and it
is byte-identical on all three instances; nothing was re-provisioned. The
conclusions and the limits are in [../../d4-acceptance.md](../../d4-acceptance.md).

## What each file says

| File | Content |
| --- | --- |
| `d4-negatives-summary.json` | Machine-readable summary: every case with its expected reason, exit status, duration, refusal line, and the plaintext probe result |
| `d4-negatives-plaintext-probes.json` | The four plaintext probes, their outcomes, and whether every listener really accepted a TCP connection |
| `d4-negative-<case>-p0.log` | The driver's own output, headed by the config it ran and the exit status it returned |
| `d4-negative-<case>-p{1,2}.log` | What each strict peer logged while the mutated driver talked to it |
| `evidence-index.json`, `evidence.sha256` | The seal over the directory |

## Results

| Case | Driver | Result |
| --- | --- | --- |
| `wrong-ca` | `negative/wrong-ca.json` on P0 | exit 3, `peer P2 certificate was not signed by the KAS CA` (0.67 s) |
| `wrong-san` | `negative/wrong-san.json` on P0 | exit 3, `peer P2 certificate SAN does not match its role` (0.69 s) |
| `no-client-cert` | `negative/no-client-cert.json` on P0 | exit 3, `the BRPC link could not be established: connect to mesh failed, failed to setup connection to rank=1` (57.41 s) |
| `tls-disabled` | `negative/tls-disabled.json` on P0 | exit 3, `the SPU link must not run without TLS` (0.64 s) |

For `no-client-cert` the strict peers did not merely time out: P1 logged
`Fail to SSL_do_handshake: error:0A0000C7:SSL routines::peer did not return a
certificate` for every attempt, and both peers then reported the same link
failure themselves.

The plaintext probe connected to all four listeners from P0 over the private
network while P1 and P2 were serving, and none of them answered in plaintext:

| Listener | Outcome |
| --- | --- |
| `172.27.172.202:47101` (P1 BRPC) | connected, `no_plaintext_reply` |
| `172.27.172.202:47201` (P1 share) | connected, `connection_reset` |
| `172.27.172.203:47102` (P2 BRPC) | connected, `no_plaintext_reply` |
| `172.27.172.203:47202` (P2 share) | connected, `connection_reset` |

`any_plaintext_service` is false in the summary: no listener returned a byte
that a plaintext client could call a business answer.

## How the run was driven

```bash
python -m infra.d4_three_hosts negatives \
  --cluster deploy/d4-three-hosts.json \
  --out-dir docs/evidence/d4-negs-3host-20261012T154315Z \
  --run-id d4-negs-3host-20261012T154315Z \
  --ssh-key <key> --ssh-user jiahao
```

The probe step starts only P1 and P2: each opens its two listeners and then
waits for the rest of the mesh, which leaves the listeners up and idle, so the
probes cannot race the grid and the driver takes no part. Each case then starts
the two strict peers on their own instances, runs the mutated configuration on
P0 in the foreground so its exit status is the real one, collects both peer
logs, and stops every node process before the next case.

Only exit statuses, refusal text, byte counts and probe outcomes leave the
instances.
