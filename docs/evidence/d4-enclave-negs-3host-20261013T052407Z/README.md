# D4 cross-host fail-closed evidence, inside enclaves (2026-10-13T05:24:07Z)

Sealed evidence directory for the fail-closed half of D4, driven by
`python -m infra.d4_three_hosts negatives --enclave-template ...` at commit
`63937a0`. This is the same replay as
[../d4-negs-3host-20261012T154315Z](../d4-negs-3host-20261012T154315Z), except
that every driver and every strict peer ran inside its own `gramine-sgx`
enclave:

| Role | Instance | Private | Public |
| --- | --- | --- | --- |
| P0 | `iZuf6bjvfplpwleemaipwmZ` | `172.27.172.201` | `106.14.207.224` |
| P1 | `iZuf6bd6qnhgtveg5khyf1Z` | `172.27.172.202` | `47.117.34.67` |
| P2 | `iZuf6bd6qnhgtveg5khygdZ` | `172.27.172.203` | `47.116.200.143` |

The workspace is the one provisioned by run
[../d4-enclave-3host-20261013T052121Z](../d4-enclave-3host-20261013T052121Z) and
it is byte-identical on all three instances; nothing was re-provisioned. The
conclusions and the limits are in
[../../d4-acceptance.md](../../d4-acceptance.md).

## What each file says

| File | Content |
| --- | --- |
| `d4-negatives-summary.json` | Machine-readable summary: every case with its expected reason, exit status, duration, refusal line, the plaintext probe result and the enclosure block |
| `d4-negatives-plaintext-probes.json` | The four plaintext probes, their outcomes, and whether every listener really accepted a TCP connection |
| `d4-enclave-p{0,1,2}-sign.txt`, `d4-enclave.manifest` | What each instance's `gramine-sgx-sign` printed, and the rendered manifest |
| `d4-negative-<case>-p0.log` | The driver's own output, headed by the config it ran and the exit status it returned |
| `d4-negative-<case>-p{1,2}.log` | What each strict peer logged while the mutated driver talked to it |
| `evidence-index.json`, `evidence.sha256` | The seal over the directory |

## Results

| Case | Driver | Result |
| --- | --- | --- |
| `wrong-ca` | `negative/wrong-ca.json` on P0 | exit 3, `peer P2 certificate was not signed by the KAS CA` (8.06 s) |
| `wrong-san` | `negative/wrong-san.json` on P0 | exit 3, `peer P2 certificate SAN does not match its role` (8.25 s) |
| `no-client-cert` | `negative/no-client-cert.json` on P0 | exit 3, `the BRPC link could not be established` (76.17 s) |
| `tls-disabled` | `negative/tls-disabled.json` on P0 | exit 3, `the SPU link must not run without TLS` (8.06 s) |

Every case still refused, and the per-case time is dominated by starting a fresh
enclave for each peer: the refusal itself happens in the same fraction of a
second it did on host processes. `no-client-cert` takes longer because the
handshake is retried until the driver gives up.

The plaintext probe connected to all four listeners from P0 over the private
network while P1 and P2 were serving from inside their enclaves, and none of
them answered in plaintext:

| Listener | Outcome |
| --- | --- |
| `172.27.172.202:47101` (P1 BRPC) | connected, `no_plaintext_reply` |
| `172.27.172.202:47201` (P1 share) | connected, `connection_reset` |
| `172.27.172.203:47102` (P2 BRPC) | connected, `no_plaintext_reply` |
| `172.27.172.203:47202` (P2 share) | connected, `connection_reset` |

`any_plaintext_service` is false: no listener returned a byte that a plaintext
client could call a business answer.

## The three enclaves are not one measurement

As in the positive run, each instance signed its own manifest, so the summary
lists three measurements and `shared_measurement` is false:

| Role | MRENCLAVE |
| --- | --- |
| P0 | `2c7131100e0a57af7f08b6bb44413703564b6aa7629ef62b91d6166711ee3829` |
| P1 | `2aada0026f43f79a77ae46264905f50164e6fd5602e4a958d8620deb3e314d89` |
| P2 | `ecb6c36aeb45a4dd6e36d1423783fe42857a6d6b0d46abd9abf84ae47b8284d9` |

The values also differ from the positive run's, because the manifest trusts the
workspace and the workspace already held the previous run's `out/` directory by
the time these manifests were signed.

## How the run was driven

```bash
python -m infra.d4_three_hosts negatives \
  --cluster deploy/d4-three-hosts.json \
  --out-dir docs/evidence/d4-enclave-negs-3host-20261013T052407Z \
  --run-id d4-enclave-negs-3host-20261013T052407Z \
  --ssh-key <key> --ssh-user jiahao \
  --enclave-template tee/gramine/enclave/spu_node.manifest.template
```

Only exit statuses, refusal text, byte counts and probe outcomes leave the
instances.
