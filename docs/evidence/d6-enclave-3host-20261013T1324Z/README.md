# D6 three-instance enclave run (d6-enclave-3host-20261013T1324Z)

Sealed evidence for the D6 gate: one client prompt drives a private
autoregressive loop through P0/P1/P2, each node inside its own
`gramine-sgx` enclave, and the session state is searched for on every
instance after the client closes it.

| Role | Instance | Private | Public |
| --- | --- | --- | --- |
| P0 | `iZuf6bjvfplpwleemaipwmZ` | `172.27.172.201` | `106.14.207.224` |
| P1 | `iZuf6bd6qnhgtveg5khyf1Z` | `172.27.172.202` | `47.117.34.67` |
| P2 | `iZuf6bd6qnhgtveg5khygdZ` | `172.27.172.203` | `47.116.200.143` |

The run is at commit `3e82e1b890bdcfc004688f5f65238fb09156863b`.

## What each file says

| File | Content |
| --- | --- |
| `d6-summary.json` | Machine-readable summary: roles, prompt, tokens, per-step latencies, negatives, close evidence, the enclosure block, the before/after session listings and the capture digests |
| `d6-client-result.json` | Everything the client saw and checked: request hashes, reconstructed tokens, its own argmax agreement, every refused negative and the float reference comparison |
| `d6-client.log` | The client process's own stdout, including its one-line verdict summary |
| `d6-three-p{0,1,2}-node-status.json` | Each node's step digests, refusals, KV wipe record and close evidence |
| `d6-three-p{0,1,2}-node.log` | Each node's log: the ready line with its identity digest and peers, then the done line |
| `d6-three-P{0,1,2}-tls-summary.txt` | Each instance's own TLS 1.3 analysis of its own capture |
| `d6-hygiene-p{0,1,2}.json` | What the post-close search of each instance's tmpfs, temp tree, logs and process table found |
| `d6-reveal-scan.json` | The production-reveal scan all three trees were checked against |
| `d6-enclave-p{0,1,2}-sign.txt`, `d6-enclave.manifest` | What each instance's `gramine-sgx-sign` printed and the manifest it signed |
| `evidence-index.json`, `evidence.sha256` | The seal over the directory |

The raw captures stay on their instances under `/tmp/`; the three
`d6-three-P{0,1,2}.pcap` entries in `<bundle>.exclusions.json` record
their size and digest, and the per-instance TLS summaries are
committed.

## The decoded tokens

| Item | Value |
| --- | --- |
| Prompt | `the cipher key is secret` |
| Prompt token ids | `[3, 70, 71, 11, 80]` |
| Generated words | `['yes', 'his', 'small']` |
| Generated text | `yes his small` |
| Session id | `ef8e01b0e5feb8725132ece9b2d177974813df4d2c17bf9b187ad2cccc9adf52` |

| Step | Token | Word | Argmax of reconstructed logits | Secure Argmax | Wall ms |
| --- | --- | --- | --- | --- | --- |
| 1 | 30 | `yes` | 30 | `True` | 2102.595 |
| 2 | 45 | `his` | 45 | `True` | 2229.916 |
| 3 | 60 | `small` | 60 | `True` | 2230.384 |

The last two columns agreeing is the point of the loop: the parties
produce a token with their own secure comparison, and the client, which
holds none of the model, reconstructs the same logits from the three
receipts and takes their argmax itself.

## Reference

| Step | Max abs error | Mean abs error | Reference token | Token match | Argmax match |
| --- | --- | --- | --- | --- | --- |
| 1 | 0.000802279 | 0.00022552 | 30 | `True` | `True` |
| 2 | 0.000492277 | 0.000120303 | 45 | `True` | `True` |
| 3 | 0.000421372 | 0.000138443 | 60 | `True` | `True` |

## Negative cases

| Case | Refused | Reason |
| --- | --- | --- |
| `duplicate_result_frame` | `True` | result frames do not cover P0, P1, and P2 |
| `tampered_decode_step` | `True` | result-frame decode-step mismatch |
| `mixed_model_manifest` | `True` | result-frame model mismatch |
| `replayed_request_frame` | `True` | ReplayRejected: counter is duplicated or out of order |
| `replayed_job_ticket` | `True` | D6NodeError: the JobTicket has already been accepted by this node |

## Session state

| Role | Spilled files | Bytes overwritten | Session dir removed | Keys zeroed | KV entries left |
| --- | --- | --- | --- | --- | --- |
| P0 | 3 | 4323 | `True` | 80 | 0 |
| P1 | 3 | 4323 | `True` | 80 | 0 |
| P2 | 3 | 4323 | `True` | 80 | 0 |

| Item | Before close | After close |
| --- | --- | --- |
| Files under the session root | 3 | 0 |

## Hygiene scan

| Role | Verdict | Findings | Roots that exist | Journal |
| --- | --- | --- | --- | --- |
| P0 | `clean` | 0 | 4 | `True` |
| P1 | `clean` | 0 | 4 | `True` |
| P2 | `clean` | 0 | 4 | `True` |

The scan searches for the share prefixes the run published as probes,
in the session tmpfs, `/tmp`, the workspace `out/` tree, `/var/log`,
the system journal and every process's command line and environment.
It also asserts the three session directories are gone and the session
root is empty, so a close that removed the directory but left something
else behind still fails.

## Verdicts

| Clause | Value |
| --- | --- |
| Tokens generated | 3 |
| At least two tokens | `True` |
| Negatives refused | `True` |
| Reference matches the float model | `True` |
| Nodes released | `True` |
| Hygiene clean | `True` |
| Gate | `True` |

## Enclosure

| Role | MRENCLAVE | `d6_node.manifest` sha256 |
| --- | --- | --- |
| P0 | `60660738c586699f960d9fadb3a3771b96c730c851480ce901ad745655875609` | `9883706a9839e82b6948d6e5c08b7e5b489912632b20fadcb4fd87acd971407a` |
| P1 | `6694f72dc7a17414e32797ae548389a3099cc6d7a5010fc730265231132768d7` | `fee8a481b758a4151cc725b10611b19c42e14da671c8acb6a4c7677d6a58d7f4` |
| P2 | `afe0b3070c1a5f73b33990b05f38163f8f32aeb3b71a3c9c02cb1a5121c12549` | `a715fb12f9373406ba459fae64d7b635fdffae24510237ad177f81e44d25cbae` |

`distinct_measurements`: 3.
Each instance signed the tree it really loaded, so the default run
measures three trees rather than pretending they are one.

| Item | Value |
| --- | --- |
| `sgx.enclave_size` | 4G |
| `sgx.max_threads` | 64 |
| `sys.stack.size` | 2M |
| Template | `d6_node.manifest.template` |
| Launcher | `gramine-sgx /home/jiahao/a122-enclave/d6-enclave-3host-20261013T1324Z/d6_node` |

## Reveal scan

| Role | Verdict | Findings | Allowlisted hits |
| --- | --- | --- | --- |
| P0 | `clean` | 0 | 34 |
| P1 | `clean` | 0 | 34 |
| P2 | `clean` | 0 | 34 |

## Captures

| Role | Bytes | SHA-256 |
| --- | --- | --- |
| P0 | 17541405 | `ce47d3c0e8acdc5fa1c4eb9666ff8db2040f9505e5069b9d4812e79f5cb2d71f` |
| P1 | 17362741 | `365394262c75c4930982d70e473b370ff7e41077c09595129b04e85ec541a4d3` |
| P2 | 17358974 | `997f452cafb50bbb5e58c56d617143d3e4d0efd7aaedc854da3bf8c09836cbcf` |
