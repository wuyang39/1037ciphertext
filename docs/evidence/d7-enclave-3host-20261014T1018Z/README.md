# D7 enclave acceptance: real GPT-2 decoding across three instances

Run `d7-enclave-3host-20261014T1018Z` at 2026-10-14T10:21:26Z (enclave mode).

## What ran

- Model: `gpt2-1l-cand1028-v1` (model hash `c0394f5002ee79e2a9119d85e44d756dcd8b3aa930934919e2cf7f871df85ad9`)
- Blocks stacked: 1 (the layer count is a measured limit, not the whole network)
- Candidate vocabulary: 1028 ids (sha256 `53767094384b1632531ed619682e7a1aa412e2b5ed0db98131775fa69ce4d3b5`)
- Tokenizer: sha256 `8414cab924d8b9b33013f0d221c5862f365ee9be39c5c2bfae8a5a9e970478a6`
- Prompt: `the cipher key is secret` (5 tokens, pinned by the plan)
- Generated: 3 tokens ` secret secret secret`

## Verdicts

| Clause | Value |
| --- | --- |
| Tokens generated | 3 |
| At least two tokens | `True` |
| Negatives refused | `True` |
| Reference matches the float model | `True` |
| Nodes released | `True` |
| Hygiene clean | `True` |
| Staged shares scrubbed | `True` |
| Gate | `True` |

## Staged shares

| Role | Share file | Bytes overwritten | Removed |
| --- | --- | --- | --- |
| P0 | `~/a122-d7/three/workspace/shares/P0.json` | 92542258 | `True` |
| P1 | `~/a122-d7/three/workspace/shares/P1.json` | 92542258 | `True` |
| P2 | `~/a122-d7/three/workspace/shares/P2.json` | 92542258 | `True` |

Each instance received only its own share file; the peers fetched their own tree from the driver host over the VPC private address, so no share crossed the public internet and no node could reach a second share.

## Enclosure

| Role | MRENCLAVE | `d7_node.manifest` sha256 |
| --- | --- | --- |
| P0 | `9c3fb97916d4e967eb7a6e08176053948d287058b6f88c8fd29c1c290b39d781` | `5382eee046312effed93e8854ab821ffed3f459080e26d18fa5ce3619d4fcda0` |
| P1 | `033bb39c2cac324828035613b68e10e4e5fd658f5fe84a7268094f035cdbea3f` | `d8710ad89ac42dbe92a7e8864a3705a18d2680abe41defa3fc5ae89441c93f99` |
| P2 | `1532891dde086f807e25813af6a49641b40a054e2f86599dc1cd2ba7f26862cc` | `11b3a190e309e335fb4b184d2150b89d0cb271c1403768ae778970c12eea791b` |

`distinct_measurements`: 3. Each instance signs the tree it really loads, and the three trees hold different shares, so the measurements differ by design.

| Item | Value |
| --- | --- |
| `sgx.enclave_size` | 4G |
| `sgx.max_threads` | 64 |
| `sys.stack.size` | 2M |
| Template | `d7_node.manifest.template` |
| Launcher | `gramine-sgx /home/jiahao/a122-enclave/d7-enclave-3host-20261014T1018Z/d7_node` |

## Hygiene

Session state scan: `clean`. The scan searches each instance for the share prefixes the run published and requires the session directory to be empty and gone.
