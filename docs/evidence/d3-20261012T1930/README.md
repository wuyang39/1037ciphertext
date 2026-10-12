# D3 Gramine encrypted-FS acceptance (2026-10-12T1930Z)

Gramine encrypted-files mount on the D1 acceptance instance
(`iZuf6bjvfplpwleemaipwmZ`, `cn-shanghai`), covering section 6 of
[后续开发总计划.md](../../后续开发总计划.md).

## Command

```bash
cd ~/1037ciphertext
PYTHON=~/a122-venv/bin/python bash deploy/run_d3_encfs.sh d3-20261012T1930
```

The runner builds a test-only Tiny model package with
`infra/build_model_package.py`, encrypts the P0 share and the P0 precision plan
with `gramine-sgx-pf-crypt`, deletes every plaintext copy, and then drives the
probe in `tee/gramine/encfs` inside a real `gramine-sgx` enclave.

The 16-byte KDK is a stand-in for the `K_disk_P0` the KAS is meant to release
after attestation. It is generated on the host, never written into the evidence
directory, and only its SHA-256 is recorded.

## Results

| Case | Result | Detail |
| --- | --- | --- |
| `accept-encrypted-share` | accepted | 46080-byte share read end to end, prefix hash matches the plaintext |
| `deny-missing-key` | rejected | no key provisioned, `EACCES` |
| `deny-wrong-key` | rejected | wrong 16-byte KDK, `EACCES` |
| `deny-tampered-store` | rejected | host flipped one byte, integrity check failed, `EACCES` |
| `deny-copied-store` | rejected | store copied to another path, embedded path mismatch, `EACCES` |
| `deny-host-plaintext-in-store` | rejected | plaintext share, first 64 and last 64 bytes absent from the 53248-byte PF store |
| `deny-host-plaintext-anywhere` | rejected | byte search over `artifacts/`, `/tmp`, `/var/log` and `$HOME` found no plaintext share |

| Item | Value |
| --- | --- |
| Plaintext share | 46080 bytes, sha256 `e4150b9bc6d172cb4b7e81c332f3d994c3116488175fa9b6901c013de7fa095b` |
| Encrypted store file | 53248 bytes, sha256 `9e963ebcb24afb272910695098f9e5520aa26e1d804fd7e9326bd69add79ef2f` |
| Plaintext prefix | first 4096 bytes, sha256 `14cd7bb478ee7ee9be85f7bc184a84e11369c76349c4f9c1ccf286cbdc1a1d37` |
| KDK | 16 bytes, sha256 `af60382f98e640e385632817f4fca75a6b71c63bd0c8a1d70ace5effbe4d94ab` (stand-in, not the released key) |
| Gramine | 1.9, `sgx.debug = false`, `sgx.remote_attestation = "dcap"` |
| Key channel | `/dev/attestation/keys/a122_disk` |

## Files

| File | Content |
| --- | --- |
| `encfs-env.txt` | packages, encrypted-files tool, SGX devices, `aesmd` |
| `encfs.manifest`, `encfs-copy.manifest` | rendered manifests for both mount paths |
| `encfs-accept.txt` / `.json` | enclave read of the encrypted share |
| `encfs-deny-*.txt` / `.json` | each refusal with its `errno` |
| `host-leak.txt` | host listing, hexdump and `strings` of the encrypted share |
| `host-substring-search.txt` | plaintext-substring search inside the store |
| `host-scan.json`, `host-scan.txt` | host-wide plaintext search result |
| `pf-crypt-encrypt.txt` | `gramine-sgx-pf-crypt` output with the bound store path |
| `shares.json` | share, plan, store and KDK hashes |
| `model-package-build.json` | the test-only package the share came from |
| `d3-summary.json` | all seven verdicts and the acceptance flag |

## Caveats

1. The KDK is generated on the host by `gramine-sgx-pf-crypt gen-key`. Binding
   the release of `K_disk_P0` to a KAS attestation decision is the remaining D3
   item and needs an attested channel from inside the enclave.
2. Gramine encrypted files do not defend against rollback after close; the
   store can be replaced by an older but authentic copy.
3. Only the P0 share and plan are mounted here. Multi-node key separation and
   per-role keys stay in D4.
