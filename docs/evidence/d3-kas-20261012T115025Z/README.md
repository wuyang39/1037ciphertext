# D3 KAS-sealed disk-key release (2026-10-12T1150Z)

Real Gramine-SGX run on the D1 acceptance instance
(`iZuf6bjvfplpwleemaipwmZ`, `cn-shanghai`). It closes caveat 1 of
[../d3-20261012T1930/README.md](../d3-20261012T1930/README.md): `K_disk_P0`
is no longer generated on the host and handed to the enclave. The KAS derives
it and releases it only as an SM2 ciphertext addressed to a temporary enclave
key, and only after a DCAP Quote binds that key, the role, the release and the
KAS challenge nonce in REPORTDATA.

## Command

```bash
cd ~/1037ciphertext
PYTHON=~/a122-venv/bin/python SYSTEM_PYTHON=/usr/bin/python3 \
  bash deploy/run_d3_kas_release.sh
```

The runner builds the throwaway model package, scrubs the raw shares the
package builder leaves behind, builds the DCAP verifier the KAS calls,
generates the KAS CA and ticket-signing key, renders and signs
`tee/gramine/enclave/encfs_worker.manifest.template`, encrypts the P0 share and
precision plan into a Gramine encrypted-FS store, and then hands the case grid
to `infra/d3_kas_acceptance.py`. Every case drives a fresh
`gramine-sgx ./encfs_worker` process against a freshly challenged KAS, and
`infra/d3_kas_release_evidence.py` turns the raw case output into the verdicts.

## Results

| Case | Result | Detail |
| --- | --- | --- |
| `accept-kas-sealed-release` | accepted | seal `200`; the enclave opened the 224-byte SM2 bundle, matched the startup fingerprint, epoch and key id, installed the 16-byte PF key and read the 46080-byte share; exit status 0 |
| `deny-missing-sealed` | rejected | seal `200`, bundle never delivered, `sealed_seen=0`, exit status 3 |
| `deny-tampered-sealed` | rejected | one flipped byte in the ciphertext, `SM2 ciphertext integrity check failed`, `bundle_open_ok=0` |
| `deny-wrong-epoch` | rejected | enclave claimed epoch 2 while the KAS sealed epoch 1, `startup_hash_ok=0` |
| `deny-wrong-startup` | rejected | enclave claimed `unregistered-model`, `startup_hash_ok=0` |
| `deny-replay-challenge` | rejected | first seal `200`, replay of the same challenge `404` (`challenge is unknown or already consumed`) |
| `deny-second-seal` | rejected | second release for the same role/release/epoch/purpose `409` (`storage key was already sealed for this node and epoch`); the first run still read the share |
| `deny-wrong-measurement` | rejected | second KAS with `mrenclave = 00*32` answered `403 MRENCLAVE does not match the release` |
| `deny-host-plaintext-in-store` | rejected | the plaintext share, its first 64 bytes and its last 64 bytes are absent from the 53248-byte PF store |
| `deny-host-plaintext-anywhere` | rejected | byte search over the run directory, `/tmp`, `/var/log` and `$HOME` found no plaintext share |

| Item | Value |
| --- | --- |
| Enclave | Gramine 1.9, `sgx.debug = false`, `sgx.remote_attestation = "dcap"` |
| MRENCLAVE | `88e73d97fe87362eac096f44df23ffd2b271cb8de7b99fa4c13d6c118a2f5cd2` |
| MRSIGNER | `4296167eed40572682c03bd4dba260ff16383d7299117d0de8ec22f52dc329b7` |
| Bootstrap Quote | 4734 bytes, sha256 `57a470dc302383700de8189f20e9d7e639d8032de60ee0bc14b1baed3560bf03`, DCAP status `0x0000` |
| Release policy | `a122-d3-kas-v1`, `tiny-local-v1`, expires `2026-10-12T17:50:40+00:00` |
| Released key id | `c9eca76f72b4c3261f91164bb7e4c0a7a6b9e0d19a175ac66d2009aca721bd24` |
| Worker startup digest | `42748f8b5597654dea6bbcd009546c8d557ef40ff6a4c8b17c7f75b2740f09a7` |
| Plaintext share | 46080 bytes, sha256 `e4150b9bc6d172cb4b7e81c332f3d994c3116488175fa9b6901c013de7fa095b` |
| Plaintext prefix | first 4096 bytes, sha256 `14cd7bb478ee7ee9be85f7bc184a84e11369c76349c4f9c1ccf286cbdc1a1d37` |
| Encrypted share | 53248 bytes, sha256 `1b28b56e94b4586d1a4ab6c5267aef9239c793c9d25119df93e18fa811abafbe` |
| Encrypted plan | 4096 bytes, sha256 `28d3cd973f315a0c566e58df1dc5d184f29ed7f067aee8253472af6ec34a46a0` |
| Key channel | `/dev/attestation/keys/a122_disk`, 16-byte PF key from HKDF-SM3 over the released `K_disk_P0` |
| Sealed bundle | 224 bytes, `SM2 C1(64) || C3(32) || C2(128)`, hex recorded only as `sealed_bytes` |

The plaintext share hash is identical to the one in
`../d3-20261012T1930/`, so this run reads the same share bytes the earlier
host-generated-KDK run read, now with a key the host never sees.

## Files

| File | Content |
| --- | --- |
| `d3-kas-summary.json` | the ten verdicts, the enclave claims, the packaging record and the acceptance flag |
| `cases.json` | raw per-case records as the grid produced them |
| `case-*.json`, `accept-kas-sealed-release.txt`, `deny-*.txt` | one file pair per case with the enclave `key=value` output and its exit status |
| `acceptance.txt` | case-grid log |
| `bootstrap-quote.txt` | the measured bootstrap run, before the release policy exists |
| `enclave-quote-verify.json`, `enclave-quote-verify.stderr.txt` | DCAP verification of the bootstrap Quote |
| `encfs_worker.manifest` | rendered manifest of the signed Worker |
| `kas-release-policy.json` | enforcement policy written from the measured MRENCLAVE |
| `packaging.json`, `packaging.txt` | `K_disk_P0` key id, store files, and the scrubbed plaintext record |
| `model-package-build.json` | the throwaway package the share came from |
| `d3-kas-env.txt` | packages, interpreters, SGX devices, `aesmd`, manifest hashes |
| `host-leak.txt` | host listing, hexdump and `strings` of the encrypted share |
| `host-substring-search.txt` | plaintext-substring search inside the store |
| `host-scan.json`, `host-scan.txt` | host-wide plaintext search result |

## Caveats

1. The challenge and release exchange runs over loopback HTTP. The Quote is
   what carries the attestation; the transport itself is unauthenticated, and
   RA-TLS between the Worker and the KAS stays open for D6.
2. The challenge store and the one-release-per-epoch ledger live in the KAS
   process memory, so restarting the KAS resets them. The grid relies on that
   for a clean ledger per case.
3. The SM2 bundle is authenticated by the SM3 `C3` check plus the bundle magic;
   there is no separate MAC, and the release carries no forward secrecy.
4. `K_disk_P0` still derives from a per-run storage master that the runner
   generates on the host. The evidence records only the derived `key_id` and
   never the master, but binding the master to the KMS remains open.
5. Gramine encrypted files do not defend against rollback after close; an older
   but authentic store copy would still be accepted.
6. The model package is the throwaway 46080-byte test share. The English GPT-2
   evaluation settings, precision plan and per-node separation are D4/D7 work.
