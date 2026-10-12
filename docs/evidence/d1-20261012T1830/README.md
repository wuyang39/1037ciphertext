# D1 Gramine-SGX acceptance (2026-10-12T1830Z)

Minimal Gramine-SGX program on the D1 acceptance instance
(`iZuf6bjvfplpwleemaipwmZ`, `cn-shanghai`). This closes item 4 of D1 section 5
in [后续开发总计划.md](../../后续开发总计划.md): a Gramine enclave must run
before Gramine is trusted with the encrypted-FS stage.

## Command

```bash
cd ~/1037ciphertext
bash deploy/run_d1_gramine.sh d1-20261012T1830
```

The runner installs nothing; it uses Gramine 1.9 (`deploy/install_gramine_server.sh`
set up the `packages.gramineproject.io` repository) and the probe source in
`tee/gramine/hello`. It builds `hello.c`, renders and signs the manifest, runs
`gramine-sgx ./hello` and verifies the emitted quote with
`tee/attestation/dcap_verifier/a122_dcap_verify`.

## Result

| Item | Value |
| --- | --- |
| Enclave | Gramine 1.9, `sgx.debug = false` |
| Quote | ECDSA/DCAP, 4734 bytes, `debug = false` |
| DCAP verify status | `0x0000` (accepted) |
| DCAP verification result | `0x0000a008` (`CONFIG_AND_SW_HARDENING_NEEDED`) |
| MRENCLAVE | `0427d1eb51730429ff03239e6c5998a667cec38e1d938d2401a7309212b612b0` |
| MRSIGNER | `4a5a7e01f7d5c187345ad38d1a50a41e3a95a1c75f63c383ef16517cb0453292` |
| REPORTDATA binding | probe report data echoed in the quote report |
| quote sha256 | `388d80ceb613658f4453b9e5995e579f98a8bad369f05f369839afac5cf29087` |

## Files

| File | Content |
| --- | --- |
| `gramine-env.txt` | packages, loader version, SGX devices, `aesmd`, PCCS config |
| `gramine-hello.manifest` | rendered manifest used for the measured enclave |
| `gramine-hello.txt` | probe stdout with the quote, plus the loader exit status |
| `gramine-hello.stderr.txt` | loader stderr |
| `gramine-quote.bin` | raw quote extracted from the probe output |
| `gramine-quote-report.json` | parsed claims and report-data binding check |
| `gramine-dcap-verify.json` | DCAP verifier output for the quote |
| `gramine-summary.json` | acceptance verdict for this run |

## Caveats

1. The signing key is generated per run, so `MRSIGNER` is not a frozen release
   identity. A fixed release signing key replaces it before model material is
   loaded.
2. `ISVSVN` stays at the Gramine default `0`; the production manifest pins its
   own value.
3. Only the minimal probe runs here. Encrypted FS, mTLS and inference remain in
   D3 and later.
