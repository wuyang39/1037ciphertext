# D7 local model evidence

- frozen source: `gpt2` @ `607a30d783dfa663caf39e06633721c8d4cfcd7e`
- license: Modified MIT License (OpenAI, 2019)
- prompt: 'the cipher key is secret' -> [1169, 38012, 1994, 318, 3200]
- layers: 12, sequence: 8, candidates: 1028
- fidelity verdict: passed
- program text: ', and the'
- released text: ', and the'

This bundle is produced by `python -m infra.d7_local_evidence`. It
records what the D7 program's own arithmetic reproduces of the
released GPT-2 before any enclave is involved.
