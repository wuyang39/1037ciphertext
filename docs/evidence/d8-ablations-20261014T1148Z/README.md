# D8 ablation: runtime arms over one fixed program

Run `d8-ablations-20261014T1148Z`: arms recorded through 2026-10-14T11:56:48Z, commit `b1f87bae5b9822d704e1b17ca924c7fbebc45bec`.

## What ran

- Model: `gpt2-1l-cand1028-v1` (model hash `c0394f5002ee79e2a9119d85e44d756dcd8b3aa930934919e2cf7f871df85ad9`)
- Blocks stacked: 1, candidate vocabulary: 1028 ids, fixed-point width 18 bits for the control arm
- Prompt: `the cipher key is secret`
- Network: lan (nothing injected; every arm runs unshaped)
- Arms: `approx-low`, `baseline`, `baseline-repeat`, `fxp-12`

Each arm is a full three-instance enclave run: staging, the SPU link,
three tokens, the five negative probes, the close and the scrub. The
difference between arms is one runtime setting, so a difference in the
table is that setting and not a different experiment.

## The arms

- `baseline`: the accepted configuration: calibrated width, default approximations
- `baseline-repeat`: the same configuration again, for the run-to-run spread
- `approx-low`: softmax exponential and division and the LayerNorm root at reduced iteration counts
- `fxp-12`: the calibrated fixed-point width narrowed from 18 to 12

## What this does not cover

- one run per arm: the spread of a single take is not separated except by the repeated control arm
- the nonlinear arms move the SPU runtime's own approximation switches; an arm that replaces the emitted MHLO operators with a different polynomial is still a second frozen program and is not in this table
- no per-process EPC residency counter exists on this kernel, so the arms are compared on time, traffic and fidelity only
- length buckets and batch size are not exercised by the one-layer probe geometry
