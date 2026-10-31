# Run 47 provenance

## Scope

This run continued the draft research record in `syscoin/PVUGC` PR #1 from verified head:

`ceec0bc9ea71206539dd17fcc195c0f3c5a02e3a`

The run used the existing repository/research record, original mathematical reasoning, and local deterministic computation. No external literature search or web search was used.

The constructive target was tensor-power amplification of the Run-42/43 native short-preimage metric gap, followed by a polynomial-size CP/rank-one compression attempt.

## Publication checkpoint

A checkpoint comment was posted before the final local proof/test record, explicitly describing the attempt as under audit and not as a security claim.

## Local files

- `TENSOR_METRIC_COMPRESSION_RUN47.md`: theorem statements, complete-output audit, resource analysis, and limitations.
- `check_tensor_metric_compression_run47.py`: deterministic Python standard-library checker.
- `TENSOR_METRIC_COMPRESSION_RUN47_RESULTS.json`: captured final checker output.
- this provenance file.

## Executions actually performed

After the final checker edit:

```text
python3 check_tensor_metric_compression_run47.py > run47_a.json
python3 check_tensor_metric_compression_run47.py > run47_b.json
cmp -s run47_a.json run47_b.json
```

The two outputs were byte-identical.

Final SHA-256 values:

- `check_tensor_metric_compression_run47.py`: `c27b00dd616c649112ada6ffe921d4f8f841f555e6c3da0ca37f71fd768dd68d`
- `TENSOR_METRIC_COMPRESSION_RUN47_RESULTS.json`: `5ad4036ba7fcc48c84e1c041078bcfc5f0d19f5333246553028994447a5a662e`

The checker reports finite algebra/exact-distribution validation only; it does not claim cryptographic security.

## Claim taxonomy

### Proved mathematical claims

1. `A^{tensor t} y^{tensor t}=u^{tensor t}` when `Ay=u`.
2. `||y^{tensor t}||_2^2=||y||_2^{2t}` and the resulting metric-gap formula.
3. `rank(A^{tensor t})=rank(A)^t` and explicit kernel directions obtained by tensoring any `ker(A)` vector with arbitrary factors.
4. Noiseless CP factors `z=A^T s` expose `<u,s>` publicly via any linear-system solution whenever `u=Ay` for an exact preimage.
5. Exact one-corrupted-factor residual distribution and shifted-distribution TV.
6. Conditional exact-linear-sketch row-space lower bound and `binom(d+t,t)` affine-patch dimension.

### Implemented algorithms/checks

- finite-field Kronecker products and tensor powers;
- finite-field linear solving/rank;
- exhaustive residual distribution enumeration;
- noiseless public-recovery solver;
- affine tensor-feature rank checks;
- explicit tensor-kernel direction construction.

### Tests actually executed

The captured JSON records:

- 1,421 tensor-preimage coordinate checks;
- 200 tensor norm checks;
- 21 gap/resource rows;
- 9 exhaustive residual-distribution fixtures;
- 15 large-q analytic controls;
- 300 noiseless public-recovery fixtures;
- 1,039 solution-invariance checks;
- 1,000 noisy residual identities;
- 12 affine span fixtures;
- 80 tensor relation rank checks;
- 80 tensor kernel-direction checks.

### Conjectural / not proved

- No general impossibility theorem for nonlinear or computational tensor compression is claimed.
- No claim that the one-corrupted-factor event has non-negligible probability for every useful LWE error distribution is made.
- No claim that standard LWE alone proves security of a capsule leaking a nonlinear function of its secret is made.
- No arbitrary-QPT key-recovery-to-source-witness reduction is known.
- No complete WKEM security proof or practical parameter set is claimed.

## Production-code status

The intended publication adds only Run-47 research files under `research/pq-wkem/`. No production source is modified. The PR must remain draft and unmerged.
