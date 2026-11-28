# Cumulative handoff: QAP source coupling, 22 October 2026

The last live head before this iteration was 278fb342262de40dec3ccf24655d8cf0dcbf4d3f. The constant-mask/padded constructions and the original unmasked small-block sparse source are broken in their committed scopes. They are not being treated as secure candidates awaiting only formal proof.

## Active component

Normalized off-domain QAP source coupling, preserving the existing typed-gate and cofactor-free spectral interface. Classical Build/Encode/Recover/SuppliedSourceExtract are specified in QAP_SOURCE_COUPLING.md; qap_coupling.py and check.py instantiate their algebra.

Input: a COMPLETE normalized R1CS with m constraints/n free wires and a public original-source extractor. The source-direction theorem additionally checks injectivity of stacked A_free/B_free. Output: L=2m-1 coupled normalized constraints, m-1 quotient coefficients, and the public coefficient array for N=2bL+1. Every valid original witness still yields the SAME K but may yield a different matrix.

## Closed in this iteration

1. Exact normalized witness lift and inverse projection; no new release oracle.
2. Every nonzero coefficient direction touches at least L-m+1 coupled gates under the checked injectivity condition.
3. With independent uniform dense outer factors, all source-only direction matrices simultaneously have rank >=2b(L-m+1)-2a except with probability <=8(q^(n+m)-1)q^(-(a+1)^2).
4. Six exact toy common-key recoveries across two block sizes; full compiler and rank diagnostics preserved.

These are source-compilation/correctness/structural statements, not a recovery-to-witness security reduction.

## Open and indispensable

- Arbitrary key-only or native-forgery extraction; false-instance QPT hiding of the actual full array; native pk/tag correlation and related capsules.
- Homogenized projective safety: quotient-only infinity directions appear; no assertion that the old projectively safe theorem transfers.
- A matched reproduction of the exact earlier attack family through a justified source transformation. The normalized R1CS control here already differs from the prior source and is NOT a positive attack control.
- Affordable public package: even the smallest degree-certified evaluation count costs about 7.5x dense storage in the 30-row arithmetic example. No claim of global optimality or practicality.
- Malicious and abort-secure N-of-N setup, complete Syscoin witness grammar, conditional native-PQ Bitcoin graph.

Next operation should address the freely varying quotient-coordinate subpencil/normalization interface and full distribution, not add padding or celebrate storage changes to an unproved carrier. Run259 remains downstream only when an accepted complete source has actually been obtained.
