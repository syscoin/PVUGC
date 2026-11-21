# SAI91 — source-root terminal-mask interpolation (NONQUALIFYING)

## Provenance and exact continuation
Observed open draft syscoin/PVUGC PR #1 on branch research/pq-wkem-validation-20260918 at 67be1750ac0a7d71f2d7bed3614bfcfbb3bcb443 (SAI90). Read SAI90 note blob da98d29b8a2970c31790bea36f38f2b195e5fda7 and SAI89 blob 065037c5ee6aa0c236a0713df4008950eb950021. A targeted top-level comment query since 2026-11-18 18:00 UTC returned []. This run did not reread Core #609 source, run Core tests, build real Bitcoin/Syscoin source certificates or implement native signing.

SAI89 left a source-authenticated publicly executable encrypted state update and one common terminal cancellation capability unfinished. SAI90's witness Merkle root ensures repeated-read *syntax* but not cryptographic release. This iteration examines a new terminal operation: a polynomial correction of a public, source-witness-dependent hash-chain terminal. It is NOT another test of the low-degree Boolean-constraint masking family (R327).

## Candidate public Build/Open
Work in F_p. T_x(w) denotes the fully computed, Merkle-consistent hash terminal of the complete witness bitstream; crucially this itself is NOT a cryptographic proof of ORIGINAL validity. Let h(t)=H2(domain||t) interpreted in F_p, ideally independent of source verification. Build chooses frozen S and fresh K in F_p, publishes D=S+K, and tries to publish a degree-d polynomial P with

    P(T_x(w)) + h(T_x(w)) = K   for EVERY original-valid R_x(w)=1.

The proposed serialized public Open executes

    Open(C,w) = D - (P(T_x(w)) + h(T_x(w))).

For a **prescribed finite list** of N distinct known valid terminals with N <= d+1, Build can actually compute P by ordinary Newton interpolation after seeing their h-values, with classical polynomial time in N. This is only a finite-list demonstration, NOT an ORIGINAL Build: the future witnesses are not known during bridge setup, and a public caller can still supply source-invalid values. Merely attaching a verifier wrapper after this calculation does not cryptographically restrict disclosure.

## Exact model-scoped completeness calculation
Fix N>d+1 distinct t_i chosen independently of the independent random function h. The vector (h(t_1),...,h(t_N)) is uniform over F_p^N. Evaluation of degree-at-most-d polynomials at distinct t_i is an injective linear map whose image has cardinality p^(d+1) by Vandermonde rank. Therefore

 Pr_h[exists P of degree <= d: P(t_i)+h(t_i)=K for all i]
      = p^(-(N-d-1))

for any fixed K, even if P is selected after seeing all N oracle outputs. Letting K vary adds no degree of freedom: P-K remains an arbitrary degree-at-most-d polynomial. This bound concerns the **proposed terminal polynomial rebase**, not general hash-only WE/FE, circuits, obfuscation or SHA itself. In particular, a protected semantic circuit might correlate terminal values in a way excluded by this model. Choosing t_i adaptively in response to h invalidates this calculation. Domain separation in SHA256 alone does not justify independence, so the equality is an idealized independent-function calculation, not a concrete SHA theorem.

This result blocks the proposed cheap correction from opening the SAME frozen S for an unpredictable, large family of distinct original-valid witness terminals. A degree N-1 table/interpolation requires foreknowledge of all those terminals and is not a polynomial ORIGINAL compiler. A canonical public terminal value independent of source evidence would instead make K derivable from public C, so a genuinely source-conditioned and setup-bindable common invariant would require a separate cryptographic construction.

## Executed reproducible bounded check
Python3 standard-library check.py in the local archive generated 32 fixed synthetic witness strings, mapped them to 32 distinct SHA256-labeled elements of F_65537, used a second domain-separated SHA256 mask h, and constructed P from the first d+1 points. Degrees d=0,1,3,7,15,31 matched respectively 1,2,4,8,16,32 of all 32 points. Full degree 31 interpolation matched all **known** points. Two completed runs exited 0 and produced byte-identical output.

Checker SHA256: 0cbe38a71c78cbf2fd4cdcd40d6283f533c4692ec2dbfbc07d5ac6d48ff3349c
Output1 and output2 SHA256: b1280c5b6d9bd5211211e7a03dedf35127027c75f58a911c343495790bce4767
RESEARCH.md local full derivation SHA256: 74b0a3262e4549bac9407c1afaa2159572e148e6278436e28a704a6a226d9fb2
Local archive: /mnt/data/SAI91_terminal_rebase_20261121.tar.gz
Archive SHA256: 29f503ce56bfa1c4fa8f44935242bfc27bb582d5c6f8badacb7936b39575824b

Only this scoped note is published to GitHub; the executable checker and captured outputs are local-only, with no assumed persistence between runs. Fixture strings are NOT authenticated source certificates and the measurements do not prove a quantum, source-work, native-signature or Bitcoin-admission property.

## Unfinished full-public security equation
The complete published view would include x_W, D, P, source/native commitments and correlated capsules. This candidate supplies no cryptographic ORIGINAL verification gate: an adversary can feed arbitrary invalid hash roots and inspect the native verification key. The FALSE and hard-TRUE full-public joint distributions cannot be shown secure from these tests. No independent malicious-setup or QPT reduction exists.

The approved ORIGINAL relation remains the OR of relevant strictly greater exact BTC work, finite authenticated claim-specific burn fault, and qualified strict-post-PQ Syscoin history inconsistency/tag fault at requisite LC depth. Equal pre-divergence canonical tags do not negate authenticated child-history conflicts. No stronger Syscoin work, winning fork, or responding second notary is imposed. Claim/UTXO, amounts/recipient, source anchors/window, actual ancestors, deadlines/reset, safe native message/VK, capsule/session, graph/DA and one-honest N-of-N boundaries remain.

Next missing operation: a **serialized, efficient, publicly executable, source-cryptographically-gated terminal rebasing/update** whose result is the SAME frozen safe capability for EVERY independently qualifying original source witness; prove its FALSE/hard-TRUE joint-public recovery/native-forgery -> actual ORIGINAL certificate or independent QPT hash/native break, including malicious source-coin retention and sibling correlations. Do not substitute a public Merkle root, proof wrapper, virtual secret-key oracle, source-generated secret, arbitrary PoW puzzle or known finite witness list.

**NONQUALIFYING**. This rules out one explicitly scoped correction, not a breakthrough. No PR progress comment, user alert, production change, deployment or automation change is warranted.
