# R312 — SHA work-subspace normalization and frozen-secret release gap (NONQUALIFYING)

## Continuation
Read current open draft syscoin/PVUGC PR #1 head `f24619707c7dfcc3f322098bbf3c6e593957bbd7` on `research/pq-wkem-validation-20260918`, and R311 research note blob `b033bde8e338aaaf159bed591d9ee0b470c23d97`. Latest substantive ordinary PR comment remains R225 #6796383617. Core #609 was NOT reread or tested in this run. This is a bounded offline SHA/finite-field experiment. No production, N-of-N ceremony, native signatures or actual network validation.

The ORIGINAL source relation is unchanged: (1) qualified strictly-higher exact cumulative work against same anchored BTC history, (2) finite authenticated burn refutation/nonmembership/complete bounded execution for the PARTICULAR withdrawal, (3) qualified actual h_rel ancestor inconsistency with relevant LC depth, or an independently authenticated exact claim-wrapper tag fault with adopted maturity. These are OR branches. Bind protocol and chain IDs, exact claim/outpoint/burn/amount/recipient, baseline, BTC anchors/window/depth, reset, cancellation message/VK and capsule. Contextual modern AuxPoW chain ID, exact 41-byte applicable Nexus SYS tag, independently checked parent coinbase and separate child Merkle commitment remain necessary under Core #609. Distinct BTC parents for one identical Syscoin child are not a fork. R225 native fixed-outpoint witness portability remains unresolved.

## Candidate: compact public work acceptance *normalizer*

Model (ONLY as an idealized subcase) a 256-bit SHA256d work hash y as an element of F=GF(2^256), and an acceptance rule where the first d work bits are zero. In reality exact Bitcoin compact targets and integer endian conventions require their own checks. Let U be the binary linear subspace of such y, dimension m=256-d, with basis b_0,...,b_(m-1). Construct its annihilator:

    L_0(X)=X
    t_i=L_i(b_i) != 0
    L_(i+1)(X)=L_i(X)^2 + t_i*L_i(X).                 (1)

Induction in characteristic 2: L_i is additive, has roots precisely span(b_0,...,b_(i-1)); its successor has roots U_i union (U_i+b_i), since L_(i+1)(X)=L_i(X)(L_i(X)+t_i). The polynomial degree is 2^m yet evaluation uses polynomially many squarings and field operations. This is an EXACT compact public test, not a secret release. Normalize:

    Z(y) = L_m(y)^(2^256 - 1)
         = 0 for all y with the required work prefix,
         = 1 for all other y.                        (2)

An actual original-source violation bit Z_orig(w)=1-R_original(x_W,w) must additionally incorporate EVERY complete contextual source, tag, ancestry, depth, claim and native binding check. Z(y) alone is unsafe: arbitrary toy mined work, without relevant authenticated source history, would open.

## Frozen capability convergence attempt

Sample independent field S (fixed cancellation capability surrogate) and alpha. Define a **private** function

    F(w)=S + alpha*Z_orig(w), GF(2^256) operations.    (3)

All qualified witnesses give S; all nonqualifying inputs give T=S+alpha. Unlike R311's many independently SHA-gated violation coordinates, a single Boolean violation bit makes all invalid public *oracle responses* equal; invalid query vectors (1,1) never span the target (1,0). If alpha is uniform and the attacker sees ONLY an ideal evaluation oracle on FALSE inputs, T is independent of S even under coherent queries to that constant oracle. That model is NOT a full-public security theorem; it assumes an evaluator which already hides S and alpha.

The essential attempted repair fails: publication of the transparent straight-line circuit (3) exposes S or alpha. Publishing T alone leaves no certificate-dependent way to derive alpha; publishing alpha exposes S=T+alpha. Publishing H(alpha) does not cause future AuxPoW evidence to contain alpha. Garbling with both external bit labels lets an adversary splice inconsistent internal evaluations (prior R280/R287), and fixed future-witness-tag rows cannot serve arbitrary later witnesses (R288). This model is not a public Build/Open or a native PQ bridge.

## Direct SHA source entropy test

The common d-bit prefix of two toy accepted SHA256d hashes is public 0^d: K=SHA256(domain||x_W||0^d) is known before any challenge; E=S XOR K leaks S. The remaining 256-d bits differ among qualified candidates. In an ideal independent random-hash model conditioned on a prefix work test, any GF(2)-linear projection of these variable suffixes of rank r coincides on two independent candidates with probability 2^(-r). Thus nonconstant work-suffix pads fail the SAME frozen-secret opening requirement, while constant-prefix pads are already public. This is a restriction on direct public hash projections, not an impossibility of all WE, SHA or QROM constructions.

Executed Python3 standard library checker: GF(2^8), AES irreducible modulus 0x11b, five-basis recurrence, exactly 32 roots (0..31), complete 256-element field census for zero/one normalizer, ideal private F returns one value on all 32 valid and a different single value on all 224 invalid. 65,536 synthetic 80-byte headers with 3-leading-zero-bit toy filter yielded 8,025 accepted hashes, 8,025 distinct full hashes and 8,025 distinct suffix SHA pads; their prefix pad was one public value. NOT Bitcoin target, authenticated AuxPoW, PQ, QPT or consensus tests. Two independent checker invocations byte-identical. Local source checker SHA256 `2beebece68687e1a172f88c29c99e056b47bb3d1266aa8071e2fbe88cb58ca68`; captured checker output SHA256 `3746f092f0d3385fa0dc68f8bd2d9d19d5ce639bc865792441d2ea5bfca2bc3e`. Full derivation/checker/two outputs/provenance in local `R312_source_entropy_normalizer_20261115.tar.gz`, SHA256 `6689592a1ec9bea7ca487e2495daa719d0d8e3c04f679a0c7abbda33192e5216`; archive NOT committed to GitHub.

## Verdict and next equation

NONQUALIFYING: a compact exact work-prefix annihilator and oracle-only same-value correction are established, but **not** the intended source-conditional classical-PPT public encoder, joint-public QPT FALSE/hard-TRUE reduction, malicious/sibling-capsule simulator, or native endpoint. No reduction of the ORIGINAL release gap was achieved. The next needed construction remains actual `Encode(S,alpha,Z_orig)->C`, where the full public C permits `Open(C,w)` on EVERY qualifying ORIGINAL authenticated future certificate yet reveals no frozen cancellation capability except through a genuine ORIGINAL certificate or independent PQ break. A secret-oracle or obfuscated-code assumption is not an instantiation. Do not optimize the polynomial normalizer until that missing release equation is solved. No progress comment, completion notification, or automation change warranted.
