# MINK-BHC: finite LWE commitments and honest-beacon setup proof

Run MINK-BHC-2026-11-01-T16. Predecessor: MINK at syscoin/PVUGC#1, branch research/pq-wkem-validation-20260918, head 6be55c9d3cf2c5e32f8d7c33b01ea338f43531a2. Exact prior MINK research blob d5211ea285e120e1f5095c14d15fde0e954b1db1. No external research. This is an independently specified *setup-proof component* for the already restricted MINK/AXLR source, NOT a generic-NP post-quantum witness-KEM or deployment.

## Exact finite commitment

Let q be an odd prime, n the LWE secret dimension, m the sample count, and chi a bounded error distribution supported on [-B,B]. Require q>12B+12 and m>n. Publish A sampled uniformly from F_q^(n by m). Set gamma=floor(q/3). To commit to one of three graph colors b in {0,1,2}, independently sample s uniformly in F_q^n and e from chi^m, and publish

    c=A^T s+e+gamma*b*e_1 mod q.

The opening (s,e,b) is checked for canonical ranges and exact equality. Use independent coins per vertex, proof round and signer, with the same uniformly generated A. This is classical PPT.

**Statistical color binding:** if distinct colors b,b' open the same c then A^T Delta_s = -Delta_e-gamma*(b-b')*e_1. Delta_s=0 is impossible because the centered distance of gamma or 2gamma from zero exceeds 2B. For each nonzero Delta_s, A^T Delta_s is a uniform vector over F_q^m. Union-bound over ordered different colors and all error differences gives the *global* bound

    delta_bind <= 6*(q^n-1)*((4B+1)/q)^m.

The bound concerns A itself, hence rules out every pair of different-color openings even for an unbounded/quantum algorithm on the good-A event. It does not require that same-color openings be unique. The example n=256, q=4294967291, B=256, m=1024 has a binding upper bound of roughly 2^(-14332) but **no established concrete LWE hardness level**.

**QPT hiding:** let Adv_LWE be QPT decisional LWE distinguishing (A,A^T s+e) from (A,u) with this exact chi, and advice independent of fresh LWE coins. Shifting one coordinate of a uniform u leaves it uniform, so any two color commitments have QPT distinguishing advantage at most 2 Adv_LWE. For reduction to standard discrete-Gaussian LWE use a polynomial-time bounded truncation and include the negligible tail loss. Uniform bounded toy errors are not asserted to be standard PQ-hard parameters. Multiple commitments are handled by a polynomial hybrid under independent per-commitment coins. Arbitrary QPT coherent processing of the CLASSICAL public values is included; coherent opening queries are not.

## Actual honest-beacon graph proof

Let X=(R_original,x, claim/UTXO/branch/anchors/window/context, vk, all related capsules, manifest, exact Build/KeyGen code identities). L_setup(X) is the NP relation: there exist keygen coins, a native sk and Build coins for **every** capsule such that Native.KeyGen gives (sk,vk) and every capsule equals Build(x,sk;r). A deterministic classical polynomial circuit-to-3-coloring reduction yields G_X=(V,E), with a proper coloring if and only if L_setup(X) has a witness. The checker in this iteration tests 3-color graphs directly; it does NOT implement the full circuit-to-3COL reduction or native KeyGen/Build.

For ell rounds, a prover knowing the setup witness computes a proper 3-coloring, applies a fresh uniform permutation of the three colors per round, and publishes fresh independent commitments for every vertex. Only AFTER ALL commitments are fixed, an independently sampled public beacon chooses one edge uniformly per round. The prover opens the two endpoint colors and coins. Accept if both commitments open correctly and endpoint colors differ. Bind all rounds and their challenges to a unique signed pre-funding session. Never reuse a graph-color commitment across multiple edge challenges.

On a graph without a valid coloring, a fixed set of color commitments (on the globally binding-A event) violates at least one edge in each round, regardless of QPT generation or adaptive classical openings. With independent post-commit challenges,

    Pr[false proof accepted] <= delta_bind + (1-1/|E|)^ell.

This does not use classical rewinding. To simulate the full CLASSICAL public proof transcript for a TRUE X under an **independent honest beacon**, choose each edge first, choose its two ordered colors uniformly and distinctly, commit honestly to those endpoints and any arbitrary colors elsewhere, and open exactly the endpoints. The actual real opened pair is exactly uniform among six ordered pairs because each round uses a fresh uniform permutation. Under QPT decisional LWE, the remaining (|V|-2)*ell commitments can be replaced via a straight-line polynomial hybrid, with loss at most 2*(|V|-2)*ell*Adv_LWE plus truncation losses. The statement may contain the genuine native vk, witness-correlated source capsule, and independent, separately simulatable auxiliary information. Commitment randomness must be fresh and not included in the auxiliary leakage.

The simulator does NOT need the native sk. On a restricted FALSE signed-XOR source, MINK's explicit delta satisfies A_source^T delta=e0, so zero-mode ciphertexts A_source^T s0 are in the Build support for EVERY sk compatible with the genuine vk. Thus L_setup(X) remains true even for capsules simulated without sk; the above honest-beacon proof simulator applies to the joint vk/capsule/proof view without a SourceOpen oracle. Related capsules are included together in the NP setup statement, with fresh proof randomness. Native signing and preauthorization authentication are separate QPT assumptions.

## Limitation that is NOT solved by this note

An **externally honest, post-commit unpredictable and independent beacon** is an explicit condition of the theorem. Neither a malicious-verifier QPT zero-knowledge protocol, nor a composable N-of-N jointly generated beacon with one unknown honest participant, nor a CRS simulator that can equivocate beacon contributions was constructed. A malicious prover seeing its own challenge before committing can cheat. A malicious verifier adaptively influencing challenge/reveal/abort interactions needs a different joint simulation proof. Thus the earlier MINK pre-funding setup-proof obligation is REDUCED to explicit primitives but NOT fully solved under the complete ceremony threat model.

No claim of generic-NP FALSE source security, hard-TRUE arbitrary final-key/native-forgery -> ORIGINAL-witness reduction, QPT concrete 128-bit LWE level, efficient large-graph proof, Bitcoin native PQ deployment, or verified AuxPoW fork evidence. The independently constructed new piece is the finite LWE three-color commitment with quantitative global binding and QPT LWE hiding, plus a scoped finite honest-beacon public-transcript proof. The exact missing equation remains a full-public, arbitrary-QPT *source-dependent Build/Lift simulator and ORIGINAL extractor* for generic NP, with malicious ceremony and multiple-capsule composition. Avoid promoting this restricted setup tool to a witness-KEM.

## Bounded executed validation

The self-contained checker.js is the exact deterministic function executed. It enumerates 662,661 color/opening combinations at q=101,n=1,m=7,B=1 for A=[94,11,14,50,7,88,5], with no cross-color collisions. It checks honest selected-edge openings, K4 noncolorability across all 81 assignments, six random-permutation endpoint pair outcomes, binding bounds and honest-beacon rounds. These are only finite correctness checks; the tiny LWE parameters are insecure. A separately executed Python checker passed 560 assertions twice with identical output and includes expanded tampering tests. A complete local-only archive is supplied separately.
