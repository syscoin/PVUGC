# SAI117 — global occurrence-consistency and Fermat-projector screen (NONQUALIFYING)

## Continuity and specific repair
Live PR #1 start: research/pq-wkem-validation-20260918 at 8b5cf52542fa340966125f63e12b699c72d4e85a; prior SAI116 note blob bfd3e24d8222282b2881673d8b8cf5aacb7a7a0b; issue comments since 2026-11-21T00:00:00Z: none. No Core source or tests were rerun, no source evidence or FE primitive was implemented. This is an original research-directory checkpoint, not a progress announcement.

SAI115's publicly selectable matrix instructions admitted different choices for repeated occurrences of one witness bit; SAI116's explicit global state graph prevented that splice but publicly enumerated accepting paths. This pass tests a polynomial-dimensional GLOBAL constraint accumulator plus a nonlinear hidden zero test, with its full-public leakage analyzed. It does not weaken the original three-OR-branch challenge relation.

## Exact globally consistent polynomial-width arithmetization
Compile a bounded Boolean verifier to m bounded-arity constraints, with local assignment a_j for each clause j, q_j(a_j)=0 for local acceptance and 1 otherwise. Let d_v be the number of occurrences of variable v, and k_v=sum_(j containing v) a_j(v), where each bit is 0 or 1. Define the integer violation

    V(a) = sum_j q_j(a_j) + sum_v k_v(d_v-k_v).

All summands are nonnegative. V=0 iff all clauses hold AND each variable's local occurrences are identical (k_v is 0 or d_v). Hence V=0 yields one consistent global satisfying assignment, not a mixture of separate invalid traces. In F_p take p > m + sum_v floor(d_v^2/4), so modular zero has exactly the same meaning. This is a precise polynomial-size verifier-arithmetization component, NOT encryption or a source release.

Represent V with an affine (2n+2)x(2n+2) state acting on [1, k_1..k_n, r_1..r_n, q], initializing all k,r,q to zero. For a local clause choice with bit b at v, update

    k_v' = k_v+b, r_v'=r_v+2*b*k_v+b, q'=q+q_j(a_j).

All updates are affine linear; induction gives r_v=k_v^2. The final fixed row reads q+sum_v(d_vk_v-r_v)=V. Circuit size and state dimension are polynomial in the full bounded verifier. Finite authentic source/claim/anchor/height/LC-depth/nonce/burn evidence is only a future input to that verifier; none was processed here.

## Candidate nonlinear same-key gate
Attempt a non-low-degree zero test rather than R327's raw affine pad. Choose gamma in F_p^*, secret invertible R in GL_2(F_p). Put

    g(a)=gamma*V(a),
    M_g=R diag(g,1) R^(-1),
    P0=R diag(0,1) R^(-1),
    C=S XOR SHA256(domain||canonical(P0)),
    Z(a)=M_g^(p-1).

Fermat gives Z(a)=P0 for *every* globally valid a and Z(a)=I for *every* invalid a; unlike an additive public feature pad this collapses all invalid prescribed outputs to a common value. Fast exponentiation requires O(log p) matrix products. This is a concrete algebraic change from a low-degree feature interpolation attack, but does not supply a secure publicly serialized Build/Open hiding R and gamma.

## Decisive complete-public leakage
Suppose a public evaluation exposes ANY pre-power M_g for one invalid a with g!=1, even if all masks R,gamma remain secret. The public trace gives g=tr(M_g)-1 and

    P0=(M_g-g*I)/(1-g).

This recovers the exact supposedly hidden valid-output projector without ANY satisfying assignment, including on a FALSE instance; a single public SHA256 of the reconstructed P0 recovers the frozen S from C. For a fixed nonzero V and uniform gamma, g=1 occurs with probability 1/(p-1); two different nonzero V values cannot both give g=1. The attack is classical and therefore defeats QPT security too. There is no full-public FALSE simulator for this exposed capsule. Using finite-field matrices is ONLY an attacked algebraic encoding, not a discrete-log hardness foundation or fallback.

The proposed next repair, hiding ALL pre-power matrices while allowing public zero-test evaluation, has NOT been instantiated. Publishing only an ideal 'power oracle', attaching an ordinary external source verifier, adding a SHA wrapper, publishing both Yao labels, or assuming a hidden evaluator would merely rename the missing scoped witness-encryption/FE problem. No security claim is based on such an oracle.

## Executed bounded checker and provenance
The attached check.py was actually run as python check.py > output.json using Python3 standard library (exit 0). It tests every 16^3 triple of 4-bit local choices in FALSE clauses A:t=Ch(x,y,z), B:t=Ch(x,z,y), C:y!=z, and companion TRUE instance C:y==z. All affine matrices match V. FALSE has zero satisfying global paths although 512 locally accepted but inconsistent paths exist; TRUE has 4 satisfying paths. With p=2^127-1 a sample invalid matrix has M^(p-1)=I but leaks P0 and the synthetic fixed 256-bit payload via the spectral formula. This is NOT genuine Bitcoin/Syscoin source authentication, SHA mining, NIZK, QPT experiment, native Bitcoin signing, or practical FE.

Executed LOCAL checker SHA256 f73c59640a7e768c1d46b404ba4e25f87f86354b3a5e29658dda3e2f6751559d (Git blob f20e60d46bd1f2a56668a8be95dae3d54b40a027).
Executed LOCAL output SHA256 a697d96d22965ff3a7e37f52c78a444f2bf96efbe4324f86d3154bf4293aa37b (Git blob de8c173d93f53962049d426255495e8044b6b59c).

## ORIGINAL stopping point
ORIGINAL remains three independently qualifying OR grounds: same-anchor greater exact Bitcoin work, finite authenticated specific burn fault/nonmembership/refutation, and relevant incompatible Syscoin history or independently authenticated tag fault at required LC depth. Strict contextual modern AuxPoW/one exact parent tag and every claim/UTXO/withdrawal/burn/amount/recipient/source anchor/window/deadline/reset/native message/VK/capsule binding remain mandatory. R316 is only a stale-tag-reference regression, not a failure of the user's history-conflict LC.

Still MISSING a classical PPT serialized Build_inc(x_W,S)->C and PUBLIC Open_inc(C,w)=S for every ORIGINAL witness, and independent full-public FALSE/hard-TRUE QPT recovery/native forgery -> actual ORIGINAL certificate or justified primitive break, including malicious setup, source coins and sibling capsules. This candidate is INSECURE even before distributed setup or native endpoint work. No progress comment, user breakthrough alert, production edit, deployment, or automation change.
