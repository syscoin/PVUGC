# Signed-unit Boolean lift versus FALSE-instance key recovery — rejected candidate

**No positive generic PQ witness-KEM construction advance.** This is a self-contained negative control for an attempted witness-free ORIGINAL-to-SOURCE compiler. It is NOT a refutation of uniform-target dual-LWE under its actual uniform-matrix QPT-LWE assumption.

## Exact predecessor and execution

Offline automation turn 10, research branch `research/pq-wkem-validation-20260918`, starting head `4d57f980e7ed8308f8ff0193e85566395bac6d49`; latest substantive ordinary comment `6516094195`; exact predecessor `research/pq-wkem/uniform_target_batched_lwe_20261030/RESEARCH.md`, blob `d1bc72cf6b2692ee73783d086931014917631859`. No external literature, entire diff, or historical replay. Published `check_compact.py` ran **twice identically** with 396 assertions per run; `OUTPUT.json` is the captured exact result. An extended local checker independently ran 397 assertions twice identically and tests modular ciphertexts and random invertible row mixing.

## Concrete candidate, actual release, and full-view failure

Every Boolean verification circuit has a witness-free linearization `C*v=t` with all `v` Boolean. For AND `c=a AND b`, introduce slack bits `s1,s2,s3` and equations

    a-c-s1=0,  b-c-s2=0,  a+b-c+s3=1.

NOT is `a+c=1`, with linear fixed-input/output and equality constraints. These exactly enforce Boolean gates. Set `z=2*v-1`, and publish `A=C mod q, U=2*t-C*1 mod q`; choose odd `q` larger than twice any row coefficient sum. Every ORIGINAL witness `W` efficiently determines a signed-unit `z(W) in {-1,+1}^m` with `Az=U`, and **every accepted signed-unit opening corresponds to an ORIGINAL witness**. Different `W` need not have common intermediate states.

Encrypt a digit `a` of the one precommitted genuine native signing secret via a dual-LWE-style ciphertext

    c=A^T*r+eta,  d=U^T*r+eta_d+g*a (mod q),

with genuine native public checking key retained in the full public view. Every accepted signed-unit opening decodes `a` deterministically if errors are bounded by `B` and `g>2B(m+1)`. Thus this candidate instantiates the **correctness** interface but not a secure SOURCE distribution.

For the FALSE original claim `a=0,b=1,c=1,c=a AND b`, force signed coordinates `z_a=-1,z_b=1,z_c=1`. No signed-unit source opening exists: the first AND equality demands `z_s1=-3`. But a PUBLICLY COMPUTABLE **invalid** pseudo-opening, for `k` replicated gates,

    z_bad = (-1,1,1,[-3,-1,1] repeated k times),

satisfies `Az_bad=U` exactly. An arbitrary public invertible left row mixing `(A',U')=(RA,RU)` preserves this. An adversary can ignore Release's format check and compute

    d-z_bad^T*c=g*a + E (mod q), E=eta_d-z_bad^T*eta.

If `|E|<g/2`, the recovered digit is the **real** precommitted secret digit and the actual native checking key accepts signatures derived from the full recovered secret. SOURCE membership soundness does not imply final-key secrecy.

## Failed redundancy repair, exact probability and proof

Take independent `eta_i` uniform on `{-1,0,1}`, `m=3+3k`, `B=1`, `g=2(m+1)+1=9+6k`, and an odd prime `q>16g` (sixteen digit centers, including modular wrap gap). All honest signed-unit SOURCE openings decode for every possible error. The exact integer-convolution checker gives fake decoding probabilities at `k=1,2,4,8,16,32` of respectively `0.9935985368, 0.9946146421, 0.9983184782, 0.9998996387, 0.9999996798, 0.9999999999963938`.

The centered noise `E` has zero mean, independent bounded summands, and total squared coefficient magnitude `4+11k`. Hoeffding proves

    Pr[|E|>=g/2] <= 2 exp( -(m+1.5)^2 / (2(4+11k)) )
                   = 2 exp( -(9/22+o(1))*k ).

Consequently repeating the local constraints makes the explicit false-source decryption succeed with probability tending to **one**. It does not repair the construction even though the pseudo-vector L1 norm `3+5k` grows faster than the accepted norm `3+3k`. All these attacks are classical polynomial time, hence included among arbitrary QPT adversaries. Public row masks, padding, or checking only accepted SOURCE representations are not repairs. No assumptions about quantum rewinding, random-oracle extraction, or MinRank/SIS hardness are used.

## Exact remaining equation and scope

A secure generic classical-PPT `Comp(R_original,x,scope,pk)` and public `Release(D,W)` must give the **same** native secret for every valid ORIGINAL `W`, **while preventing key recovery by arbitrary algorithms from the complete public view** of every fixed FALSE instance, including linear pseudo-openings outside the accepted representation. For hard TRUE instances, final native-secret recovery or fresh target forgery must yield an ORIGINAL witness or an independent QPT break. All checking key, auxiliary, context and related-capsule correlations, arbitrary N-1 malicious participants, and abort/fundable graph must be included. This candidate fails the FALSE requirement, so it is **rejected** and does not replace the uniform-source restricted result. A future repair needs a truly nonlinear/relation-dependent release mechanism AND its jointly simulated QPT challenge distribution, not a stronger supplied-representation statement.

No deployment, production code, workflow, merge, review, or independent-agent claim.
