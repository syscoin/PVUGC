# Run 551 — distributional LWE release versus chosen false-instance hiding

Verified starting state: `syscoin/PVUGC#1`, draft/unmerged, branch `research/pq-wkem-validation-20260918`, head `c5d68d3c110803e1abd63c11acca7528af60c4e8`. Exact Run 259 source-binding and Run 548 frontier note were read, along with the CLZ applicability assessment. Negative bounded checkpoint, not a practical WKEM.

## Concrete minimal candidate

For prime q, public A in Z_q^(n×m), b in Z_q^m, and threshold B, define the restricted NP relation

R_LWE((A,b),(s,e)) = [b=A^T s+e mod q AND ||e||_infinity <= B].

Setup chooses an independently protected capability bit mu, samples r uniformly in {0,1}^m, and publishes (u,v)=(Ar, <b,r>+floor(q/2)mu) modulo q. Given any valid (s,e), evaluation rounds v-<s,u> = <e,r>+floor(q/2)mu to mu. If Bm<(q-1)/4, ALL valid witnesses recover the SAME capability bit; their intermediate states can differ. Repetition with independent r encapsulates a context-bound capability, not an exposed common master secret. Honest setup/evaluation are classical PPT. This is a restricted LWE-key relation, NOT authenticated ORIGINAL SYS/BTC evidence. It neither supplies keyless retained-coin builder security nor a Bitcoin endpoint.

## Positive average-public-key lemma, not worst-case security

For independently uniform A,b the linear family h_(A,b)(r)=(Ar,<b,r>) is two-universal over binary r. The leftover-hash lemma gives

TV((A,b,Ar,<b,r>),(A,b,U_{Z_q^(n+1)})) <= (1/2)*sqrt(q^(n+1)/2^m).

Uniform public keys admit any bounded-error representation with probability at most q^n*((2B+1)/q)^m. Conditioning a random key on being false therefore changes its distribution by no more than that probability. This is statistical hiding over randomly sampled public keys, including independent auxiliary inputs and quantum postprocessing; it is NOT false-instance QPT hiding for adversarially selected (A,b). No practical QPT-LWE hardness or 128-bit parameter claim follows. The toy parameters below do not make the leftover-hash bound nonvacuous.

## Chosen-false near-secret attack

Sample uniform A and a secret s that the attacker knows. Set e_bad=(B+1,0,...,0) and b=A^T s+e_bad mod q. The pair (s,e_bad) is invalid. For each other s'!=s, uniform A makes A^T(s'-s) uniform in Z_q^m, so

Pr[there exists any valid (s',e')] <= (q^n-1)*((2B+1)/q)^m.

Nevertheless if B+1<(q-1)/4, public-capsule decryption under invalid near-secret s gives

v-<s,u>=<e_bad,r>+floor(q/2)mu,

where <e_bad,r> is either 0 or B+1. It therefore RECOVERS mu for EVERY r. This attack works on an ORIGINAL-false restricted-language key with overwhelming probability, under honest setup, independent capsule randomness, arbitrary public checking keys, erasure and context separation. It is classical PPT, hence an arbitrary-QPT break. Unlike Run 541's directly public linear projector, this example has a standard Regev-like ciphertext and a valid *distributional* statistical secrecy lemma; the false-key security quantifier is the decisive gap, not a proposed repair of Run 541.

## Source-extraction and attack taxonomy

The attack returns the capability directly without an accepted Run-259 representation z. A public infinity-norm check does not constrain algebraic decryption of a published (u,v). Run 259's zero-residual/SIS extraction theorem only applies AFTER a complete accepted z exists, which this construction does not supply. No ORIGINAL-to-LWE relation-preserving compiler exists here. No secret-state local mixer beyond the arithmetic rounding frontier is assumed.

Relevant attack families: (1) local rounding/tolerance seam is broken; (3) uniform-key statistics conceal chosen-key weakness; (4) independent multiple ciphertexts all leak; (5) adaptive chosen-statement selection wins; (6) malicious setup is not needed; (7) context binding does not repair near-secret decryption; (8) checking keys can validate guesses, not prevent recovery; (9) no coherent-only attack is needed. Permutation gauge/cycle attacks are not relevant to this arithmetic gadget. QPT positive security: NONE. No new complete primary-literature proof audit was completed; Regev decryption and the leftover-hash lemma are standard ingredients.

## Exact executed checker

`run551_lwe_boundary_check.py` (standard library, deterministic) at q=257,n=2,m=6,B=1: 12 chosen false instances; all 792,588 candidate s' enumerated without any valid witness; 1,536 legitimate and 1,536 illegitimate decryption checks; 256 checks across two distinct valid witnesses in a rank-deficient key. Two independent executions produced byte-identical output, captured in `run551_lwe_boundary_validation.json`. This tests finite algebra, not security.

**Handoff:** A conventional LWE decryption frontier already exhibits different valid witness states recovering the same secret for a restricted key relation, but its soft rounding admits known invalid near-secrets. Distributional LWE hiding does not imply WE-style chosen-false-instance hiding. Exact source authentication jointly with protected release, and arbitrary-QPT unauthorized-signature/capability recovery -> ORIGINAL witness or independent break, remain UNPROVED. N-of-N, multiple-capsule, 128-bit resources, and conditional P2MR/SLH Bitcoin graph also remain UNPROVED. The stopping condition is unmet.
