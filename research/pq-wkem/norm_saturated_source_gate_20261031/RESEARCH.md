# Norm-saturated 3CNF-to-affine SOURCE: exact representation lemma, rejected secret release

**2026-10-31, bounded offline research iteration. Status: NO positive secure PQ witness-KEM advance.** This supporting note corrects the idea that a norm-sound 3CNF-to-short-solution compiler fixes the false/hard-true key-recovery gap in the existing statement-bound binary-ISIS and quotient-noise candidates. Not for production or deployment.

**Provenance:** syscoin/PVUGC PR #1, existing open/draft/unmerged branch research/pq-wkem-validation-20260918, starting head 58bd840ceb05efdbb2e217f47794cbd5dad14b1a. Latest ordinary substantive comment read: 6542499938. Exact predecessor read: research/pq-wkem/quotient_noise_gate_20261031/RESEARCH.md, Git blob 30f2e92112ef1508c9c500ea2a604ba0705a3399. No external research. The full independent Python implementation and captured outputs are in the local research archive.

## Explicit witness-free ORIGINAL compiler

For any 3CNF F with n Boolean variables and m clauses, put P=n+2m. Construct an integer affine system A_F z=t with 2P columns and n+3m rows. Every bit (original variables and two slack bits per clause) is a complement pair (z_{j,0},z_{j,1}), with equation z_{j,0}+z_{j,1}=1. The first n pairs encode the ORIGINAL variables. For each clause c add the equation

    L_c(z) - a_c - 2 b_c = 1,

where L_c is the sum of three literal values, and a_c,b_c are the low and high slack bits. This A_F,t is computed *without* a satisfying witness in classical polynomial time.

Every satisfying ORIGINAL assignment W extends to a binary vector z(W) with A_F z(W)=t and squared norm ||z(W)||²=P, using the binary encoding of L_c(W)-1 ∈ {0,1,2}. All satisfying W may have different z(W).

**Proved short-opener soundness, but ONLY for submitted representations:** If integer z satisfies A_F z=t and ||z||²≤P, every pair must be (1,0) or (0,1). The proof is that for integers a+b=1, a²+b²≥1, equality only for the binary pair; summing P pairs saturates the bound. All clauses then hold. The first n variables extract an actual ORIGINAL witness. This exact representation-to-ORIGINAL lemma needs no SIS assumption. For modular equations use centered lifts and q>2(6√P+1), so sufficiently short modular solutions satisfy the integer equations. It does NOT extract W from an arbitrary cryptographic final-key adversary.

## Joint real SOURCE generation, capsule and public release

For each precommitted master-key bit k_j, sample s_j uniformly from Z_q^{n+3m}, independent mean-zero per-coordinate noise e_j with |e_j,i|≤B and e*_j with |e*_j|≤B. Generate and publish BOTH related source and ciphertext fields:

    beta_j = A_F^T s_j + e_j mod q,
    tau_j  = t^T s_j + g k_j + e*_j mod q.

Include F, ORIGINAL relation identity, claim/UTXO, intended branch, anchors/window/context, native checking key and auxiliary data in the complete public view. Related capsules only add public information. The checker uses mock key bits; actual native signing keys are NOT implemented or tested.

Public Release using any valid ORIGINAL W first forms z(W), then decodes

    center(beta_j^T z(W) - tau_j) = -g k_j + e_j^T z(W) - e*_j (mod q).

Every binary z(W) has L1 norm P, so g>2B(P+1) and q sufficiently large give exact **every-ORIGINAL-witness SAME-precommitted-capability correctness**, without a common intermediate witness state. This is a real release algorithm, not a SourceOpen oracle.

## The decisive FALSE/hard-TRUE classical attack (arbitrary 3CNF)

Choose *any public Boolean assignment* W0, for example all zeros, without solving F. For each clause it violates (L_c(W0)=0), set the low slack a_c=-1 and high slack b_c=0, encoded as integer complement pairs (2,-1),(1,0). For satisfied clauses use the usual legal slack pairs. The resulting public integer vector z0 satisfies A_F z0=t **exactly**, independent of whether F is satisfiable. If u≤m clauses are violated, then

    ||z0||² = P+4u,       ||z0||_1 = P+2u.

When u>0 this is not an accepted short opener; the API can correctly reject z0. But the public linear ciphertext cannot enforce this optional check against an attacker. In the actual sampled, fully correlated SOURCE distribution,

    center(beta_j^T z0-tau_j) = -g k_j + X_j,
    X_j = e_j^T z0-e*_j.

For independent centered noise bounded by B, Hoeffding (no classical rewinding or quantum lifting) gives the one-bit error bound

    Pr[ |X_j|≥g/2 ] ≤ 2 exp(-g²/[8B²(P+4u+1)]).

At the *minimum* deterministic legal opening gap g=2B(P+1)+1, a union bound for the whole 512-bit master yields

    Pr[any wrong bit] < 1024 exp(-(P+1)²/[2(P+4m+1)])
                      ≤ 1024 exp(-(P+1)²/[2(3P+1)]).

For P growing with security parameter this is negligible. Thus a fixed trivial Boolean W0 gives unauthorized final K with overwhelming probability for every sufficiently large F, even arbitrary FALSE or hard TRUE. No nonwitness representation is supplied to the defender; the attacker simply evaluates public fields locally. Authentic native vk/context, any auxiliary data and related capsules cannot undo the one-capsule exposure. This is a classical PPT attack valid a fortiori against arbitrary nonuniform QPT adversaries.

**Scope of theorem:** It rules out this particular bounded, mean-zero independent-error affine LWE release with deterministic all-witness gap. It does not rule out general WE, standard QPT LWE, or an actually instantiated nonlinear cryptographic enforcement. The structured A_F distribution is not uniform, so ordinary QPT-LWE already lacks the required joint-public challenge simulator.

## Exact checker and observed output

The published checker.js is formed verbatim from the function actually executed twice in the restricted JavaScript environment; output.json is its captured result. It passed 7,201 assertions identically twice. An independent local Python standard-library checker also passed 7,324 assertions twice, with byte-identical output. The latter initially had an internal assertion typo (FALSE spacing g used instead of TRUE g_true), corrected before final checks. Neither executes genuine native SLH signatures or measures QPT hardness.

Test FALSE instance: all 8 polarity 3-clauses on three variables, repeated four times, yielding zero original satisfying assignments. P=67, 99 rows, 134 columns, a fake z0 with squared norm 83 and L1 norm 75, q=65537, B=1, g=137. Full generated beta,tau gave 512/512 attacker-recovered mock master bits. Exact fixed-fake 512-bit union bound 7.59327670534584e-10. Separate TRUE formula has six distinct original witnesses, each releasing all 512 bits of one master (3,072 evaluations). All software models here are toy finite-field/bit calculations.

## Handoff, proof gaps and prohibited shortcuts

**No positive secure WKEM advance.** The algebraically norm-sound SOURCE representation is not final-key extraction: it has a separate, explicit classical FALSE-key attack. The next compiler must cryptographically enforce the Boolean/norm constraints *inside public release*, rather than optional API checks or special noise choices. Needed is a classical-PPT witness-free Comp with all-ORIGINAL-witness Lift recovering one bound K, **joint** generation and QPT challenge simulation of (F, capsule, genuine native vk, context, aux, related capsules), and a proof that arbitrary unauthorized FALSE/hard-TRUE final-key recovery or accepted native forgery yields an actual ORIGINAL W or independent QPT break, without requesting the adversary's internal z. These equations are missing; no SourceOpen oracle, stronger uninstantiated structured-LWE or hidden verifier is being assumed.

Malicious one-honest N-of-N setup/abort/DA graph, SYS/BTC qualification and the hypothetical Bitcoin no-EC native endpoint remain separate unresolved obligations. No actual PQ WKEM, proof of 128-bit QPT security, native implementation or Bitcoin deployment is claimed.
