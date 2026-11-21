# R147 — Globally nonlinear ORIGINAL ideal-mask SOURCE: public key-projector theorem

**Status:** REJECTED candidate, negative security-foundation checkpoint. This is not a secure generic witness-KEM and should not trigger a routine user notification. No optimization of the restricted LWE-credential scheme was attempted.

**Continuity:** syscoin/PVUGC draft PR #1, branch research/pq-wkem-validation-20260918, starting head b52e0e20cac54f78aa4c4a08245eb528a35d3b5a. Exact R146 note research/pq-wkem/r146_cyclic_local_marginal_20261107/RESEARCH.md, Git blob c50f63513161b85f6d215d139a85b1b2a452e81c, was read at that head. R146's affine complete-local-marginal false odd-XOR witness had fractional half/half components. This iteration replaced local factor consistency by GLOBAL nonlinear ORIGINAL Booleanity and clause equations, to see whether a direct coefficient-release could enforce actual ORIGINAL witnesses instead of pseudomarginals.

## Exact candidate and classical-PPT honest release

Encode the actual ORIGINAL NP verifier as Boolean 3CNF in n variables, including the actual claim/UTXO, branch, anchor/window, context and verification-key identity in the statement. Over F_q, let f_i(z)=z_i(z_i-1) enforce actual Booleanity, and for each original clause C, let f_C(z)=product over literals l of (1-l(z)) be the clause-failure polynomial. On a Boolean assignment w, all f vanish exactly when the ORIGINAL relation holds. Original witness privacy is not required.

Choose a publicly explicit polynomial monomial basis of dimension N=poly(n,lambda) containing constant 1. Let M_x be the N by t coefficient matrix of publicly selected products m(z)f_j(z) fitting the basis, where monomial m ranges over a degree-bounded polynomially enumerated set. It includes the complete global constraints, not merely local marginals. Let e0 be the coefficient vector of constant 1.

Constructor chooses the bound frozen capability K in F_q and independent uniform masking vector r in F_q^t, then publishes P=K e0 + M_x r in F_q^N, together with relation, statement, checking key, context, auxiliary fields and related capsules. Honest off-chain Open(w) FIRST verifies the ORIGINAL Boolean witness and context, and THEN evaluates the public polynomial P at w, obtaining ev_w(P)=K. This is exactly the same capability for every valid ORIGINAL witness, even for distinct assignments or internal states. Both setup and opening are classical PPT for explicit polynomial-size basis. Bitcoin does not execute this verifier. This construction is not yet a native-signature capsule or distributed setup.

## General coefficient-exposure lemma (proof; not a hardness assumption)

Define the public subspace V_x=image(M_x) and coefficient vector e0. For uniform r, P is uniformly distributed on the affine coset K e0+V_x.

* If e0 lies in V_x, all these cosets are identical: P is statistically independent of K. This may happen on FALSE instances admitting low-degree polynomial ideal refutations of 1.
* If e0 is NOT in V_x, ordinary public Gaussian elimination finds lambda with M_x^T lambda=0 and e0^T lambda=1. Then lambda^T P=K for **every** setup tape, without any witness, without a source decryption key, and without an adversary supplying an internal representation.

Every TRUE ORIGINAL instance necessarily has e0 NOT in V_x: any genuine witness w gives ev_w^T M_x=0 and ev_w^T e0=1, contradiction if e0 were in image M_x. Critically, although ev_w depends on an ORIGINAL witness, Gaussian elimination produces some lambda **without finding w**. Consequently the candidate is broken for EVERY satisfiable instance, including witness-search-hard true instances, by deterministic classical polynomial time. When a FALSE instance lacks a low-degree ideal refutation, it may leak K as well.

The statement covers every finite polynomial-size coefficient basis and arbitrary nonlinear Booleanity/clauses so long as source coefficients are exposed in this affine public form. This is a broad architecture-specific impossibility, NOT a general impossibility of witness encryption. All public J/CK/Aux fields and related capsules only add information: the attack requires just M_x and P. It already violates unauthorized hard-TRUE release; any native signature built with that capability is consequently exposed. Quantum coherence is irrelevant because the public classical attack succeeds with probability 1.

## Bounded independent checks and reproducibility

The exact published JavaScript checker (checker_code_mode.js) was executed in the authorized connected V8 code runtime and passed 3,542 assertions. It constructs the F_101 degree<=3 monomial basis in two Boolean variables, genuine Booleanity polynomials, and 10 literal/2-literal clauses. Across all 175 one-, two- and three-clause formulas, 149 are satisfiable, 26 are false. Every satisfiable formula exposes a public witness-free linear projector and yields exactly the same K for every valid ORIGINAL witness on both checked setup key values. A distinct locally executed Python standard-library checker also passed 1,174 assertions for the same class and one explicit fixed-FALSE control; the independent Python file is LOCAL-ONLY and not claimed as published.

These finite checks verify the modular linear-algebra implementation; the general theorem above is the proof. Neither checker measures QPT computational hardness or instantiates arbitrary-witness SOURCE privacy.

## Attempted LWE repair and precise failure of the composition

Replace coefficient exposure with a genuine statement-dependent LWE-style phase: c=M_x^T s+e, p=b_x^T s+Delta K+eta. Every valid short ORIGINAL witness evaluation vector z_w would need M_x z_w=b_x, giving a decodable p-z_w^T c. However, R138–R146 demonstrate unauthorized fractional/integer pseudocertificates for related structured matrices. Here M_x is entirely derived from the ORIGINAL constraints, not an independently uniform LWE public matrix. Left multiplying by a public invertible random U does not make its public rowspace indistinguishable from a uniform matrix. There is no provided reduction embedding an ordinary scalar-LWE challenge into the joint distribution of M_x, c, p, all CK/J/Aux, sibling capsules and adaptive permitted openings without the challenge secret. A publicly computable arbitrary lambda in the cleartext theorem need not have a low-noise norm when coefficients are encrypted, so the cleartext theorem alone does NOT prove that all such LWE releases are broken.

This attempted encrypted repair therefore remains UNINSTANTIATED, not an accepted successor or new QPT hardness assumption. No SOURCE-opening oracle, canonical/common witness, hidden iO, or extraction from adversary-volunteered representation is allowed. No native-bridge, malicious N-of-N setup, abort/DA or deployment claim follows.

## Exact next missing equation

Construct honest classical-PPT Comp(R_ORIGINAL,x) jointly with a real challenge simulator for the COMPLETE public source distribution, so that Open(Comp(R_ORIGINAL,x),w)=one same precommitted native capability for every actual valid ORIGINAL witness; and turn arbitrary unauthorized QPT final-key recovery/accepted native forgery (NOT an adversary-supplied internal vector) into an actual ORIGINAL witness or independent justified QPT break. The needed encryption must prevent public coefficient-space extraction while preserving every valid witness path. This step remains missing and was NOT materially reduced. Stop cleartext ideal-mask variants; no optimizing or routine negative update.

**Provenance:** GitHub PR metadata, latest ordinary relevant issue comments and exact R146 file were read through the permitted connector only. Exact JavaScript function source and captured output accompany this file. Additional Python derivation/checker/output are separately preserved locally and not GitHub-published. No external web/literature research, full PR diff, independent agent, production edit, native functionality or deployment was involved.
