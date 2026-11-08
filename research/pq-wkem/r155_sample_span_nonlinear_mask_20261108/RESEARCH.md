# R155 — Unknown-support nonlinear Boolean masks: known-key sample-span recovery

STATUS: REJECTED as a repair to exact-linear ORIGINAL-witness release. This is an offline, one-candidate structural theorem, not a secure witness-KEM, a QPT security argument, or a performance optimization. It extends R154's explicit polynomial-ideal coefficient-span attack to arbitrary nonlinear mask samplers whose effective span is not made public, under a precisely required conditional known-key sampling interface.

CONTINUITY: PR #1 research/pq-wkem-validation-20260918, open/draft/unmerged. Observed starting SHA ccf4e958a00df0ff11ed2ac1074af677120f730f, parent R153 0b759ede8706926690a0116ddb85d4efc54f4e40. Exact R154 source blob b0ed5443ae55d5c069ef2261545e5d20f9fb980f read before starting; latest ordinary substantive comment 6718361572 (R153). Only the authorized connected GitHub research branch was used for continuity; no internet/literature research.

## Candidate and actual distributions

Let x denote an ORIGINAL arbitrary-NP instance with claim/UTXO, branch, anchors/window, relation identity, native VK and challenge context bound into fixed public parameters pp. Fix q a prime power, V=F_q^N for a polynomial N, public vector v(pp) not zero, and public offset a(pp). A classical-PPT known-key conditional source sampler takes the *same fixed public pp* and fresh independent honest coins r and outputs

    C_K = a(pp) + K v(pp) + F(pp;r), K in F_q.

F can be any computationally complicated nonlinear mask mapping; its output distribution need not be uniform over its support span, and no linear generator/basis need be published. The key premise is that the adversary can run a public classical-PPT Sample0(pp) that produces independent samples distributed exactly as the target's F(pp;r) conditional on the same target pp. A general unconditional Build that samples a different native signing key or secret-correlated public setup is NOT enough. The attack reads only C_K; if complete public checking keys, auxiliary/context and related capsules also exist, they cannot conceal a K already released by this visible projection, but they may render the same-pp sample interface unavailable.

Exact all-valid-witness linear opening means: for each satisfying ORIGINAL witness w, a (possibly distinct) linear functional L_w:V->F_q exists with L_w(v)=1 and L_w(F(pp;r))=0 for all honest r. Removing a is public. Thus L_w(C_K-a)=K, with no canonical witness or common internal representation. The proof chooses w only existentially; the attacker does not obtain, compute or request w.

## Distribution-free polynomial sample-span lemma

Let X_1,...,X_m,X_* be independent and identically distributed on F_q^N, under ANY distribution. Put S_m=span_Fq(X_1,...,X_m). Then

    Pr[X_* not in S_m] <= N/(m+1).

PROOF: Set R_j=rank(X_1,...,X_j) and p_j=Pr[X_{j+1} not in span(X_1,...,X_j)]. By coupling a common infinite sequence and using one common independent next sample to compare nested spans, p_j is nonincreasing. Since each new independent direction increments the rank by one,

    sum_{j=0}^m p_j = E[R_{m+1}] <= N.

Nonincreasing p_j gives (m+1)*p_m<=N. No minimum support probability, full-support assumption, uniform source, explicit subspace basis or computational assumption is needed. Over finite fields, Gaussian elimination is polynomial in N,m,log(q).

ATTACK: For fixed target pp, draw m independent Sample0(pp) outputs X_i=F(pp;r_i). Given C_K, solve

    C_K - a = alpha_1 X_1 + ... + alpha_m X_m + K_hat v

for alpha and K_hat. Existence of even one valid w in the mathematical proof implies v is NOT in S_m: L_w kills every X_i and sends v to one. Thus any solution has the same K_hat. When the target mask X_* lies in S_m, the solution exists and K_hat=K. With m=4N, the failure probability is <1/4 for ALL mask distributions. For larger m=poly(N,lambda) one can lower it to any desired inverse-polynomial threshold; do not assert a negligible universal failure bound from fixed polynomial m. K_hat is recovered directly, without enumerating q possible keys or assuming any adversary-supplied representation.

The attack is classical, so it defeats arbitrary-QPT unauthorized hard-TRUE security too. It is already a key-recovery attack; no FALSE-instance indistinguishability or signature-forgery reduction is needed.

## Exact limits and implications

This theorem requires *exact* linear witness annihilation and a *public same-pp* known-zero mask sampler. It does NOT apply automatically to noisy threshold rounding, to source views for which F cannot be independently resampled under the target public setup, or to genuine LWE ciphertexts where noise causes the masks to span the entire ambient space. It does not prove that computational witness encryption is impossible, that LWE is insecure, or that arbitrary nonlinear witness opening leaks. It is distinct from R153's NP-in-SZK complexity consequence for statistical FALSE hiding, and from the R137/R138 fractional attacks on particular noisy linear decoders.

R154's public ideal matrix is one explicit case (F=M_x r). More importantly, hiding or nonlinearly generating a polynomial-dimensional mask-support basis does not repair exact affine-message/linear-witness SOURCE if an adversary can make known-key samples under fixed pp. The degree of F and visibility of its support basis do not enter the sample bound. A genuinely viable repair must abandon at least one exact premise, not merely change nonlinear polynomial coins.

## Executed bounded checker and provenance

The exact Python 3 standard-library checker in this folder was executed offline with fixed seed 15520261108. It forms an unknown 4-dimensional mask span inside F_101^8; a degree-two/three nonlinear four-random-input source uses hidden basis columns. Two distinct ORIGINAL-witness-style exact linear evaluators e0 and e1 always recover the SAME K. A public sample-only Gaussian attack (32 independently sampled known-zero masks) recovered the secret in 512/512 seeded trials. The checker also did exact-rational dynamic-programming probability enumeration for a skew distribution in F_3^3, checking the nonincreasing escape probabilities and universal bound for m=0..8. It passed 1,545 finite algebraic assertions. A second execution reproduced byte-identical output. None of these checks establish any PQ hardness; the displayed inequality is proved algebraically above.

Local SHA-256 provenance: checker.py 207691fe045bc60c21afab54beb08d011be5fbde60d3385767b92c42b246ccb8; output.json bc2df4508c54568d301e7daa79010eb1d83695f2e82b468474d79fea8eb154a0. The research markdown is a standalone coherent derivation, rather than the full R154 replay. Publication of code and captured output does not establish a successful generic WKEM.

## Next original-NP security obligation

Construct a concrete classical-PPT ORIGINAL-NP-dependent release and full joint public simulator whose source cannot be recovered by either (i) the statistical-FALSE-hiding NP-in-SZK boundary of R153 or (ii) this exact-linear known-sample span learner. An ordinary-LWE-based route must instantiate its genuine statement-dependent setup/openings and straight-line challenge simulator together, with all public checking, auxiliary, context, related-capsule and selective-opening correlations reproduced on the actual challenge. All valid ORIGINAL witnesses must recover the SAME precommitted claim/path-bound native capability; arbitrary unauthorized QPT final-key recovery or accepted native forgery must imply an actual ORIGINAL witness or an independent justified PQ break, not an adversary-volunteered internal representation. Preserve malicious N-of-N honest-cut, abort/erasure, DA and the conditional Bitcoin native endpoint; no optimization or deployment.
