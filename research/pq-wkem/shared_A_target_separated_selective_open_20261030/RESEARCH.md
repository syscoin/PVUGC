# Shared-A, separated-target dual-LWE SOURCE — exact restricted proof and efficiency result

**Status: POSITIVE restricted SOURCE-only advance; NOT a generic NP witness-KEM.** This construction reduces public SOURCE matrix storage across independently protected claims without weakening the *specified* complete-public ordinary-QPT-LWE game. It additionally handles adaptive opening of other independent native keys and their encryption coins, and it explicitly instantiates one class of previously released SOURCE-opening correlations. It does NOT instantiate ORIGINAL-witness release, fixed-FALSE ORIGINAL soundness with useful release, arbitrary hard-TRUE extraction, or a fundable PQ Bitcoin endpoint.

## Provenance and selected prior component

Research record shared_A_target_separated_selective_open_20261030, automation turn 11, 2026-10-30. Existing syscoin/PVUGC PR #1 is open/draft/unmerged on research/pq-wkem-validation-20260918, starting SHA 50ff929ce7e3022ed6b6600a0d6bd1336c3afeaf. Latest substantive ordinary comment read: 6523417583. Exact relevant predecessor files read at that SHA: uniform_target_batched_lwe_20261030/RESEARCH.md blob d1bc72cf6b2692ee73783d086931014917631859 and fractional_lp_spike_no_go_20261030/RESEARCH.md blob 198511fe7688e41d22f3b35dcda0889f1ee027f8. No internet research, PR diff, historical archive sweep, or independent agents.

The precursor honestly samples a fresh independent uniform M=[A|U] for each SOURCE scope, and its classical release algebra and source-only QPT hybrid work, but public A costs n*m field elements for every claim. This continuation proves safe reuse of **honestly generated A only**, never target U, native sk, or encryption coins.

## Classical-PPT algorithms, full public distribution

For each preauthorizing signer h=1..N, independently and honestly sample a **public** A_h uniformly from F_q^(n x m) and bind it by authenticated transcript to h. For each independent scope s (ORIGINAL relation id, x, claim/UTXO, branch, anchors/window, context, intended PQ-native challenge path and authorization policy), independently sample U_{h,s} uniform in F_q^(n x L) and (sk_{h,s},pk_{h,s}) from the genuine Native.KeyGen. Never reuse the same native secret or SOURCE target across scopes. The honest signer controls its A_h,U_{h,s},pk binding against N-1 malicious participants.

Use odd prime q, L canonical digits of the **real native secret**, constant-weight signed T={z in {-1,0,1}^m : ||z||_0=w}, bounded independently sampled error distribution chi on [-B,B], ell bits per digit and g=floor(q/2^ell) with g>2B(w+1) and non-overlapping circular digit centers. Honest Setup holds no SOURCE short preimage or trapdoor. For same-scope capsule j, sample fresh uniform r_{h,s,j} in F_q^n and independent eta_{h,s,j} from chi^(m+L), publishing:

    c_{h,s,j} = A_h^T r_{h,s,j} + eta_{h,s,j,1:m}
    d_{h,s,j,l} = U_{h,s,l}^T r_{h,s,j} + eta_{h,s,j,m+l} + g*a_{h,s,l}   (mod q).

Publish real pk_{h,s}, full related capsules, attestations, x, context and auxiliary records. Setup authenticators are separate from native protected challenge secrets; the latter never sign pre-funding challenge transactions. Erase/protect sk and r/eta after valid pre-funding checks. No claim here that the unsolved graph or consensus endpoint actually enforces those checks.

The SOURCE relation accepts Z=(z_l)_l iff z_l in T and A_h*z_l=U_{h,s,l} for all l. The public OFF-CHAIN release computes d_l-z_l^T c and uniquely nearest-center decodes all a_l, then verifies canonical Native.PK(sk)=pk_{h,s}. Since

    d_l-z_l^T c = g*a_l + eta_{m+l} - z_l^T eta_{1:m},

the absolute centered error is at most B(w+1) for **every distinct legal SOURCE tuple**. Every legal tuple recovers the exact same precommitted native sk, regardless of its internal states. This says NOTHING about turning an ORIGINAL Syscoin fork witness into Z. With C scopes per honest h, the precursor pairwise-independence calculation and union bound give Pr[some signed-short target lacks a preimage] <= C*L*q^n/|T|, an existence result, never an efficient opening algorithm.

## QPT complete-public selective-opening theorem

**Independently justified assumptions only:** nonuniform QPT decisional LWE for EXACT uniform M in F_q^(n x(m+L)), uniform r and chi^(m+L) error, distinguishing (M,M^T r+eta) from (M,V_uniform); actual native signature EUF-CMA against nonuniform QPT with only classical, permitted nonchallenge signing queries; separately authenticated setup records. Adversaries can be arbitrarily coherent QPT and receive independent quantum advice, the full classical public joint view of C*N slots, real pk and setup records, adaptive corrupt signer contributions, and polynomially many related capsules. They can adaptively learn COMPLETE sk,r,eta of other scopes, including earlier legitimately settled claims. Their relevant auxiliary information must be efficiently simulatable from the public challenge plus independent opened slots, not a hidden challenge key or an unimplemented SOURCE-opening oracle. No superposition decryption/signing/opening queries and no target sk/r/eta leakage.

Fix never-opened honest slot (h,s) with J_s related capsules. The ordinary LWE challenger provides one uniform M_t=[A_h|U_{h,s}] and vector V_t that is LWE or uniform. The simulator chooses all OTHER honest U_{h,i} independent uniform, all their genuinely signed keys and ciphertext coins, and can return their exact sk/r/eta on adaptive Open(i) requests. All other honest signers have independent A; corrupted signers are simulated by running the QPT adversary itself. Target sk and native pk are genuine in the LWE hybrid, so the challenger V_t is shifted only in the final L coordinates by the genuine secret digit vector g*a_{h,s}. The remaining J_s-1 target capsules are sampled honestly using the same challenge M_t. If the attacker asks to open the target, the win event is defined to be false and the reduction stops rather than inventing ciphertext coins. All full-public checking keys and supplementary correlations are retained; no SourceOpen oracle, extractor for a supplied representation, or classical/quantum rewinding.

Successively replace the J_s whole target ciphertext vectors (not isolated scalar pads). Every other-source column U_{h,i}, ciphertext, opened key, opened coin, auxiliary and native checking-key record is simulatable as postprocessing of the same uniform challenger M_t plus independent honest randomness and adaptive adversary choices. Consequently each step costs at most ONE ordinary nonuniform-QPT decisional-LWE advantage. In the final all-uniform target hybrid, the protected ciphertexts are independent of target sk, while pk remains genuine. A fresh unauthorized native challenge signature, or recovered usable sk which signs a fresh message, forges native QPT EUF-CMA. For each fixed never-opened honest h,s:

    Pr[unauthorized h native signature or usable key]
       <= J_s*Adv_QPT-LWE + Adv_QPT-Native-EUF-CMA + Adv_setup-auth.

For a claim winning with at least one never-opened honest signer, a union/guess over at most C*N possible protected slots yields a corresponding C*N factor. A realistic Bitcoin N-of-N graph, admissible-claim conditions and non-bypass transaction binding remain CONDITIONAL, not instantiated here.

**Selective-opening rule:** Disclosing r and eta of even ONE target capsule reveals g*a_l directly from d_l-U_l^T r-eta_{m+l}, and hence every scope-sharing native key digit. Therefore any same-key capsule opening makes the WHOLE target scope opened; fresh ciphertext coins alone do not create selective-opening security. The proof permits full key/coin openings of DIFFERENT independently sampled U/sk slots. Adversarially computed and voluntarily provided SOURCE Z for other slots can be passed through the simulator as adversary postprocessing, but no automatic honest SourceOpen oracle exists.

## Exact source-correlated auxiliary distribution without SourceOpen oracle

A separately defined classical-PPT **planted SIDE sampler** handles some already-exposed other scopes. Given the *target* challenger's public A_h, sample independent Z_i from T^L, set U_i=A_h*Z_i, independently sample their genuine native keys and ciphertext coins, and publish/open those other U_i,Z_i,pk_i,sk_i,coins. The simulator knows Z_i because it explicitly sampled them; it does not know a target SOURCE opening and does not know the challenge r or eta. This entire arbitrary number of planted side-opening correlations is straight-line efficiently computable from A_h, so the target ordinary-QPT-LWE hybrid is still exact even against coherent attacks on the complete joint view.

For each column Z uniform T and public A uniform, pairwise-universal hashing gives

    Delta( (A,A*Z), (A,U_uniform) ) <= delta
       = (1/2) sqrt((q^n-1)/|T|).

With K independently planted columns and common A, condition on A and telescope product measures: the PUBLIC, PRE-DISCLOSURE target-column distribution differs from K genuinely uniform target columns by at most K*delta. This is tiny at precursor illustrative log2(|T|/q^n) about 1792.5. **After Z disclosure** the joint law is the explicitly planted side experiment; it is NOT universally interchangeable with an unknown real ORIGINAL-witness-derived opening law. Honest protected targets remain genuinely uniform, unplanted. This avoids declaring an unexplained SourceOpen oracle or claiming that artificial planted openings provide future legitimate release.

## Exact regression and efficiency

Reuse of U across scopes is a direct failure: revealing even one valid short SOURCE Z for (A,U) permits release of ANY other same-(A,U) capsule regardless of fresh r,η, independent signing keys, native pk and context. Independent U is essential; neither public basis changes nor domain-separation strings alone prevent this equation.

For illustrative **uncalibrated** q=16777213, n=256,m=6800,w=2000,B=128,ell=5,L=52, 3 bytes per field element, A occupies 5,222,400 B, U per scope 39,936 B and a batched capsule 20,556 B. N=4 signers and C=100 separate claims would require 2,104,934,400 B in fully independent public SOURCE matrices but just 36,864,000 B with a shared A_h per honest signer and separate U_{h,s}, an exact 98.2487% saving. Two capsules per scope add 16,444,800 B. Native signing material and proof context are excluded. These parameters are NOT validated for concrete 128-bit QPT hardness; no unsupported native PQ Bitcoin resource claim is made.

Exact Node/V8 checker check.js and captured OUTPUT.json are committed with this note. It checks 134 finite assertions: full small q=5 signed-short/source TV enumerations, two-side same-A total-variation telescope, source preimage count moments, distinct valid opening recovery of the same precommitted bit, and exact storage calculations. Separately, an extended local-only standard-library Python checker check.py ran twice byte-identically with 428 assertions, including 3 independent scopes, 2 related capsules and 8 digits per scope, coin-opening leakage and deliberate same-U cross-claim failure. It is preserved in a local archive; only check.js is the publication's exact executed checker. No quantum security test was performed.

## Handoff and nonclaims

This is **not** the missing ORIGINAL W-to-SOURCE reduction. There is NO classical-PPT Comp(R_original,x,claim,context,pk) and Lift(x,W,M_x) allowing EVERY valid ORIGINAL W to obtain the same native sk; no jointly simulated source-dependent ORIGINAL correlation; no fixed-FALSE useful-release security; no arbitrary hard-TRUE final-key/native forgery to ORIGINAL W or independent PQ break; no malicious complete one-honest funded graph, abort/completeness, authenticated SYS/BTC fork qualification, or deployed native PQ Bitcoin endpoint. Do not resurrect the failed structured signed-unit pseudo-openings, assume a retained source trapdoor, or claim that efficient SOURCE sampling supplies witness release. This research-only component may be reused in a future successful compiler but the automation cannot be considered complete.
