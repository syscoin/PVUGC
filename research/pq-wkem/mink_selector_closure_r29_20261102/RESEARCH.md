# R29 MINK-SELECTOR-CLOSURE — degree-three OR-branch source compiler

**Research only. Restricted constructive result, NOT a completed post-quantum witness-KEM.**

Provenance: bounded offline iteration, 2026-11-02; syscoin/PVUGC PR #1, open/draft/unmerged, branch research/pq-wkem-validation-20260918; starting head 523e524f6620a2f8b13eb9b5af1d5baf3ac3302c. Read latest substantive ordinary comment 6594269907 and exact R28 blobs (research 5c5ef207e418050834ab3db6ebbc61cb3b7b3fe6; checker 791199ddff6a407d70160763090e9a032491d4f8; output 219d6c63a10154cd5cc430b0360cd861a86cc8d5). No external research. The task continues the failed R28 degree-zero hard-TRUE OR pseudowitness.

## Actual source algorithm and verified new selector theorem

Work over the square-free Boolean ring A_n=F_q[z_1,...,z_n]/(z_i²-z_i). For every ORIGINAL 3CNF clause-failure polynomial g_j, degree-D honest Build uses the matrix B_D whose columns are *all* monomial products m*g_j with degree(m)<=D. Independently sample uniform masks r per column and independent centered bounded errors e. For each precommitted native-signing-seed bit mu, publish

    C_mu = B_D*r_mu + Delta*mu*e_empty + e_mu (mod q).

The relation binds claim/UTXO, branch, anchors/window/context and native verification key. For every valid ORIGINAL witness w, its Boolean evaluation row lambda_w annihilates all B_D columns; off-chain Lift obtains lambda_w*C_mu=Delta*mu+lambda_w*e_mu. All valid ORIGINAL witnesses recover the SAME bound capability when the decoding error is below threshold, without common witness states/canonical witnesses. This is correctness, not unauthorized key-recovery resistance.

Use R28's *exact* nine-clause unsatisfiable four-variable formula F (the clause ordering is in CHECKER.js). Its previously uninstantiated low-degree integer Boolean-ideal certificate is

    1 = sum_{j=0}^{8} f_j - x_2*f_4 - x_3*f_5.                (1)

Thus the public refutation has 11 terms with multiplier degree d_F=1, valid over integers before reducing mod q; the exact coefficient identity and all 16 Boolean points have been checked locally. Define Q_4=1-x_2, Q_5=1-x_3, Q_j=1 otherwise. Degree zero did not refute F and admitted R28's fake decoder.

For every ORIGINAL F-side two-clause OR gadget, put s=1-t and x=1-l_1,y=1-l_2,z=1-l_3 with auxiliary a. Its actual 3CNF failure polynomials are g_{j,1}=s*x*(1-a), g_{j,2}=a*y*z. **Without** assuming an honest a assignment,

    s*f_j = y*z*g_{j,1} + s*x*g_{j,2}.                      (2)

Multiply by the real Q_j and sum using (1):

    s = sum_j Q_j*(y_j*z_j*g_{j,1}+s*x_j*g_{j,2}).           (3)

Every multiplier on an actual gadget failure has degree at most 3. The checker explicitly expanded (3) to a **57-term exact integer certificate** using only genuine degree-three monomial-mask columns. It works for **every** other branch G, including hard TRUE G, and inserts no manually invented s-column. Therefore s=1-t lies in im(B_3). Any fake linear functional ell annihilating B_3 satisfies ell(s)=0. R28's publicly computable no-witness dual had ell(s)=1, so it is excluded. This does **not** exclude arbitrary nonlinear/quantum key recovery or different short duals on G.

More generally, a checked degree-d_F refutation of an unsatisfiable F produces a degree-(d_F+2) selector certificate under the authentic OR gadget. Multiplication by any monomial p of degree <=h shows s*p lies in im(B_{d_F+2+h}). Thus an honest degree-D compiler closes *all* false-branch polynomial moments up to degree D-d_F-2, not just one label/occurrence. The independently executed Python checker verifies all 15 degree<=1 selector moments on the 14-variable F-gadget source at D=4.

## A genuinely instantiated certified-FALSE OR and full-public simulator

For G-side OR gadgets put selector t and auxiliary b. The actual failures are g'_{j,1}=t*x'*(1-b), g'_{j,2}=b*y'*z', with

    t*f^G_j = y'*z'*g'_{j,1} + t*x'*g'_{j,2}.              (4)

If G also has a publicly checked degree-d_G certificate 1=sum_j R_j*f^G_j, the authentic degree-D matrix with D=max(d_F,d_G)+2 contains both s and t in its image and hence e_empty=s+t in its image. The executed checker constructs **F OR a disjoint copy of F** and checks an actual **96-term integer degree-three unit certificate** for its 36 two-branch gadget clauses. This is an instantiated polynomial certificate, not a presumed SOURCE-opening oracle.

For any such publicly certified FALSE statement let B_D*alpha=e_empty be the explicit checked certificate. The honest source bit has C=B_D*r+Delta*mu*e_empty+e. Since r is independent uniform, a simulator with NO private signing seed samples r'=r+Delta*mu*alpha, and

    B_D*r+Delta*mu*e_empty+e = B_D*r'+e

as an **exact equality of full classical distributions**. The independent native verification key vk can be supplied by a QPT signature-security challenger and retained, including its correlation with unknown signing seed, because the ciphertext distribution conditional on vk is still identical. Public CK, statement, source context/UTXO/branch and auxiliary data must be reproducible without the private source mask coins; independent base capsules are coupled separately and publicly derived related capsules follow deterministically. Exact equality is preserved under arbitrary QPT coherent processing and independently supplied quantum advice. This is the restricted R20 simulator with its **actual certificate premise instantiated**, not a universal FALSE proof or a new QPT-LWE hybrid. The equality does *not* simulate target-base private opening, secret-correlated checking keys, malicious graph setup or arbitrary auxiliary data revealing the secret.

For arbitrary FALSE G without a polynomial public refutation, the simulator is unproved. For hard TRUE G, selector closure merely defeats the known F-side linear fake; an arbitrary K/native-forgery adversary need not provide ANY representation. No arbitrary hard-TRUE recovered-key/native-forgery -> actual ORIGINAL witness or independently justified QPT break reduction exists. Ordinary QPT-LWE pad indistinguishability would not establish the complete SOURCE challenge simulator; LWE remains a primary unresolved foundation.

## Executed code, parameters and scope

Published CHECKER.js is the exact independently authored/executed JavaScript checker. It ran **twice, 103 assertions per run, byte-identical OUTPUT.json** (SHA256 c0028e3901a32f6ecca0434bddd7f94f7e50c816672dec7d1f5b87d1a8adfff8). It verifies the *integer* F identity, both OR-gadget identities, FALSE OR unit certificate, and 80 distinct valid ORIGINAL witness extensions of the R28-style TRUE OR instance. An independent, longer local-only Python 3 standard-library checker ran twice with **1,125 assertions per run**, identical SHA256 output 1a27d1a39b3ec68f8076780046903ec7ae15803c38c23b4e7f10c2701d7224d1. The extended checker additionally verifies 57/96 certificate terms, 15 selector moment closures, 64 exact FALSE source-mask shifts, an actual sampled full Build and 80 different valid ORIGINAL witnesses decoding both capability bits with independent coefficient noise. Local-only material is not claimed to be a published blob.

The R28 20-variable 24-clause TRUE fixture at D=3 has 32,424 mask columns and 31,662 supported coefficient rows. Illustrative q=2^31-1 and Delta=(q-1)/2 with independent errors in {-1,0,1} give deterministic simultaneous correctness for every witness because |lambda_w*e|<=31,662 << Delta/2. At 4 bytes/field element, a 256-bit coefficient capsule alone consumes **32,421,888 bytes (~30.9 MiB)**, excluding CK/context/DA. This is not practical or a 128-bit QPT security estimate; for fixed D the algorithms are classical PPT, but higher degrees may be exponentially costly.

Full public view means ORIGINAL relation/statement, native vk, checking key, capsule, branch, context/claim/UTXO/anchors/window, auxiliary inputs and related capsules. Honest Build is classical PPT; security adversaries may be arbitrary QPT including coherent processing of the public transcript. Independently justified native QPT-EUF-CMA, where referenced, is assumed, not derived. N-of-N one-honest preauthorization and erasure, malicious/abort composition, pre-funding DA, selective openings of the target, native no-EC-key-path P2MR-like/SLH-like endpoint and BTC/SYS chain membership assumptions all remain open; nothing is deployed. Bitcoin runs no original NP/VM/verifier or BitVM trace dispute.

**Next precise missing equations:** independently instantiate classical-PPT generic-NP Setup/Open **and** a secret-free challenge simulator reproducing *all* public-source/opening correlations for EVERY adversarial FALSE ORIGINAL statement under a justified QPT assumption; then construct a QPT-valid reduction from an arbitrary unauthorized hard-TRUE final-key recovery or accepted native forgery to an actual ORIGINAL witness R(x,w)=1 OR independently justified PQ break, without requiring an internal representation. R29 does not complete either theorem. Research remains incomplete; do not disable the existing automation.
