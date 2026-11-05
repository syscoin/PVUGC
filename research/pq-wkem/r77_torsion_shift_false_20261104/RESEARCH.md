# R77 — Modular torsion-shift FALSE-source simulator

**Status:** A strict, unconditional extension of R74/R75's *restricted certified-FALSE* source class, with a classically efficient source-opening algorithm and conditional complete-public-view QPT composition. **NOT** a generic PQ witness-KEM; **NO** hard-TRUE recovery-to-ORIGINAL-witness theorem.

## Exact continuity and authorization

Run R77-TORSION-SHIFT-FALSE-20261104. syscoin/PVUGC PR #1 is open/draft/unmerged on research/pq-wkem-validation-20260918, starting at 5002467698519310a90ff05a73b4158f86bbba9d; latest substantive ordinary comment 6647702420. Predecessors: R76 RESEARCH.md blob 0c109aa5ab5ba6c06d05a6d04a8a3b6c3bc3635e (all-witness annihilator), R75 RESEARCH.md blob 26c7c14932bceab441ee4751eff0cf43a0a7d2e7 (adaptive same-root false joint public view), R74 RESEARCH_AND_CHECKER.md blob 312151aa8d61d896980aa18b0952dadf917910b8 (exact rank-refutable false source). No external internet or other repository research.

R76's hard-TRUE issue is **not** repaired: an independent uniform additive LWE mask not annihilated by every valid ORIGINAL witness breaks correctness. R77 instead removes a stronger-than-needed certificate condition from the R74/R75 false-source construction, without inventing a witness-release assumption.

## Actual release algorithm and exact new certificate

Fix q=2^k, p dividing q, s=q/p, Delta=s*Lambda with 0<Delta<q, and b-bit source words. The degree-d Boolean moment compiler for the scope-bound ORIGINAL statement x outputs a public matrix A_x over Z_q and the constant monomial row e0. For **every** valid ORIGINAL witness w, its evaluation vector r_w is normalized and obeys r_w^T A_x=0, r_w^T e0=1. Distinct witnesses need not share anything else. Alongside ordinary CNF clause polynomials, the compiler may handle bounded-degree *integer polynomial equalities on Boolean evidence* by including their monomial multiples of degree at most d; this extension is necessary for the strict example below.

Honest classical Build samples a uniform precommitted root K and, for EACH word mu_j(K) and EACH related capsule, independent uniform z_j in Z_q^D and independent bounded e_j from chi_src^M. It emits C_j=Round_(q->p)(A_x z_j+e_j+Delta*mu_j(K)*e0). Honest Open on any valid ORIGINAL w calculates r_w^T C_j mod p and nearest-word decodes. With B=M(E/s+1/2), the sufficient conservative conditions Lambda>2B and p-(2^b-1)*Lambda>2B ensure every ORIGINAL witness recovers the SAME K with the stipulated bounded errors. At fixed d the source and opening are classical PPT.

**R77 certified FALSE class** F_(d,Delta) is the set of x admitting a publicly checkable modular certificate t_x such that A_x t_x=Delta*e0 (mod q). This is a polynomial-time modular linear-image decision/checking problem. Unlike R74, the new theorem does NOT require A_x t_x=e0.

For every fixed symbol mu, source error e and uniform z, the pointwise identity

    A_x z+e+Delta*mu*e0 = A_x(z+mu*t_x)+e       (mod q)

holds. Translation of independent uniform z leaves its law unchanged; any deterministic rounding preserves equality of the *entire source ciphertext distribution*, not merely one marginal. A key-blind simulator samples fresh uniform z', honest e', and emits Round_(q->p)(A_x z'+e'), without K, SourceOpen, any witness or the challenge secret. An ORIGINAL witness would imply 0=r_w^T A_x t_x=Delta (mod q), contradicting nonzero Delta. Thus the public certificate suffices for ORIGINAL-FALSE soundness. This is Delta-torsion in the module Z_q^M / im(A_x), a strict extension of the unit-image condition; it is not claimed necessary for all secure distributions.

## Strictly new certified FALSE statement, not merely renaming R74

At degree d=1, take ORIGINAL *integer polynomial equality* 4a+4b-1=0, where a,b are binary ORIGINAL evidence. Its evaluations (-1,3,3,7) are all nonzero. With rows (1,a,b), the degree-1 compiled matrix has only column A=(-1,4,4)^T: the products a*f and b*f contain an ab term of degree 2 and are excluded at this bound. For q=4096, p=256, Delta=1024, set t=3072. Then A*t=(1024,0,0)=Delta*e0 (mod 4096). However e0 is NOT in im(A), since the first row would force t=-1, making the second row -4 mod 4096. So this EXACT degree-1 arithmetic-ORIGINAL FALSE statement lies in R77's class and outside R74's degree-1 unit-certificate class. The equation 8a+8b-1=0 similarly works. This is NOT a claim that rewriting the same statement as a different CNF or raising the compiler degree would preserve strictness.

A TRUE example at the same degree 1 is ORIGINAL equality a+b+c=1: the column (-1,1,1,1)^T and three distinct valid one-hot binary witnesses yield normalized rows annihilating A, each opening precisely the same precommitted K. No canonical or shared-intermediate-state requirement.

## Joint full-public QPT simulator: actual ordinary-LWE foundation, no SourceOpen

Use the independent uniformly random A_com and explicit LWE-seed PRG H_(A_com) from R71/R75. Its independent conditional decisional-QPT-LWE experiment distinguishes (A_com,A_com*s_L+e_L mod q_L), with the EXACT specified uniform secret/bounded error distributions, from (A_com,U_(q_L)^m). R71's two straight-line hybrids yield U=H_(A_com)(K) of length L>ell from uniform ell-bit K, under advantage <=2*epsilon_LWE for arbitrary QPT distinguishers and advice independent of K/challenge coins. No 128-bit-QPT parameter strength is established.

The setup independently pre-signs the exact intended native challenge-path message before funding (conditionally assuming a native PQ signature and no-EC-keypath output). Bind relation identity, ORIGINAL claim/UTXO, branch, anchors/window, context, intended vpk/capability. Create Dsig=sigma XOR U[0:|sigma|]; then CK and Aux are domain-separated public functions of the SAME U, frozen scope, Dsig, prior source ciphertexts and permitted related capsule references in acyclic order. No raw K, Hash(K), unreleased sigma, source z/e, signer coins, or target-seed-correlated advice outside this generator is exposed. Native QPT-EUF-CMA, checking-key binding and source binding are independent assumptions.

The simulator is given ONE **real ordinary-LWE-derived PRG challenge** U*, not its seed or challenge secret. It constructs Dsig, CK, Aux, scope, related outputs and adaptive classical adversarial appendices from U*. For each adaptively requested publicly certified R77-FALSE statement x_i it constructs fresh key-blind source C'_ij=Round(A_(x_i) z'_ij+e'_ij), independently for every word and sibling. The exact modular shift proves identity of each conditional classical message law, even conditioned on U* and prior CK/Aux/source transcripts. Induction over polynomially many messages and application of the same intervening QPT quantum channels gives equality of the complete *joint adversary state* in each PRG challenge world. This includes polynomially many SAME-root certified-FALSE siblings, independently rooted/opened related TRUE capsules, and classical adaptive public outputs. QPT adversaries process the entire classical transcript coherently, but the classical Build does not offer a superposition query oracle. No quantum rewinding, SourceOpen oracle or adversary-supplied representation occurs.

When the adversary outputs K', accept root recovery only if H_(A_com)(K')=U*. In the uniform-U* world the image-counting probability is <=2^(ell-L), even computationally unbounded. Thus exact-seed recovery in the specified certified-FALSE joint-view game is bounded by 2*epsilon_LWE+2^(ell-L), plus separately charged binding/native-forgery events. A fresh native signature is separately reduced to native QPT-EUF-CMA after uniform masking; do NOT claim every accepted signature must expose a source witness. Exclusions: same-root openable TRUE sibling, source-randomness reuse, correlated target-seed advice, hidden setup bias, corrupt signer retention, graph bypass, and abort-selected *conditional* distributions. Malicious N-of-N setup/funding completeness remains unproved.

## Evidence and unproved requirements

The exact executed JavaScript checker, in checker.js, and its captured output JSON are published as separate files. It passes 8,905 assertions: q=16 exhaustive **nonzero-error** four-symbol ciphertext histograms for each of two strict FALSE statements, a negative control, 160 exact source/CK/Aux/two-capsule/adaptively-chosen-statement/related-opening/appendix couplings using a toy ordinary LWE q_L=256, n_L=3, m_L=6 challenge, and 240 successful TRUE openings from three distinct ORIGINAL witnesses. Hash and native signature data are synthetic; these toy checks do not prove QPT security. An independent LOCAL-ONLY Python 3 checker passed 6,908 assertions (available as a downloadable archive) and is not represented as the exact published JavaScript source.

**Still UNPROVED:** generic arbitrary-FALSE full-view security, generic hard-TRUE source security, arbitrary QPT final-key recovery or accepted native forgery to an ACTUAL ORIGINAL witness or independent PQ break, malicious/abort-secure N-of-N and DA composition, 128-bit parameters, and the hypothetical native PQ Bitcoin endpoint. R58 and R63/R67 attacks remain. For arbitrary QPT A on hard TRUE x, the missing equation is

    Pr[A(V_x) obtains accepted final native capability or forges accepted path]
      <= Pr[R_ORIGINAL(x, Ext^A(V_x))=1] + Adv_independent_QPT_break + negl(lambda).

Here V_x includes relation/statement, full source, CK, context, Aux and related capsules; Ext cannot demand a representation from A. This R77 false-source lemma does NOT instantiate the hard-TRUE simulator or extractor, and cannot justify stopping the research. No production changes, merge, external research or Bitcoin deployment.