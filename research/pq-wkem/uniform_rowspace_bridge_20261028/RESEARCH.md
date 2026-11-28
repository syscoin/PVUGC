# Uniform-rowspace SOURCE release: exact certified-false security and an unconditional rank bridge

Research record: uniform-rowspace-20261028-turn11. Offline continuation of syscoin/PVUGC PR #1, branch research/pq-wkem-validation-20260918, starting head 878978a59c8ef0c6a1acffcae8935b17d5f7f099, open/draft/unmerged. Previous exact RESEARCH.md blob be5ef84bd0033fa9a12b4ce63dda53ec05bcf90a and checker blob 5ad816c8d9a6428e9aa33aff50a2efb9d513b871 under research/pq-wkem/degree2_rank_subset_20261028/. Latest substantive ordinary comment at first read: 6469535552. No outside web/literature or full PR diff.

## Verdict

**Qualified constructive simplification, not a generic witness-KEM.** The existing classical degree-two NAND SOURCE needs no public LWE matrix or unpublished LWE secret merely to perform its source-dependent release. Sampling a uniform row mask directly removes the entire public A matrix and secret s/eta generation. For the previous EXACT certified-false subclass, native-key security follows from an exact full-public statistical coupling plus independent native QPT EUF-CMA: the prior QPT decisional-LWE term disappears. For ANY original x, including hard true, the old LWE-derived mask and new uniform mask are QPT-indistinguishable under the precise former DecLWE assumption; if n>=r+8 with uniform s, a new unconditional finite-rank theorem makes their entire joint distributions statistically close. None of this establishes arbitrary hard-true recovery -> ORIGINAL witness or independent PQ break, nor false security for all NP instances.

## Source, Build and public OFF-CHAIN Release

Given a polynomial-time ORIGINAL NAND verifier V(x,W), use the predecessor's one-hot anchored encoding z=f_x(W), m=1+2v+4G, h=1+v+G. The matrix F_x comprises global degree-two coefficients L_i(z)z_j and z_i^2-z_0z_i. Select actual linearly independent original rows (not an arbitrary basis transformation) to obtain G_x in F_q^(r x M), where r=rank(F_x), M=m(m+1)/2. For every ORIGINAL witness W accepted by V, w=phi(f_x(W)) satisfies G_x w=0, w_00=1, and has exactly B=h(h+1)/2 ones. Distinct W may have distinct w and states. The present compiler only binds a NAND verifier instance; it does NOT yet authenticate an actual BTC/SYS burn, chain, output, qualified fork, interval tags or graph permission.

Honest classical-PPT Build obtains genuine native KeyGen secret serialization K and verification key pk, with kappa-bit K, and samples independent uniform kappa-bit U,Z. It publishes actual pk, D=U XOR Z and V=K XOR U. Choose prime q, g=2B+1, radix b=floor(q/g)>=2, ell=ceil(kappa/log2(b)) rounded to exact integer capacity. Write Z in ell base-b digits a_j. For every j independently sample

    u_j <- Uniform(F_q^r),
    eps_j <- Uniform({-1,0,1}^M),
    p_j = G_x^T u_j + eps_j + g*a_j*e_00 (mod q).

Publish ORIGINAL relation/statement, G_x, all p_j, actual pk,D,V, intended verification-key identity, claim/UTXO, challenge branch, anchors/window/context, admissible auxiliaries and related capsules. Never publish u_j or eps_j. There is NO A_j, s_j, eta_j or LWE wrapper in this simpler Build. Native KeyGen and a CSPRNG are required in a real implementation; the attached checker uses a clearly marked 256-bit mock, NOT a native PQ signing implementation.

Public OFF-CHAIN Release verifies the actual ORIGINAL V(x,W)=1, locally computes w=phi(f_x(W)), and projects

    w^T p_j = g*a_j + w^T eps_j (mod q), |w^T eps_j| <= B.

All base-b codepoints, including the wraparound interval from the last codepoint to zero, are separated by at least g=2B+1. Therefore EVERY valid ORIGINAL W deterministically decodes exactly the same precommitted Z and returns the same K=D XOR V XOR Z for EVERY honestly sampled eps, even though w and individual noise projections may differ. This is not a canonical-witness or common-intermediate-state trick. The intended path then uses ordinary native signing; Bitcoin verifies no ORIGINAL NP proof, VM, SNARG, or PCP.

Previous exact q=65537 NAND examples retain: certified false r=230, M=231, h=8, B=36, g=73, radix=897, ell=27; three-witness true r=63, M=66, h=5, B=15, g=31, radix=2114, ell=24. These are algebraic resources, NOT certified 128-bit QPT parameters.

## Theorem A: exact complete-public false security, no LWE hypothesis

Fix any x whose actual public G_x admits a polynomial-time computed/verified finite-field certificate lambda satisfying G_x^T lambda=e_00. The prior impossible NAND(a,NOT a) example has such an exact certificate at the published predecessor SHA. For EVERY digit a, public G_x, and fixed error eps,

    G_x^T u + eps + g*a*e_00 = G_x^T (u+g*a*lambda) + eps.

Since u is independently UNIFORM over the full F_q^r, translation by g*a*lambda is a perfect permutation. Hence the ENTIRE vector p_j (not merely its projection or first coordinate) is independent of a_j, even conditional on real K, pk, U,Z,D,V and any permitted auxiliary source/context variables. Applying this independently to all columns and any number of unopened, independently masked capsules sharing a single K/pk gives an exact multi-capsule joint law.

For every fixed K, (U_i,Z_i) -> (D_i=U_i XOR Z_i,V_i=K XOR U_i) is bijective. After removing the digit dependence, ALL pairs (D_i,V_i) are uniform and mutually independent conditional on K and thus convey no information about K beyond the genuine pk. This remains valid for common-K related capsules only if ALL of them are certified-false or otherwise independently proven nonreleasing, none are opened, and their pad/mask coins are independently sampled. Opening a same-K sibling or including an easily opened true SOURCE sharing K trivially leaks K and is excluded. Classical adaptive openings of independent-key siblings are supported if the simulator knows their keys.

An ordinary QPT native EUF-CMA reduction given ONLY the genuine native pk can now sample uniform D_i,V_i and certified-false p_j, prepare all permitted public context and independent sibling data, and forward allowed classical native signing queries to its challenger. It never needs K, a source oracle, a submitted representation, rewinding or quantum-RO programming. If the QPT adversary outputs a fresh accepted challenge-path signature, it forges. If it returns exact native K, the reduction signs a fresh intended-path challenge to forge. Thus in this restricted certified-false game,

    Pr[unauthorized native K recovery OR fresh intended-path signature]
        <= Adv_QPT_Native_EUF-CMA.

This is EXACT simulation of the whole joint public view and classical-query interface, with arbitrary coherent QPT processing of that view. It assumes honest classical setup, nonuniform classical advice or independently preparable quantum advice not correlated with hidden setup coins, a native EUF-CMA assumption for the genuine key distribution and signing oracle model, and context/auxiliary data simulatable from public x,pk and independent sibling information. It does NOT cover secret-dependent auxiliary leakage, retained builder K, malicious setup, target-key-reusing opened capsules, coherent quantum SOURCE-opening oracles, an already-signed challenge message, nor arbitrary false x without the certificate.

## Theorem B: arbitrary-instance QPT comparison with the predecessor

For any x, true or false, the previous distribution publicly included uniform A_j in F_q^(n x r), with uniform secret s_j in F_q^n, independent eta_j <- chi^r, unpublished y_j=A_j^T s_j+eta_j, and p_j=G_x^T y_j+eps_j+g*a_j*e_00. For comparison, augment the NEW uniform-mask Build by public independent dummy A_j. Given a standard ordinary decisional-LWE challenge (A,y), the simulator knows x, G_x, genuine K/pk,U,Z,D,V and can make p=G_x^T y+eps+g*a*e_00 without the LWE challenge secret. Its full public output is EXACTLY the predecessor when y is LWE, and EXACTLY the new Build with dummy A when y is uniform. For arbitrary nonuniform QPT adversaries with admissible public auxiliary/related-capsule distributions efficiently simulatable without hidden target s_j,eta_j, a straight-line column hybrid gives

    |Pr[QPT(V_old)=1]-Pr[QPT(V_new_plus_dummy_A)=1]|
        <= ell*Adv_QPT_DecLWE(n,r,q,chi),

with ell replaced by total switched columns for multiple related capsules. Actual checking-key/XOR-share correlations, the ORIGINAL statement, and permitted independent-key adaptive classical openings are preserved. Coherent QPT postprocessing of the classical full transcript is allowed; quantum rewind, general oracle extraction and source witness disclosure are not used. The new public view omits dummy A by ordinary projection. This comparison does NOT itself imply either version is secure on hard-true inputs: both may be insecure.

**Stronger unconditional theorem for n>=r:** Conditioned on A having rank r, the linear map s -> A^T s is surjective and sends uniform s to PERFECTLY uniform y in F_q^r; independent eta does not change uniformity. Thus the entire joint law (A,p_j,pk,D,V,x,allowed aux) is identical to the dummy-A/uniform-y law conditional on full rank. For one A the rank-deficiency probability is exactly

    rho(n,r,q) = 1 - product_{i=0}^{r-1}(1-q^(i-n))
               <= (q^r-1)/(q^n*(q-1)).

For independently sampled A_j the total joint classical statistical distance is at most ell*rho, and coherent QPT postprocessing cannot increase trace distance. At q=65537, choosing n=r+8 gives ell*rho<2^-139 for BOTH previously verified instance sizes (r=230,ell=27) and (r=63,ell=24), certified by exact integer inequalities in verify.js. This does not require assuming LWE hardness. If n<r, the rank theorem does NOT apply, and the QPT-DecLWE theorem above remains conditional on the actual parameters. The predecessor's LWE wrapper was therefore statistically redundant at these explicit n>=r+8 parameters; it cannot be credited with independently establishing the missing hard-true SOURCE security.

With n=r+8, deleting public A removes (238*230*27)=1,477,980 field elements from the false instance and (71*63*24)=107,352 from the true instance. Their p widths remain 231*27=6,237 and 66*24=1,584 elements, plus G_x, pk and other context. All honest routines remain classical PPT. No 128-bit QPT attack-cost estimate follows from this dimension calculation.

## Executed checker, progress standard and exact handoff

The EXACT published standalone verify.js was locally executed twice with byte-identical JSON output, **6,445 assertions per run**: exhaustive q=7 whole-p distributions and pointwise certified-false shift couplings, q=257 two-distinct-witness 256-bit same-seed recovery, and exact big-integer full-rank failure inequalities for the predecessor's (230,27)/(63,24) resources. An independent extended local Python check.py was executed twice with identical output, **14,334 assertions per run**, additionally checking exhaustive toy finite-field matrix-rank distributions, 1,000 actual LWE challenge couplings and 30 complete 256-bit same-seed trials. Algebra and test outputs do NOT establish native SLH security, QPT computational hardness or generic-NP security; local seeded RNG and SHA256 mock are never presented as production cryptography.

**UNRESOLVED hard TRUE equation:** For arbitrary ORIGINAL (R,x) and any QPT adversary outputting the FINAL intended native signing K or fresh challenge-path signature, construct a straight-line or explicitly justified quantum-safe reduction to an actual ORIGINAL W satisfying R(x,W)=1 or to a separately independently justified PQ break, without asking the adversary to supply an internal moment vector. The uniform rowspace Build has NO such proof. For a true x the e_00 shift certificate cannot exist because valid w has <w,e_00>=1 but G_x w=0. For false x without a certificate, the full-public shift simulator is also unavailable. Exact source-dependent false-security, hard-true extraction, malicious N-of-N setup/erasure/abort, pre-funding DA, one-honest-observer enforcement under censorship, actual SYS/BTC headers/AuxPoW/tag/ancestor/window checks, Bitcoin challenge transaction graph and native no-EC-key-path SLH-like output remain unfinished. Do not disable the research automation or claim deployment.

Provenance: connected GitHub metadata/latest comments/exact predecessor files were read; no internet literature or other repo was accessed. The published checker was actually run, not merely generated. This is a new source-build and independently proved full-joint-output/cost result, but NOT the sought generic-NP witness-KEM.

