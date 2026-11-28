# R36 — Sparse One-Lift Repair of R35 (2026-11-03)

## Constructive result and exact provenance

Offline continuation of R35 uniform-product-span and R33 branchwise OR. Beginning syscoin/PVUGC PR #1: open, draft, unmerged; branch research/pq-wkem-validation-20260918; SHA cd91577b5f7eae52ec4f9d8449b0b4efbe61a640; latest ordinary substantive comment 6600380809. Read R35 RESEARCH.md at exact blob 986ff360ea2853308127ace2b99a5476e4645a92. No external research or PR-wide diff. This is NOT a generic or proven QPT-secure WKEM.

**New repair:** One explicit FALSE 3CNF branch F breaks the R35 mask span W2 and consequently R33 BRANCHWISE-OR(F,G), leaking its shared K without any ORIGINAL G witness. Adding ONLY the public polynomial u=z_1*f_8*f_14 to W2 produces W+=W2+span{u}, satisfying an exact 24-term integer unit certificate. This gives a concrete classical release with an exact full-permitted-public-output FALSE-branch simulator and restores R33's reduction to the still-hard single TRUE G challenge. It expands a genuinely instantiated, previously leaking FALSE class, not merely a rank observation.

## Actual ORIGINAL 3CNF and attack on old source

Variables z0..z5; each triple (positions):(failure bits) specifies a genuine 3CNF clause violated exactly when the three indexed variables equal the listed bits. Its clause-failure polynomial f_j is the product of corresponding literal-violation indicators. The 19 clauses, indexed from zero:

0 (1,3,4):(0,0,0); 1 (0,1,4):(0,0,0); 2 (0,1,4):(1,0,1);
3 (1,3,5):(1,0,1); 4 (1,3,4):(1,0,0); 5 (0,1,2):(0,0,0);
6 (0,3,4):(0,1,1); 7 (2,3,5):(1,0,0); 8 (0,4,5):(1,1,0);
9 (1,2,5):(1,1,1); 10 (1,2,4):(1,0,0); 11 (0,3,4):(1,0,0);
12 (0,4,5):(0,0,1); 13 (2,4,5):(1,0,0); 14 (2,3,4):(0,1,1);
15 (0,3,5):(0,0,1); 16 (0,4,5):(0,1,0); 17 (1,3,4):(0,1,0);
18 (1,2,4):(1,1,0).

Every one of the 64 Boolean assignments violates some clause; thus this is a FALSE ORIGINAL 3CNF. Let A=F_q[z0,...,z5]/(z_i²-z_i), q=65537, Delta=32768. R35's old W2=span{f_j*f_k:0<=j<=k<19}, with 190 generators, has rank 50; adding the constant 1 raises rank to 51.

The publicly computable signed linear functional on evaluation vectors

h(P)=-P(17)+P(19)+P(25)-P(27)+P(49)-P(57)+P(59)

has h(1)=1 but annihilates EVERY generator of W2. Its coefficient functional on squarefree monomial noise has L1 norm exactly 20. Under R34's centered independent coefficient noise e_T∈{-1,+1}, |h(e)|<=20 deterministically. Therefore the OLD capsule C_mu=U(W2)+Delta*mu+e has h(C_mu)=Delta*mu+h(e), and nearest-decoding always exposes the capability bit, with no witness. This also defeats OR(F,G) with a QPT-hard true G when branch capsules share K. The result corrects any unsupported generic-security reading of R35; R35 itself limited its claim to product-span-certified FALSE instances.

## Exact one-generator release repair

Define u=z1*f8*f14, W+=W2+span{u}. The rank is 51 and 1 is in W+. An exact identity in the INTEGER Boolean squarefree quotient is:

1 =
 f0*f0 - f0*f7 - f0*f12
 + f2*f2 - f2*f8 - f2*f14
 + f3*f3 - f3*f9 - f3*f10 - f3*f15
 + f6*f6 - f6*f9 - f6*f14 - f6*f16
 + f8*f8 + f9*f9 + f10*f10
 + f13*f13 - f13*f17
 + f14*f14 + f15*f15 + f16*f16 + f17*f17
 - z1*f8*f14.

The identity has 24 terms, all ±1. The published checker verifies it on all 64 Boolean assignments using exact integer arithmetic. The evaluation map Z[z]/(z_i²-z_i)→Z^(2^6) is an isomorphism by integer Möbius inversion, so this check establishes the universal integer quotient identity, and hence a certificate alpha with L(alpha)=1 in any finite field. The old functional satisfies h(u)=-1: it no longer annihilates W+.

Honest classical Build, for EACH bit mu of the SAME precommitted native signing capability K and each independent branch/scope, samples 190 coefficients a_jk plus one coefficient a_u uniformly and independently in F_q; independently samples all 64 coefficient noise signs e_T; publishes

 C_mu = L(a)+Delta*mu*1+e,  L(a)=SUM_{j<=k}a_jk*f_j*f_k+a_u*u.

This adds only one field draw (190→191, +0.526%) per bit. A public rank-guided compiler can test whether 1∈W2, and if not test candidates z_i*f_j*f_k and adopt any independently verified one-generator unit-span repair. This procedure is classical PPT for fixed polynomial degree with explicit coefficients, but computationally very large for generic NP and not assured to find a repair for every FALSE x.

For any genuine ORIGINAL witness w of the compiled relation, all f_j(z_w)=0, so all g_jk and u vanish, and C_mu(z_w)=Delta*mu+e(z_w). In this finite n=6 fixture |e(z)|<=64 < Delta/2, hence ALL distinct genuine witnesses deterministically recover the SAME K, including adaptive witness selection. Original x must faithfully bind the actual ORIGINAL verifier/relation, claim/UTXO, branch, authentic SYS/BTC anchors and window/context, and intended native verification key/path. The standalone checker uses an illustrative easy TRUE G solely to test noncanonical witness correctness; it does not prove QPT hardness. Build may know K; optional keyless Build and malicious-ceremony protections remain unimplemented.

## Full permitted public-view simulator and reduction

L:F_q^191→W+ is public and surjective, and the explicit alpha satisfies L(alpha)=1. Therefore for uniform a, each real capsule

 C_mu=L(a)+Delta*mu+e = L(a+Delta*mu*alpha)+e

has EXACTLY the same entire public coefficient-vector distribution as the independent zero-bit capsule L(a')+e with uniform a'. The simulator samples a',e and needs neither K nor SourceOpen nor an adversary-supplied certificate. The proof works for any number of independently randomized F branch capsules, given the real native vk and any externally supplied side data independent of fresh source coins conditional on K; publicly reproducible CK transformations and derived related capsules are preserved. This is equality of complete classical transcript distributions, not a conjectural computational hybrid, so arbitrary coherent QPT postprocessing with conditional independent quantum auxiliary advice also preserves equality. It does NOT simulate target secret mask/noise openings, unreproducible K-dependent CK generators, malicious setup or adversarially correlated fresh coins.

In R33 BRANCHWISE-OR(F,G) where F is this specific FALSE branch and G is any single hard TRUE ORIGINAL relation, independently encrypt SAME K in F and G capsules. A reduction receiving the genuine single-G challenge with native vk/context but not K samples repaired F zero-bit capsules and presents the combined full permitted public view. Its distribution is IDENTICAL to the true joint OR view, so any arbitrary QPT recovered-K or fresh accepted-native-forgery success transfers to a single-G adversary with zero statistical loss. This requires no internal representation from A. It proves only the *F-branch simulation-to-G interface*, not recovery of any ORIGINAL G witness.

## Exact executed code/results and full limitations

The accompanying CHECKER.js was executed offline in V8 TWICE with byte-identical output; 10,830 assertions each: 64 F-unsatisfiability and exact integer certificate assignments, rank50→51, original public fake functional with coefficient L1=20 and lift moment -1, 128 deterministic unauthorized old-F bit recoveries, 8192 exact whole-capsule shift-coupling checks, and 2160 same-capability recoveries over 45 distinct genuine assignments to an independent illustrative G fixture (16 bits ×3 scopes). The toy PRNG is deterministic noncryptographic xorshift; randomness tests are not cryptographic security evidence. Proven statements follow algebra and sampling distributions, not toy runs.

No independently justified QPT assumption closes hard TRUE security. The remaining missing inequality for arbitrary QPT A from FULL joint relation/statement/capsules/CK/native vk/context/auxiliary/related-capsule view is

 Pr[A recovers K OR forges native intended signature]
 <= Pr[Ext^A outputs ACTUAL ORIGINAL w with R_G(x,w)=1]
  + Adv_QPT(independent break) + negligible.

Ext may not require an adversary-supplied representation, a canonical common witness, an oracle for SourceOpen, classical rewinding applied to QPT, or a renamed WE/iO/WPRF assumption. Generic arbitrary FALSE full-public simulation, multiple hard TRUE branches/selective openings, secret-correlated CK, malicious one-honest N-of-N graph/ceremony/abort and pre-funding data availability, concrete practical resource security, and an actual native Bitcoin PQ signature/output are still open. Native SLH-like signature and no-EC-key-path P2MR-like support remain conditional. ORIGINAL SYS/BTC headers/AuxPoW/coinbase tag/ancestor/window verification remains OFF CHAIN; Bitcoin never executes NP verification, a VM, PCP/Kilian, or BitVM trace disputes.
