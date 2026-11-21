# R54 — CK-NORMALIZED-IDEAL-CLOSURE: exact full-view postprocessing and a newly certified FALSE ORIGINAL fixture

**Status:** A restricted *constructive source/CK composition* is established: a direct, versioned release algorithm simultaneously (i) enlarges the certified-FALSE family beyond pairwise clause-failure masks in an exact 19-clause ORIGINAL 3CNF, (ii) preserves every genuine ORIGINAL witness's same precommitted capability, and (iii) admits a full-*joint*-public-view source-transform theorem with an actually secret-K_bind-dependent checking key and auxiliary records. **Not** a generic PQ witness-KEM; arbitrary hard-TRUE capability recovery to ORIGINAL-witness extraction is still entirely open. No claim that true secrecy is repaired by enlarging masks. This is one bounded OFFLINE iteration.

## Starting checkpoint and actual research scope

On 2026-11-03 (Vancouver-local run), checked actual syscoin/PVUGC PR #1 **open/draft/unmerged**, branch \`research/pq-wkem-validation-20260918\`, starting SHA \`5ed44604758d28ba882a169b001f3fa69a9beac8\`. Latest substantive top-level comment \`6622097120\` (R53). Read exact R53 note blob \`fa2d8a99c2a60dbbc0ece3a83ebf7d6b664ce0da\`, its checker blob \`1fa0edd7f4a7e82b34055e23feae916c6a2dafe6\`, R48 note blob \`d3dce77b15d70b61c1d1e1e1ee2fcbef2f8ee4d2\`, R52 note blob \`16a8b0125cc62cc17aacf5b005f6e8ff3a7d98e0\`, R46 note blob \`7413e303a4b3b0649e0e9a0ca040d5a23b8b0663\` and original fixture checker blob \`29e518613a67f0c124b40d9d8a86449713bf957c\`. No external literature, web or PR-wide diff.

## Exact source, transform, release and checking-key repair

Let \`x\` bind the actual ORIGINAL relation/verifier identity, claim/UTXO, branch, all required SYS/BTC header/AuxPoW/coinbase/ancestor-window/tag/authorization/output and context, intended fixed native verification key and challenge path, manifest and capsule version. A classical-PPT honest Build compiles the ORIGINAL verifier faithfully (off chain) to \`f_1,...,f_j\` clause-failure polynomials in the Boolean quotient ring \`A=F_q[z_1,...,z_n]/(z_i^2-z_i)\`. Take the explicitly supported bounded-degree monomial coefficient space \`F_q^M\` (the finite six-variable complete toy uses \`M=64\`, \`q=65537\`). All arithmetic is in the stated public monomial ordering; do not presume a polynomial-size explicit \`M=2^n\` for general NP.

Define
\`\`\`
W0 = span{ f_i*f_j : i <= j };
W+ = W0 + span{ z_S*f_i : |S| <= 2 } .
\`\`\`
All products are reduced by the Boolean identities, and each generator vanishes on EVERY valid ORIGINAL assignment. Let \`P0,P+\` be the public canonical RREF quotient projections with kernels \`W0,W+\` and \`S0,S+\` their zero-pivot public sections. Define the **public deterministic capsule normalizer**
\`\`\`
T_x = P+ o S0.
Z0(mu,eta) = P0(Delta*mu*1 + eta).
Z+(mu,eta) = P+(Delta*mu*1 + eta) = T_x(Z0(mu,eta)).
\`\`\`
The last equality holds for **every** \`mu,eta\`, because \`v-S0(P0(v)) in W0 subset W+\`. It needs neither a witness nor any unknown secret, and holds simultaneously for arbitrary correlated bitstrings and individually independently sampled capsule noises.

The NEW versioned algorithm \`Build+\` samples honest native signing keys and a fixed-path pre-signature \`sigma*=Sign(sk_N,m*(x,vk))\` BEFORE irreversible funding under the **separate conditional R45 N-of-N preauthorization, DA and graph assumptions**. Its independent hidden seeds \`r0,s1,e1,K_bind\` and exact public LWE base \`A0\`, expansion/matrix commitment \`alpha\`, and signature mask \`D = Encode(sigma*) XOR Encode(A(r0)*s1+e1)\` follow R52's explicitly QPT-DLWE-conditional tree construction. The new source encrypts every bit of \`r0 || Encode(s1,e1) || K_bind\` by fresh independent \`Z+_mu=P+(Delta*mu*1+eta_mu)\` with centered coefficient errors in \`[-B,B]\`.

**Crucial R53 full-CK repair:** Publish a VERSIONED checking key
\`\`\`
CK+ = F( domain_+, K_bind, x, vk_N, m*, A0, alpha, D, canonical(Z+_all),
         canonical(related Z+_public), ctx )
Aux+ = AuxAlg(K_bind, CK+, x, vk_N, A0, alpha, D, Z+_all,
              related Z+_public, ctx; independent_aux_coins).
\`\`\`
\`F\` is an explicitly selected deterministic PPT function with canonical length-prefixed encodings (e.g. a separately QPT-collision-resistant hash if adversarial CK-binding authenticity is needed). **It is genuinely K_bind-secret-dependent and is NOT assumed publicly reproducible.** The permitted AuxAlg may reveal K_bind but must not leak \`r0,s1,e1,eta\`, the target signature or native sk beyond the displayed allowed public fields. It cannot depend on old discarded \`Z0\`, deleted raw mask coins, or hidden noise. Every related capsule that appears in CK/Aux must also be normalized *before* CK is computed. A different old literal R52 CK that hashes raw Z0 is NOT transferable by this argument; this is an intentional new version, not an unnoticed raw-byte change.

\`Open+(x,w)\` OFF CHAIN verifies actual \`R_ORIGINAL(x,w)=1\`, evaluates \`Ev_w(S+(Z+_mu))\` for every bit, nearest-centre decodes all hidden seeds, regenerates \`A(r0)\` and checks \`alpha, CK+, Aux+\`, unmasks the exact precommitted signature from D, verifies \`Verify(vk_N,m*,sigma*)=1\`, and returns **only the ordinary native fixed-path signature**. Bitcoin does not run NP, SHA traces, PCP/Kilian, VM, BitVM disputes or LWE verification. BitVM remains covenant plumbing only; SLH-like native PQ signatures and a no-EC-key-path P2MR-like output remain CONDITIONAL, not deployed.

## Proved same-capability correctness for all genuine ORIGINAL witnesses

For any genuine ORIGINAL witness \`w\`, \`Ev_w(W+)=0\`. Thus for every bit and any \`eta\`:
\`\`\`
Ev_w(S+(Z+_mu)) = Delta*mu + Ev_w(eta) mod q.
|Ev_w(eta)| <= M*B .
\`\`\`
With \`M*B<Delta/2\`, nearest-centre decoding recovers \`mu\` for **every** valid ORIGINAL witness, including witnesses with distinct states, without a canonical witness, shared short preimage or common intermediate state. Therefore all valid witnesses obtain the exact same Build-chosen matrix seed, LWE pad and K_bind, then the identical precommitted native signing capability. This is correctness, not secrecy or soundness under a malicious Build.

## Exact full-JOINT-view nonworsening lemma, including secret-dependent CK

Define an *augmented comparator* \`Build0+\` (not the literal R52 protocol): construct R52-style Z0 but compute CK and Aux using only the **public invariant** \`T_x(Z0)=Z+\`, rather than raw Z0. Its public transcript is \`(x, Z0, D, A0,alpha,vk,CK+,Aux+,related Z0,ctx)\` with relevant normalizers defined at each related statement. \`Build+\` is the deterministic public map \`H\` of this FULL comparator transcript: replace every Z0 by its own T_x(Z0), retain the SAME already-generated CK+, Aux+, context, D, vk, A0, alpha and independently scoped opening outputs. NO recomputation of CK or knowledge of K_bind is needed by H.

For any arbitrary classical joint randomness, shared capability bits, separate/no shared capsule seeds as specified, and any QPT adversary A given the NEW transcript, define B on the augmented comparator transcript by \`B(V0)=A(H(V0))\`. B is straight-line QPT and has EXACTLY the same output law and win probability; this transfers **any** stated full-view security bound from the explicitly defined augmented comparator to the new one by data processing. Allowed external classical auxiliary is generated as above; coherent QPT processing and efficiently simulatable independent quantum advice do not change equality. Publicly reproducible/non-target coherent opening tables can be passed along when the simulator already knows their contents. This lemma does NOT assume such a bound has been proved for arbitrary TRUE, and says nothing about secret-dependent auxiliary correlated with the deleted Z0, unrestricted target opening, malicious setup or target-correlated quantum advice. In particular the R53 ghost dual is eliminated from the named toy subspace but not a generic TRUE security theorem.

## Strictly enlarged certified-FALSE full-public-output simulation

Whenever a PUBLIC certificate shows \`1 in W+\`, \`P+(1)=0\`. Then for every TARGET seed bit, \`Z+_mu = P+(eta_mu)\`, exactly independent of the encrypted seed even conditional on the native vk, K_bind and allowed public data. For arbitrary independently noised same-pad target capsules and independent related non-target claims, a simulator can sample target Z+ using only eta, choose K_bind itself, compute the exact secret-K_bind-dependent CK+ and Aux+, and embed the actual independently justified ordinary QPT-DLWE tree and final-pad challenge **without** knowledge of challenge r0,s1,e1 and without a SourceOpen oracle. With the same R52 conditions (honestly uniform A0, legitimate LWE seed/error distributions, predesignated unopened certified-FALSE target, truth/certificate invariant under hybrid matrix/alpha changes, genuinely independent non-target openings, fresh bound native message, excluded secret-dependent quantum advice), the **same straight-line QPT bound** applies:
\`\`\`
Pr[accepted target native signature]
 <= (2^d-1)*Adv_QPT-DLWE_base
    + Adv_QPT-DLWE_pad + Adv_QPT-EUF-CMA_native.
\`\`\`
QPT collision resistance for adversarial context/commitment re-binding remains separate. This is a certified-FALSE **capability-to-native-forgery** composition, not arbitrary-FALSE IND secrecy, arbitrary true witness extraction, or an independently demonstrated 128-bit parameter setting. The statement is not circular WE/iO/WPRF hardness: these restricted hybrids invoke precisely the independent LWE/native assumptions already identified in R52.

**New concrete coverage:** On R36's ACTUAL 19-clause unsatisfiable six-variable ORIGINAL 3CNF, WITHOUT R36's ad hoc additional \`z_1*f_8*f_14\` lift, pair-only \`W0\` has rank 50 and \`P0(1) != 0\` (so R52's certified-FALSE source theorem **does not apply** to this pair-only instance). The bounded module \`W+\` defined ABOVE has rank **64**, so \`P+(1)=0\` and every encrypted seed capsule is empty. This EXACTLY gains certified-FALSE full-public-output security coverage for a previously excluded actual fixture using a fixed transparent generator rule, while retaining the new secret-correlated CK and allowed Aux. The original R36 lift is not being silently assumed.

On its genuine TRUE 18-clause variant (delete exactly clause index 10), valid ORIGINAL satisfying assignments are \`10,11,43\`; ranks are \`49 -> 61\`, quotient dimensions \`15 -> 3\`. This improves SOURCE coordinate count **only in this small toy** and retains all-witness correctness. Full ideal saturation here, sparse dual/witness-span recovery in easy instances, affine closure and source-hardness failure remain live tests; there is NO claim the enlarged space makes the true source secure. For generic NP, explicit full Boolean dimension \`2^n\` is not polynomial and many FALSE cases may lack a degree-two certificate. No practical arbitrary-NP cost/security theorem follows.

## Executed finite checker, provenance and failures

The exact \`CHECKER.js\` file (Git blob SHA \`d73a52156b81e8e066fcfab0953c177c481b723f\`) was executed using the connected V8 runtime with an injected console. \`OUTPUT.json\` (blob SHA \`4b5b22ed8bd6e610ed4be2255379b2a4c31972de\`) records **773 successful assertions**: actual 19-clause R36 and 18-clause R46 ranks/truth, old/new cert status, 128 coordinate transforms on standard basis, 192 genuine-witness bit openings for two bit values across all three genuine TRUE ORIGINAL witnesses, and 128 finite exact FALSE target-pad couplings including K_bind-dependent CK, Aux, public related TRUE-but-independent capsule and canonical challenge context. Toy CK is JSON serialization, NOT a collision-resistant hash or native PQ signature. Matrix/quantum hardness is not tested. A previous LOCAL checker transcription erroneously replaced the genuine eleventh clause, causing an expected rank-assertion failure *before publication*; the corrected checker executed with 773 passes and was published. Container/Python returned \`redis.exceptions.ResponseError\`; no independent local checker or downloadable archive is claimed.

## Exact unfinished reduction and handoff

The R53 ghost's removal and full-view normalization are NOT a repair of R35/R46 short pseudoevaluations in general. Nothing proves \`W+\` source secrecy for TRUE hard NP, nor prevents arbitrary QPT recovery of r0,s1,e1/CK/native signature by another public functional or cross-capsule quantum attack. A missing **independently instantiated and proved** source and reduction must establish for hard-TRUE genuine ORIGINAL x, full joint \`V=(R,x,Z+,A0,alpha,D,CK+,vk,ctx,Aux+,related/openings)\`:
\`\`\`
Pr[A_QPT(V) recovers capability or supplies accepted native signature]
  <= Pr[Ext^A outputs ACTUAL ORIGINAL w, R_ORIGINAL(x,w)=1]
     + Adv_QPT(independently justified explicit primitive break) + negligible.
\`\`\`
No extractor may require A to disclose an internal supplied representation. Also unresolved: arbitrary-FALSE security, fully malicious N-of-N ceremony/collateral erasure/abort, useful liveness and pre-funding DA under censorship, 128-bit QPT hardness/concrete resources, keyless Build, and undeployed conditional Bitcoin-native PQ signature endpoint. Keep the existing hourly research automation ENABLED; do not claim completion.
