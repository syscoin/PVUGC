# R87 — Ternary-randomness packed Regev source over an odd modulus

**Run:** R87-TERNARY-ODD-MODULUS-PACKING-20261105  
**Scope:** \`syscoin/PVUGC\` PR #1, \`research/pq-wkem-validation-20260918\`. Verified starting PR head \`02453fd25a5a373876bbf9f54d5046670c040605\`, open, draft, unmerged. Exact predecessor R86 \`RESEARCH.md\` Git blob \`f35fa9cd68c0b5ef150e09cdc8f9326566d0f559\`. Latest substantive ordinary PR comment at opening: \`6657384151\`. Authorized connected GitHub read only for project continuity; no internet literature search.

## Actual construction advance

R86's packed vector-Regev source uses a binary coefficient vector \`r_g <- {0,1}^m\`. Its proof needs \`m >= (n+ell) log_2(q)+2lambda+2\` rows for the leftover-hash loss. **For any odd modulus q (including odd composite q)** replace this by a *uniform ternary* coefficient vector \`r_g <- {-1,0,1}^m\`, with independent fresh vectors for each packed block. All other pieces of R86/R85 remain unchanged. This saves roughly **36.9% of the public source-key matrix rows and associated key-generation work** for the same odd q,n,ell,lambda and the same conservative leftover-hash error, without strengthening the ordinary QPT-LWE assumption. It does not reduce the ciphertext's number of q-symbols, native signature size or random-bit entropy consumption.

For the **illustrative and not QPT-security-calibrated** odd 16-bit modulus \`q=65521\`, \`n=256\`, \`ell=16\`, \`lambda=128\`, the binary proof needs \`m=4610\` rows and the ternary proof needs \`m=2909\`. The complete public source key \`(A,B)\` shrinks from \`4610*(256+16)=1,253,920\` to \`2909*(256+16)=791,248\` Z_q elements, or **2,507,840 -> 1,582,496 bytes** with canonical two-byte residue encoding (925,344 bytes saved). The packing ciphertext remains \`ceil(11008/16)*256+11008=187136\` Z_q elements. The worst-case exact all-witness decoding condition at those dimensions permits \`beta<=3\` for the binary example and \`beta<=5\` for ternary; choose the SAME original error law \`chi\` supported in \`[-3,3]\` to compare without changing hardness assumptions. Total PRG seed generation and native signature length are unchanged. Ternary sampling must be unbiased, e.g., independent rejection sampling.

## Full classical PPT distribution and original release

Fix arbitrary positive n,m,ell, security parameter lambda, odd q>=3, independent bounded error law chi on integers \`[-beta,beta]\`, \`Delta=floor(q/2)\`, and \`m beta < q/4-1\`. Independently, exactly as in R85, choose the *distinct* public PRG matrix A_G with R85's separate even-modulus ordinary-LWE distribution; this PRG does not change in R87.

Honest source-key generation samples \`A <- U(Z_q^{m x n})\`, independent columns \`S_j <- U(Z_q^n)\`, \`E_j <- chi^m\` and publishes ORIGINAL restricted statement \`x=(A,B=A S+E)\` plus the frozen claim/UTXO, original relation identity, branch, anchors/window/context, N-of-N authorization graph and native verification key. The ORIGINAL relation is *only* the honestly generated LWE-short-error vector relation \`R_vec(x,(S',E'))=[B=A S'+E' mod q AND |E'_{ij}|<=beta AND exact bound statement fields]\`; it is NOT an arbitrary generic NP relation. Build requires no source witness but uses the ordinary native pre-signature held under the separate honest-erasure baseline. Arbitrary corrupt setup, retained source secret, and arbitrary quantum advice correlated with that secret are excluded.

Let the R85 independently justified LWE PRG expand a *uniform precommitted seed* \`T in {0,1}^k\` to the disjoint native-signature pad \`P\` and checking-key seed \`B_check\`. Split \`T\` into \`h=ceil(k/ell)\` groups. For each g independently sample \`r_g <- U({-1,0,1}^m)\` and publish:

\`\`\`text
u_g    = A^T r_g mod q
v_g,j  = B_j^T r_g + Delta*T[g*ell+j] mod q
C      = {(u_g,v_g)}_g
Dsig   = sigma XOR P                     sigma = Sign(sk_native, frozen M)
CK     = F(B_check,Dsig,C,x,A_G,context,prevCK)
Aux    = H(B_check,Dsig,CK,C,x,A_G,context,prevCK)
View   = (original statement, C, Dsig, native vk, CK, Aux,
          frozen scope, signed independent preflight attestation,
          permitted other capsules and public A_G)
\`\`\`

\`F,H\` are acyclic public deterministic classical PPT; no output is permitted to reveal the seed, pad, native signature, secret-dependent fingerprint, decryption key, or another target-secret correlated leakage, except the displayed dependencies. Native signatures and independent preflight attestations are not instantiated as Bitcoin deployed capabilities. The proving interface must NOT require unknown source coins or a SourceOpen oracle; public proofs whose simulator needs them remain outside this restricted result.

For **every valid ORIGINAL witness** \`w=(S',E')\`, compute

\`\`\`text
v_g,j - (S'_j)^T u_g = (E'_j)^T r_g + Delta*T[g*ell+j]  (mod q).
\`\`\`

Since every coefficient of r has absolute value at most 1, \`|(E'_j)^T r_g|<=m beta\` exactly as in binary R86. The cyclic centers 0 and Delta are separated by Delta approximately q/2; \`m beta<q/4-1\` ensures deterministic nearest-center recovery of each and every bit for every valid witness, including witnesses with distinct S' and E'. Reconstruct the same \`T\`, \`P\`, \`B_check\`, checking-key/aux DAG and the same *precommitted native signature*. Reject if the frozen context, CK/Aux or ordinary native verification fails. Only off-chain capability release is contemplated; Bitcoin does not evaluate the NP relation.

## Exact two-universal proof and QPT reduction

Let \`d=n+ell\`, \`D=[A|B]\`, and consider \`h_D(r)=D^T r\` with independent uniform \`D <- U(Z_q^{m x d})\`, \`r <- U({-1,0,1}^m)\`. For any **distinct** r,r', some nonzero coefficient of r-r' belongs to \`{+/-1,+/-2}\`. Because q is odd, **both 1 and 2 are units mod q**, even when q is composite. Conditioning on other rows of D, the corresponding uniform row multiplied by that unit makes \`D^T(r-r')\` uniform over \`Z_q^d\`. Hence

\`\`\`text
Pr_D[h_D(r)=h_D(r')] = 1/q^d,    for each r != r'.
\`\`\`

The family is exactly two-universal. Its input has min-entropy \`m log_2 3\`. The standard statistical collision/leftover bound (or direct Cauchy-Schwarz) gives

\`\`\`text
TV((D,D^T r),(D,U(Z_q^d)))
    <= epsilon_LHL3 := 0.5 * sqrt(q^d / 3^m).
\`\`\`

For the same q and d, binary R86 has \`epsilon_LHL2 = 0.5*sqrt(q^d/2^m)\`; choosing \`m_3=ceil((d log_2 q + 2lambda+2)/log_2 3)\` instead of \`m_2=ceil(d log_2 q +2lambda+2)\` achieves \`epsilon <=2^{-lambda-2}\` in both cases. This loss is **statistical** and remains valid under arbitrary coherent quantum postprocessing of this complete classical source, not because of a classical-to-quantum extractor lift. For an EVEN q the proof fails: the difference 2 is not invertible. The executed checker verifies a concrete mod-4 failure; do not apply the ternary theorem to R85's separate even-modulus PRG matrix.

To move from genuinely sampled LWE \`B=A S+E\` to uniform B, replace each of ell independent columns sequentially using one genuine \`(A,As+e)\` versus \`(A,U)\` decisional-QPT-LWE challenge. A reduction samples all other columns on the same A and recomputes the complete source and all checking-key/auxiliary fields deterministically. Cost <=ell*epsilon_LWE for each direction with **exactly the source q,n,m,chi**. In the all-uniform-B world, use the two-universal bound above once per independent ciphertext block, preserving the same public D, to obtain <=h*epsilon_LHL3 joint error even for adaptively coherent QPT postprocessing. Thus for two chosen messages the entire packed PKE ciphertext QPT INDCPA advantage is bounded by

\`\`\`text
2*ell*epsilon_LWE(n,m,q,chi) + 2*h*epsilon_LHL3.
\`\`\`

For odd q fixed, R87's \`m_3<m_2\` does not demand a *stronger* decisional-LWE assumption: an adversary on the smaller m_3 samples can be used unchanged against an m_2-sample challenge by discarding extra rows. This observation does NOT calibrate either LWE law or prove practical 128-bit security.

In the full-public hybrid, a genuine packed-PKE INDCPA challenger encrypts the actual T versus an independent known T' with unknown randomness and secret source key; the simulator independently constructs all other fields from its known T, the challenge C, and the frozen context. The target/same-key source witness or seed is **never** opened in this wrong-seed hybrid. Then R85's independently instantiated uniform-seed ordinary-QPT-LWE PRG hybrid randomizes \`P||B_check\`, while constructing the public CK/Aux jointly. Finally uniform P masks the unknown already-presigned target sigma and an **independent QPT-EUF-CMA native signature** challenger receives any accepted target signature as a forgery. Under R85/R86's restricted honest setup, nonleaking auxiliary data, non-target selective-opening restrictions and fixed target, the bound remains

\`\`\`text
Pr[unauthorized accepted target preauthorized native signature]
 <= 2ell eps_LWE_source + 2h eps_LHL3
    + r_G eps_LWE_PRG + Adv_QPT_EUF_native + eps_independent_preflight.
\`\`\`

For polynomial related capsules add their actual block count and hybrid/target-selection loss. Public CK, source C, native vk, scope, context, auxiliary fields and permitted siblings MUST be generated jointly; no marginal pad argument suffices. QPT adversaries may process this public classical transcript coherently, with quantum auxiliary advice independent of challenge/retained source secrets. Rewinding and supplied-representation extraction are absent. Releasing any same-x secret decryption witness breaks target confidentiality and remains excluded. The restricted proof does NOT establish arbitrary FALSE security, malicious N-of-N ceremony/abort or an extractor for generic hard-TRUE statements.

## Checker and complete reproducible interpretation

\`checker.js\` executes without network access on Node.js and was also actually executed under a connected V8 context; \`captured-output.json\` records its exact returned data. It passed **6,475 explicit assertions**, including exhaustive q=5,d=2,m=2 collision counts for all 36 pairs of distinct ternary inputs and 625 hash matrices; full mean-TV censuses over all 625 q=5,m=4,d=1 hash matrices for both ternary and binary input distributions (ternary 0.06461629629629663 vs bound 0.12422599874998831; binary 0.18687999999999957 vs bound 0.2795084971874737); mod-4 negative collision probability 1/2 instead of the required 1/4; 192 same-capability releases and 4,608 seed-bit decodes across **three different valid witnesses** per deliberately structured *insecure* toy x; and 192 toy public checking-key/auxiliary consistency checks. The toy native capability is just random bytes with a weak toy pad/checksum, not a true signed transaction or cryptographic security claim. The fixture's A has a zero column to manufacture distinct valid witnesses; this is NOT a secure honest LWE-key distribution. No checker empirically verifies ordinary-QPT-LWE, real INDCPA, EUF, malicious setup, a full ORIGINAL verifier, or deployed Bitcoin PQ paths.

## Unresolved exact handoff

The previous R86 restricted witness-KEM survives with a smaller *odd-q public source key*, but this iteration did **not** solve or assume away the main obligation:

\`\`\`text
For arbitrary hard-TRUE x, provide a classical-PPT generic ORIGINAL
compiler plus genuine LWE joint source/challenge simulator such that

Pr[A obtains the already preauthorized native capability from V_x]
 <= Pr[R_original(x,Ext^A(V_x))=1]
    + Adv_independently_justified_QPT_break + negl(lambda),

with Ext not requiring an internal representation volunteered by A,
and with SAME precommitted capability for all valid ORIGINAL witnesses.
\`\`\`

Generic FALSE full-public-output security, false-to-true source-binding, malicious N-of-N setup/abort/useful completeness/pre-funding DA, optional fully keyless Build, calibrated QPT parameter sets and a **conditional** no-EC-key-path native Bitcoin PQ endpoint remain open. Repeated source-key/public basis tricks cannot replace this missing generic compiler/extraction step. R87 is NOT a completed WKEM. Research-only publication does not meet the stopping criteria; do not disable the existing automation.
