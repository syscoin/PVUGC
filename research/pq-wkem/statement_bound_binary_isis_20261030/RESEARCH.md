# Statement-bound binary-ISIS dual-LWE reconciliation — restricted planted-source theorem

2026-10-30. **NOT a generic PQ WE/WKEM and NOT secure for arbitrary FALSE instances.** This is a constructive, fully instantiated release/checking-key and QPT challenge-simulation *component* for the special binary-ISIS NP relation, with a proved fatal FALSE-input limitation. No new independent WE/iO/WPRF assumption or SourceOpen oracle is introduced. The exact checker is appended separately.

## Continuity and component boundary

Repository syscoin/PVUGC, open/draft/unmerged PR #1, branch research/pq-wkem-validation-20260918, read starting SHA 8c7147522799d2fa7c12e599aff17b914f9fe43e. Latest ordinary substantive comment 6539751921. Exact predecessor research/pq-wkem/source_seed_wrap_prg_20261030/RESEARCH_AND_CHECKER.md blob 3bf7a5858c0cb7c3d2b71f72f6b9046fc1b2aedd. The predecessor plants SOURCE targets independently of an ORIGINAL statement and cannot make an arbitrary ORIGINAL witness open them. Here the ORIGINAL relation *is itself* the SOURCE relation, and the public statement is cryptographically bound to the release matrix. This does NOT compile arbitrary ORIGINAL NP.

Define
\[
R_{\rm binISIS}((A,u,w),z)=1\quad\Longleftrightarrow\quad
z\in\{0,1\}^m,\ \|z\|_0=w,\ Az=u\pmod q,\qquad q=2^k.
\]
Every valid ORIGINAL witness, not a canonical witness or hidden SourceOpen oracle, is a public off-chain release input. The full source x plus claim/UTXO, branch, anchors/window, intended native pk and challenge-path identity must be authenticated in the manifest.

## Explicit honest classical-PPT Comp and off-chain Lift

Choose q=2^k, M=2^s dividing q with s<k, A in Z_q^(n×m), and errors chi supported on [-B,B]. Require B(w+1)<M/2. Let d=ceil(512/(k-s)). Given only (A,u,w), claim/path/context (NO witness), sample for every j in 1..d independently:
\[
s_j\leftarrow U(\mathbb Z_q^n),\ e_j\leftarrow\chi^m,\
e_{*,j}\leftarrow\chi,\quad
\beta_j=A^\top s_j+e_j,\quad
t_j=u^\top s_j+e_{*,j},\quad h_j=t_j\bmod M.
\]
All equalities above are mod q except the low-M residue. The first 512 high bits of t_1,...,t_d, where each high part is floor(t_j/M), form the **precommitted master K**. Split K into 32-byte SK.seed and 32-byte SK.prf. Sample a fresh independent public 32-byte PK.seed and derive the actual native checking key from genuine Native.KeyGenFromSeeds; mock keys in tests do not count as real SLH tests. Publish (R,x,A,u,w, all beta_j,h_j, genuine pk, PK.seed, authenticated context, auxiliary data and related capsules). Derive the final statement and manifest with the actual pk after sampling the base statement and t, avoiding circular context/key dependencies. Honest Build in this restricted baseline knows K and must protect/erase it; no keyless or malicious N−1 ceremony is proved.

For *any* valid ORIGINAL witness z, verify the exact binary weight-w source equation. For each j let y_j=<beta_j,z> mod q, set center_M(v) to its unique centered representative in [-M/2,M/2), and compute:
\[
\widehat t_j=[y_j-\operatorname{center}_M(y_j-h_j)]_q.
\]
Then reconstruct K from the high parts, verify the genuine checking key, and perform an ordinary native signature off chain for the bound challenge path. Bitcoin verifies only the hypothetical native signature, not the NP relation, VM, PCP or dispute trace.

**Every-ORIGINAL-witness SAME-capability correctness is unconditional for this source.**
Because Az=u and z is weight-w binary, y_j-t_j=<e_j,z>-e_{*,j} modulo q, with absolute integer error at most B(w+1)<M/2. Since M divides q, center_M returns precisely that integer error, so t_hat_j=t_j mod q. Every valid z, including different z with different internal states, recovers EXACTLY the same precommitted K and native checking key. No common short preimage, canonical W, source oracle or witness privacy is required.

Illustration ONLY: q=2^24, n=128, m=4469, w=2004, chi uniform on [-128,128], M=2^19. Honest absolute error is at most 256640, versus M/2=262144 (strict margin 5504). Each t contributes 5 uniform high bits; d=103 coordinates give at least 512 master bits. These illustrative dimensions are NOT independently calibrated for practical QPT-LWE hardness, 128-bit security, SLH resources or a real ceremony.

## Exact planted statement distribution, composite-modulus hashing and full-public simulator

For this restricted **hard-TRUE planted-source game ONLY**, sample A uniformly in Z_q^(n×m), sample hidden z uniformly over T={0,1}^m of exact weight w, set u=Az mod q. The adversary is given (A,u) and the honest capsule but NOT the planted z, any legal target SOURCE opening or witness-correlated auxiliary data. Comp itself receives only (A,u). Other scopes have fresh native masters and fresh s_j/e_j, and their public outputs and any allowed disclosed source evidence must be independently generated or efficiently simulatable from the target public challenge.

For any distinct binary z,z' in T, at least one coordinate of z-z' is +/-1, a unit even modulo 2^k. Thus Pr_A[Az=Az']=q^(-n) exactly, yielding the two-universal leftover bound for the entire JOINT (A,u) distribution:
\[
\Delta((A,Az),(A,U(\mathbb Z_q^n)))\le\epsilon
=\tfrac12\sqrt{(q^n-1)/\binom{m}{w}}.
\]
This bound would NOT automatically hold for signed-unit source differences of +/-2 over a power-of-two modulus. Any classical Comp postprocessing, genuine pk correlations, and any quantum operation on the classically presented public data preserve the TV bound. It does not survive auxiliary public fields depending on the hidden planted witness except through (A,u).

Assume ordinary nonuniform QPT decisional LWE for a uniformly sampled public matrix [A|u] in Z_q^(n×(m+1)), fresh uniform s_j, independent chi noise for all m+1 entries, and the corresponding fully uniform response vector; separately assume genuine QPT native EUF-CMA for 256-bit SK.seed and SK.prf and independently random public PK.seed, and authenticated manifest/context soundness. The QPT adversary may coherently process the entire classical public joint view, use independent quantum advice and make classical allowed-message signing queries. Quantum signing-oracle superposition, target valid-witness disclosure, hidden-witness-correlated advice, malicious one-honest setup, arbitrary related source dependencies and arbitrary adversarial x are OUTSIDE this theorem.

**Straight-line, full-public hybrid:** (1) Replace the planted hidden-z source (A,Az) with uniform (A,u), paying epsilon. Comp depends only on (A,u); generate real checking-key, manifest, context and signing correlations as postprocessing. (2) For each j replace the COMPLETE LWE sample (beta_j,t_j) with independent uniform responses, one ordinary QPT-LWE hybrid per j, all on the same public [A|u]. The challenge simulator computes h_j, the entire master K, the genuine native checking key pk and permitted native signatures from its actual candidate t_j and the other simulated columns, so it NEVER assumes an external SourceOpen oracle or knows the challenge secret s_j. (3) When every sample is uniform, the q=2^k, M=2^s factorization t_j <-> (h_j,floor(t_j/M)) makes the low h and high master bits EXACTLY independent and uniform. Native pk is now independent of A,u,beta,h and other allowed public aux, so embed the genuine native EUF challenger pk and allowed-signing oracle. A recovered usable native master yields a fresh native signature; an accepted fresh signature already wins EUF. No rewinding, classical-to-QPT lifting, supplied representation or random-oracle extraction is used.

If Win is such a fresh scoped native forgery/usable native master without an ORIGINAL witness on an independently planted hidden-witness source, the **restricted theorem** is
\[
\Pr[\mathrm{Win}]\le\epsilon +2^{-n}
+d\,\mathrm{Adv}_{\mathrm{QPT\text{-}LWE}}
+\mathrm{Adv}_{\mathrm{QPT\text{-}native\text{-}EUF}}
+\mathrm{Adv}_{\mathrm{QPT\text{-}auth}}.
\]
The negligible 2^-n term excludes the event that u has no odd coordinate; outside it, t=u^T s+e_* is uniform even before LWE hybrid, and the final uniform-world high/low partition is exact. Multiuser/related capsules require a target-guessing or union factor on ALL relevant terms, not just epsilon, and independent per-scope s_j and native keys. A supplied ORIGINAL witness for the protected claim makes the recovery authorized; no one-packet target SOURCE-opening secrecy is claimed.

Illustrative entropy: log2 binom(4469,2004)=4428.254611, n log2 q=3072, log2 epsilon <= -679.127305. This statistical bound alone does NOT imply 128-bit QPT security; the stated noise/matrix dimensions may be computationally insecure. The uniform-source game at this entropy is overwhelmingly TRUE (the planted distribution is close to uniform), so this theorem is not a meaningful arbitrary-FALSE security result.

## Exact fatal arbitrary-FALSE public-output attack — limits of this component

The release API checks binary validity, but arbitrary quantum/classical attackers need not call that API. Any NONLEGAL integer coefficient v with Av=u and |<e,v>-e_*|<M/2 recovers every t_j using the SAME public hint. For the exact FALSE instance q=4096, M=16, B=1, n=m=w=1, A=[1], u=3, the only weight-one binary z is 1, so no legal witness exists. The publicly known nonbinary coefficient v=3 has 3 beta=t+(3e-e_*), |3e-e_*|<=4<M/2=8, recovering the secret t for ALL s and all bounded errors. The executed checker exhaustively confirmed all 4096*3*3=36864 cases.

At the illustrative full dimensions construct public A with only its first column a nonzero and primitive, all other columns zero; set u=3a. All binary weight-w sources produce either 0 or a, never 3a, so the ORIGINAL binary-ISIS statement is FALSE. Yet y_j=3 beta_(first,j) estimates t_j with error at most 4B=512, far below M/2=262144. Every one of the 103 t_j and the EXACT 512-bit native master is thereby recovered for every secret/error choice, despite all public checking-key and statement-binding checks. The checker exercised forty complete 103-column false-key recoveries. For w>=3 and worst-case honest decoding requirement B(w+1)<M/2, 4B<=B(w+1)<M/2, so merely tuning the same linear reconciliation margin cannot remove the attack.

This is a deterministic complete-public FALSE security failure, not a no-go for generic witness encryption. It does NOT contradict the restricted planted-input QPT-LWE theorem because the adversarial A/u distribution is far from uniform. Directly feeding a generic 3CNF-to-syndrome matrix into Comp also falls outside the theorem, and the old fractional/pseudoopening failures return. A successful generic ORIGINAL compiler needs a **cryptographically enforced nonlinear release gate** that rejects the attacker’s public nonbinary linear combination *inside* the cryptography, not merely at the exposed release API. No such gate or full-joint QPT simulator is instantiated here.

## Actual validation and exact next handoff

The appended JavaScript checker was actually executed in the publication session and its exact source, output and provenance are preserved with this record. It tests 32 deliberately nonuniform toy instances with 128 distinct valid openings and the same recovered 512-bit K; exhaustive high/low factorization of q=4096; 36,864 FALSE exact recovery cases; 40 full-size 103-column FALSE master recoveries; all 15 binary-source pairs under exact Z_8 two-universal hashing; and illustrative entropy, dimensions and margins. The independent offline Python stdlib checker passed 45,848 assertions TWICE with byte-identical output; its exact bytes are preserved in the linked local research archive, not asserted identical to JS. Neither checker uses genuine SLH signatures or tests QPT adversaries.

Missing for the ORIGINAL Bitcoin/SYS application: witness-free classical-PPT Comp(R_original,x,ctx,pk) and public Lift from **every** qualifying ORIGINAL W with identical precommitted native capability; arbitrary FALSE and hard-TRUE full-joint-public QPT security or arbitrary recovery/native forgery to actual ORIGINAL W or independent PQ break; malicious N-of-N honest-erasure/abort and graph/DA composition, SYS/BTC header/AuxPoW/tags/interval/fork evidence, and hypothetical no-EC-key-path native PQ Bitcoin endpoint. The exact unresolved equation is
\[
\forall W:\ R_{\rm original}(x,W)=1
\Longrightarrow\mathrm{Recover}(\mathrm{Lift}(x,W,\mathrm{Comp}(R_{\rm original},x,\mathrm{ctx},pk)))=K^*
\]
**together with** a single sound complete-public reduction that blocks all nonlegal algebraic release paths. No production action or deployment is justified.
