# Normalized QAP source coupling for the spectral candidate

Checkpoint `qap-source-coupling-20261022`. Interactive retry; no scheduler run ID supplied.
Starting syscoin/PVUGC#1 head: `278fb342262de40dec3ccf24655d8cf0dcbf4d3f`.
Branch: `research/pq-wkem-validation-20260918`; observed open/draft/unmerged.

## Result and exact scope

This continues the unmasked spectral candidate after the two committed public recovery regressions. It does not repeat those attacks as the deliverable. The component implemented here replaces a local normalized R1CS source with an off-domain quadratic arithmetic program (QAP), keeping the same typed gates and spectral decoder. There is an explicit original-witness lift and supplied-source extractor, plus a uniform lower-rank theorem for the **source-only perturbation** across every coefficient direction. The latter is stronger than observing that individual input columns happen to look dense.

This is NOT a secure witness-KEM or a proof that all commutator/central-polynomial attacks are defeated. It does not establish arbitrary-QPT key recovery to ORIGINAL extraction. QAP is an established technique, and using QAP against sparse AADP attacks was already suggested by the original authors. The contribution of this checkpoint is an executable normalized integration with the current spectral carrier and a precisely quantified all-direction source-rank property. No invention of QAP or new hardness assumption is claimed.

The original sparse four-form compiler with small blocks remains broken in its recorded scope. The new compiler is not asserted to be equivalent to that broken ciphertext distribution.

## 1. Classical compiler and exact algorithms

Work over F_q. Fix a complete normalized R1CS source z=(1,z_1,...,z_n), with m>=2 rows

    (A_i z)(B_i z)=C_i z,  i=1,...,m.

The statement includes the actual relation/context and all Booleanity, input, gate, and acceptance constraints. Assume its accepted z has a public ORIGINAL-source extractor. The concrete tests use Boolean variables and a sum constraint; they do not implement the Syscoin evidence grammar.

Choose distinct gate nodes t_1,...,t_m and L>=2m-1 distinct evaluation nodes e_1,...,e_L, disjoint from the gate nodes. Sufficient field size is q>=m+L. The reference code additionally avoids node zero and therefore requires q>m+L. Let ell_i(T) be the Lagrange basis on the gate nodes and Z(T)=prod_i(T-t_i).

For each source coordinate j define

    a_j(T)=sum_i A_ij ell_i(T),
    b_j(T)=sum_i B_ij ell_i(T),
    c_j(T)=sum_i C_ij ell_i(T).

All have degree <m. Write A_z(T)=sum_j z_j a_j(T), and similarly B_z,C_z. Introduce coefficients h_0,...,h_(m-2) for H(T), degree <=m-2. At every evaluation node enforce the normalized typed constraint

    A_z(e) B_z(e) = C_z(e)+Z(e) H(e).

Thus the new source y=(z,h) has k=n+m coefficient coordinates INCLUDING its fixed constant coordinate, and L constraints.

**Encode(w).** Obtain the complete original z, and divide A_z B_z-C_z by Z. A valid original has zero remainder, and its unique quotient H has degree <=m-2. Output y=(z,h). No canonical witness is selected: different original witnesses retain different states.

**SuppliedSourceExtract(y).** Check the normalized constant is one and all new constraints, then return the original z through the original extractor.

**Correctness and soundness proof.** The polynomial F=A_z B_z-C_z-ZH has degree <=2m-2. If all L>=2m-1 new constraints hold, it has more roots than its degree and is zero. Evaluating at each gate node gives the original R1CS row. Conversely a valid original makes A_z B_z-C_z divisible by Z, with the stated unique quotient degree. This proves a bijection between original accepted normalized sources and accepted extended normalized sources. It is not an extractor from a bare recovered key.

**Build.** Use the Run593 typed block gate with a=A_z(e), b=B_z(e), c=C_z(e)+Z(e)H(e), d=1. Internal b-by-b mixing forms X_e(y) are fresh random affine forms. Outer L_e in F_q^(N x 4b), R_e in F_q^(4b x N) are independently uniform. Fix the MINIMAL margin N=2bL+1. Set

    M(y)=sum_e L_e G_{X_e(y)}(a_e,b_e,c_e,1) R_e,
    C_0=M_0+K I_N, C_j=M_j for j>0.

Publish the full aggregated coefficient array, compiled-source specification (or its deterministic generator), q,b,N, context, native public key and any correctly scoped key-selector data. Private factors and coins are not published. There are NO residual shields and NO extra nullity margin. An honest-erasure setup baseline is retained; the distributed ceremony is not implemented or proved.

**Recover(w).** Encode w, evaluate C(y), apply the existing spectral decoder, and select the intended capability under its original selector conditions. Each valid typed gate has rank 2b since d=1, so rank(M(y))<=2bL<N for EVERY valid witness. K is therefore a field eigenvalue. The implementation factors characteristic polynomials in small fixtures, using a synthetic public hash selector, not an actual Bitcoin or native-SLH transaction.

## 2. Source-direction support theorem

This section adds an exact condition to make 'dense source' meaningful under arbitrary linear recombination.

Assume the stacked FREE-coordinate matrix [A_free;B_free] has full column rank n. This is an efficient public check. It holds when every original Boolean wire has an explicit Booleanity row z_j*z_j=z_j. It must not be silently assumed for an arbitrary field-valued R1CS. The reference checker verifies this condition.

Let eta be ANY nonzero vector in F_q^k, including arbitrary values for H coefficients, and form the four source-form coefficients (a_e(eta),b_e(eta),c_e(eta),d_e(eta)). At least

    Delta = L-m+1

evaluation gates have a nonzero tuple.

Proof: if eta_0!=0, d_e=eta_0 is nonzero at every node. Otherwise, if the original free-coordinate direction is nonzero, injectivity guarantees a nonzero A or B polynomial of degree <=m-1, with at most m-1 roots. H cannot cancel that polynomial because it enters only c. Finally, if the original direction is zero but the H direction is nonzero, c=Z H. Z is nonzero at every evaluation node and nonzero H has at most m-2 roots. Hence this case has at least L-m+2 nonzero tuples. These cases exhaust all nonzero eta. QED.

No knowledge of a witness is needed for the theorem, and it covers coefficient directions chosen after setup. It does not depend on treating the H coefficients as Boolean.

## 3. Source-only rank and its uniform preservation under dense outer mixing

Let S(eta) be the block diagonal matrix whose e-th block is G_0(a_e,b_e,c_e,d_e), i.e. the typed gate with its internal X set to zero. Let

    E(eta)=L S(eta) R,

where L concatenates the outer L_e and R stacks the R_e. This is the source-only term in the existing M=internal-mixing+source decomposition.

Every nonzero scalar tuple gives two nonzero 2-by-2 scalar blocks, each of rank at least one, tensored with I_b. Thus

    rank S(eta) >= r0 := 2b(L-m+1)  for every eta != 0.

This is a lower bound on the specified source-only term, NOT on C-KI, and not on every conceivable alternative decomposition of C.

### Random projection lemma

For any fixed matrix S of rank r and independent uniform compatible L,R with square output dimension N, put t=min(N,r). For integer a>=0,

    Pr[rank(LSR)<t-2a] <= 8 q^(-(a+1)^2).

Proof: by invertible coordinate changes LSR has the distribution UV, where U is uniform N-by-r and V is independent uniform r-by-N. For an alpha-by-beta uniform matrix, a rank deficiency at least d from min(alpha,beta) has probability at most

    4 q^(-d*(abs(alpha-beta)+d)).

To see this, transpose so alpha>=beta, enumerate d-dimensional kernel subspaces (at most 4 q^(d(beta-d))), and multiply by q^(-alpha d), the probability of annihilating one. The Gaussian-binomial factor is <4 over every finite field. This proves the bound without a cryptographic assumption.

Apply it to V with d=a+1. Except with probability 4q^(-(a+1)^2), rank V>=t-a. Condition on V of rank v; the product UV has the rank distribution of a uniform N-by-v matrix. A second application gives rank(UV)>=v-a except with the same bound. A union bound proves the claim. Vacuous negative thresholds simply give an empty bad event. QED.

### Simultaneous source-rank theorem

For the compiler above and its independent dense outer factors,

    Pr[exists eta != 0: rank E(eta)<r0-2a]
      <= min(1, 8*(q^k-1)*q^(-(a+1)^2)).

Proof: apply the projection lemma to each fixed nonzero eta and union-bound over q^k-1 vectors. No independence between different directions is required. On the complementary setup event EVERY nonzero direction has the stated source-only rank. Hence adaptation to the complete public array, arbitrary computation, and coherent QPT postprocessing cannot produce a counterexample to this particular structural property.

This theorem does not require a classical-to-quantum rewinding argument. It is an information-theoretic property of an honestly sampled setup. It is NOT QPT key hiding: a successful key-recovery algorithm need not produce a low-rank E(eta). Matrix-valued transformations, another decomposition, and nonlinear processing remain outside this structural conclusion.

## 4. Size and parameter choice

Take L=2m-1, the smallest evaluation count justified uniformly by this degree-only polynomial identity proof. This is not a universal size-optimality theorem for QAP or witness encryption.

Then k=n+m, N=2b(2m-1)+1, Delta=m and r0=2bm. The dense field-element payload is

    (n+m)*(2b(2m-1)+1)^2,

versus (n+1)*(2bm+1)^2 for the original normalized source encoding. The metadata, native key, context and selector must also be counted. The compiler basis may be regenerated from the complete public source; an arbitrary basis cannot be omitted for free.

For n=29,m=30, the dense payload increases by 7.48454x at b=1 and 7.54496x at b=2. For n=11000,m=16000,b=1 it increases by 9.81637x. There is no practical-size claim. Compression of these huge arrays is not a substitute for the missing security proof.

For an illustrative q>=2^256, n=11000,m=16000,b=1, choose a=164. Then every nonzero source-only direction has rank >=31672 except with probability at most 2^-57597 by the conservative bound. This number concerns ONLY the source-density event, not 128-bit security of a key or signature. Such a field and enormous payload are not endorsed parameters.

## 5. Executed checks and a necessary negative qualification

The final bounded checker passed 737 explicit assertions. It exhausts 29,380 extended normalized assignments in four small true/false source cases; checks all 342 nonzero coefficient directions in one F7 fixture; performs an exact 4,096-product rank census; and recovers the same synthetic key through three distinct original witnesses for each of b=1,2 (six recoveries, with different matrices).

The recorded public-pencil diagnostics test three fixed slice selections in each of four new-candidate setups over F65537. In all twelve tests F0-KF1 was FULL rank, so these particular pencils did not expose K. HOWEVER the normalized R1CS control also had full rank: it is not the projectively safe four-form source used by the earlier committed attack. Therefore these diagnostics DO NOT prove that QAP alone repaired that attack. An initial expectation that this changed control would reproduce the old attack failed; that assertion was removed and the control's distinct scope is recorded rather than concealed.

A larger execution at n=29,m=30 completed with 736 assertions before the final extra census assertion was added. Its transformed dimensions were 119 and 237. A combined command attempting a repeat exceeded the local 200-second limit during the repeat, which produced no final output. It is not counted as a completed repeated run. The final bounded n=7 regression checker and unchanged core were then run twice within the bounded execution, with byte-identical full stdout. Both scripts compile. SymPy emitted a nonfatal modular-integer ordering deprecation warning, captured locally.

All tests use exact finite-field arithmetic and deterministic toy coins. They do not prove hardness; assertion counts and no-attack-found are not security evidence. The structural theorem, not the samples, covers all directions.

## 6. Cumulative ledger and adversary surface

Verified reusable pieces: original typed-gate rank lemma; normalized QAP witness lift/extraction; same-key spectral correctness; all-direction source-support lemma; simultaneous dense-projection source-rank bound. No new assumed release oracle.

Missing: computational hiding of the full public operator on false instances; arbitrary hard-true key recovery or accepted native forgery -> ORIGINAL witness/independent QPT break; malicious/abort-secure N-of-N setup; related capsules and public checking-key correlations; concrete efficient resource parameters; actual SYS/BTC relation and transaction-graph integration.

Normalization is essential. The new source theorem is on z0=1. Homogenizing it introduces H-only solutions at infinity; projective safety of the prior four-form compiler does NOT transfer automatically. This is an explicit outstanding interface, not a completed projectively safe replacement.

Attack taxonomy: scalar source-coordinate cancellation/recombination is covered by the rank theorem for E, not all ciphertext processing. Full public descriptions and fixed commutator/central-polynomial probes were considered, with the control caveat above. Global frame synchronization, distribution fingerprints, alternate algebra decompositions, chosen inputs, related capsules and genuinely coherent quantum attacks have no comprehensive hiding proof here. Retaining setup coins still reveals the key, so this is not keyless setup. Context binding and native signatures do not repair ciphertext leakage. The supplied-source extractor is not falsely presented as key-only extraction.

Next exact gap: prove or refute full-public-output security for this normalized globally coupled carrier, INCLUDING the freely varying quotient-witness coefficients and alternative public matrix pencils. Before claiming a deployable repair, resolve normalization/projective safety and compare against the exact earlier attack family under an honestly justified source transformation. Do not optimize this carrier as though it were already secure.

## Primary literature and exact dependency

- Latest live audit: `research/pq-wkem/unmasked_spectral_20261022/UNMASKED_SPECTRAL_PUBLIC_RECOVERY.md` at starting head above, read in full. Its exact attack formulas and typed gate are the relevant dependency; current ordinary comments 6356389755 and 6356648337 were read before this work.
- Gennaro, Gentry, Parno, Raykova, Quadratic Span Programs and Succinct NIZKs without PCPs, Section 4, Definition 7 and Theorem 5 (PDF pp.19-20, screenshots inspected): https://www.andrew.cmu.edu/user/bparno/papers/quadratic.pdf . Only arithmetization is used, not its pairing/knowledge-assumption security.
- Patrick Towa, Swiss Crypto Day 2026, PDF slide 60 (one-based; screenshot inspected) already proposes QAP coupling against sparse AADP attacks: https://swisscryptoday.github.io/assets/2026-09/talks/PatricTowa.pdf . This is architectural precedent, not a QPT theorem for this construction.
- AADP authors' challenge specification: https://www.allocinit.xyz/posts/challenges . It expressly describes heuristic rather than standard-assumption security. No complete new AADP paper/errata audit is claimed.

Production unchanged. No completion claim and no automation disablement.
