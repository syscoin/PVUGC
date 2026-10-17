# Run 565 — Affine residual-span bypass of a late-witness release frontier

Research-only checkpoint at live PR #1 head c8696f2182ca28dc0ab5595f6b74eb323b497071. Date: 2026-10-17. PR remains draft/unmerged; production unchanged.

## Precisely narrower test than Run 564

Run 564 permitted an unrestricted public FHE circuit to overwrite an encrypted Boolean authorization flag. This run forbids arbitrary evaluation circuits and direct setting of acceptance flags: the adversary may only (i) invoke **one fixed authorized late-witness evaluator** on public candidate inputs and (ii) combine two resulting ciphertext states by a publicly supported affine ciphertext operation. This narrower interface is still insecure when the release gate checks only the *decrypted scalar residual*, not provenance of its source computation.

## Theorem: affine span of invalid residuals gives unauthorized capability

Let q be prime. An honest classical-PPT setup encrypts a fixed hidden capability K_x and an exact bound statement/UTXO/branch context vector x. A fixed publicly executable late-witness algorithm on any w produces c_w decrypting to (K_x,r_x(w),x), with public scalar residual r_x(w) in F_q. Genuine ORIGINAL representations are exactly those with residual zero and admit a deterministic source extractor. The *ideal secret-derived* output gate D_x returns K_x from a ciphertext decrypting to (K_x,0,x) and otherwise returns bottom. This grants the defender an output gate: no real construction of it is assumed.

Additional and indispensable assumption: the public representation supports Aff(a,c1,c2), decrypting componentwise to a Dec(c1)+(1-a) Dec(c2), and D_x does not cryptographically reject a mixed ciphertext based on its execution lineage. Neither arbitrary FHE circuits nor direct encrypted-register overwrites are granted.

Choose any two *invalid* candidates w1,w2 with distinct nonzero publicly computable residuals r1,r2. In F_q compute a=r2/(r2-r1) and b=1-a=-r1/(r2-r1). Form c*=Aff(a,c_w1,c_w2). Its plaintext equals:

- capability: a K_x+b K_x=(a+b)K_x=K_x;
- context: a x+b x=x;
- residual: a r1+b r2=0.

Therefore D_x(c*)=K_x although neither w_i is a valid ORIGINAL witness. The attack is classical PPT, hence also available to QPT adversaries. It uses only two authorized fixed evaluations and one affine combine, with no public acceptance-bit overwrite and no reversal of local masks. A public checking key can recognize recovered credentials but is not required to construct the attack.

## Distinguish false hiding from unauthorized true-instance release

For a conditional QPT one-way permutation f_lambda:{0,1}^n->{0,1}^n, choose q>2^n prime, set x=(b,y,context), ORIGINAL R(x,w)=[b=1 AND f(w)=y], and define:

- b=1: r_x(w)=int(f(w))-int(y) mod q;
- b=0: r_x(w)=1 for every w.

For a sampled true instance y=f(u), choose two distinct arbitrary candidates w1,w2 different from u. Injectivity gives distinct nonzero residuals, and the affine attack reconstructs K_x without computing u. For false b=0, every affine mixture of public evaluated states has residual a*1+(1-a)*1=1: this **particular attack** does not defeat that false branch. This does not prove false-instance key hiding for any instantiated encryption.

If there were a universal straight-line QPT extractor turning the forged release transcript into an ORIGINAL preimage, an inverter of f could generate the setup/hidden K itself and simulate the attack from y without u, then run that extractor. Thus extraction from the forged state does not follow from the release gate, conditionally on QPT one-wayness. This is not a claim about black-box extraction from legitimate native signatures.

## Boundary, source binding, literature

Source binding from Run 259 applies to a **supplied accepted complete representation** under its residual and SIS hypotheses. The mixed ciphertext c* is NOT such a representation. No extraction theorem for it is established. Authentication of *some affine calculation* is insufficient if affine combinations of outputs of invalid SOURCE computations are still permissible; policy must authenticate a single admissible source-consistent Join_R operation or an accepted complete representation. A real controlled transform language that excludes this affine combination is outside the theorem.

The exact live dependency notes are Run 564 blob fc6b3e6e17d24eeca9d53586a047fc63adaff1aa; Run 259 blob c7f3b77f0273ca1cbe6f0b31c1a086b8eb3acbf2; CLZ applicability blob c19d9d9cd515140e3ce62eac960cd548c0add622. Catalano–Fiore's homomorphic MAC work (EUROCRYPT 2013) is architectural background about authenticating allowed computations, not proof of this WKEM gate. No full CLZ merged-paper audit or attack on its actual controlled evaluator is claimed.

## Attack taxonomy and quantum model

Honest setup and fixed evaluation are classical PPT. Attacker is arbitrary (possibly nonuniform) QPT with all public outputs, keys, auxiliary material, and coherent access to published circuits; the attack itself is classical. (1) Local seam: public affine combination is decisive; (2) gauge: not needed; (3) statistical fingerprint: not needed; (4) two within-capsule views suffice, no related statement required; (5) adaptive public chosen inputs are essential; (6) malicious setup/retained randomness: unnecessary; (7) same exact context survives, no replay needed; (8) native verification key not needed for K recovery; (9) no quantum-specific acceleration established, independently justified QPT release still missing.

Executed checker is a **symbolic field-triple model**, not real FHE, a QPT-hard one-way permutation, a native SLH signature, or a constructed release gate. Its 127008 assertions validate exact finite interpolation and source/non-source cases only.

## Core handoff

Do not claim practical WKEM, source-authenticated controlled Join, concrete 128-bit hardness, or CLZ break. Need a classical-PPT practical restricted late-witness evaluator whose admissible states cannot be forged via affine closure, with every valid ORIGINAL witness recovering the same capability; full-public-output QPT false hiding; unauthorized true-instance recovery or native forgery -> ORIGINAL representation/independent QPT break; one-honest-party N-of-N ceremony; multi-capsule composition; and conditional native-PQ Bitcoin graph. Bitcoin itself performs no NP verification.
