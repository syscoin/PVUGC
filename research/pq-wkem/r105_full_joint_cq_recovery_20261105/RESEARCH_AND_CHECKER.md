# R105 — Correct full-public CQ root-recovery bound, and post-view target selection

Run `R105-FULL-CQ-JOINT-IMAGE-BOUND-CORRECTION-20261105`. Project `syscoin/PVUGC#1`, branch `research/pq-wkem-validation-20260918`, actual verified start SHA `cf7b946113e87fc818dea38bfe63771c3e458164` (open/draft/unmerged). Exact predecessor R104 `research/pq-wkem/r104_mixed_malicious_monotone_20261105/RESEARCH.md`, blob `dcb45ae7bd21a30854e4f9c64d7f2f1b1908b1ae`. Offline mathematics only; GitHub continuity/publication reads authorized.

**Status: a material correction and restricted full-cq proof lemma, not a new generic witness-KEM construction.** There is still NO generic ORIGINAL-NP-to-LWE compiler and NO arbitrary recovery-to-ORIGINAL-witness reduction. The R89/R98/R99 near-key breaks persist.

## The wrong bound from R103/R104

Those runs reported the following *terminal exact hidden-root guessing* term in an LWE-PKE / PRG full-view hybrid: `2^(kappa-L_G)` when `G:{0,1}^kappa->{0,1}^L_G`. This was an error, conflating `Pr_U[U belongs to Image(G)]` with `Pr[attacker's guessed root equals the actual independently sampled T]`.

In the final hybrid, hidden `T <- Uniform({0,1}^kappa)` and a new uniform `Y <- Uniform({0,1}^L_G)` are **independent**; all public checking/auxiliary outputs must be computed from Y, not from T. An attacker can blindly guess T with exact probability `2^-kappa` for any L_G. For `L_G > 2*kappa`, the prior image bound would be *smaller than this unconditional success event*, hence it cannot be a security upper bound.

The finite checker below selects kappa=3, L_G=9 and an injective toy G. It exhaustively enumerates all 4,096 (T,Y) pairs. Returning G's inverse if Y is in its image, otherwise zero, hits the actual T in 512 cases: `1/8`. The incorrect image term is only `8/512=1/64`. This is a direct correction, not a crypto hardness test.

**Correct fixed-target bound for the precisely restricted R104 experiment**:
`Pr[output exact T] <= Q_target * eps_INDCPA + eps_PRG + 2^-kappa + eps_binding/audit`.
Here `Q_target` is the actual number of challenged honest-key packed ciphertext groups; it is not an abstract SourceOpen oracle. Native-signature forgery remains a separate game with its own QPT-EUF-CMA premise; one cannot replace that premise with exact-root guessing.

## Exact restricted source, joint public view and QPT model

Let `P` be the existing polynomial-size monotone AND/OR formula over N labeled LWE-credential occurrences, with repeated identities. Fix adversarial/malicious key identities C and honest identities H such that P(C)=false. The complete C-occurrence plaintext-share vector (not only its marginals) is perfectly independent of its root by the *proved* R103/R104 sharing induction. For each capsule j sample an independent kappa-bit root T_j, independent sharing randomness and native presignature for the bound, distinct challenge message.

Classical honest setup samples a shared uniform matrix `A in Z_q^(m x d)`, independently honest `S_i,E_i` and `B_i=A*S_i+E_i mod q` for each i in H. The exact R101/R102 honest PKE uses q=65521,d=256,m=1656,ell=16,beta=3 and exact uniform bounded-L1 septenary encryption randomness (uncalibrated). An arbitrary *nonuniform QPT* malicious key generator, given all honest public keys and advice independent of protected roots, chooses any classical B_i for i in C and retains an entangled quantum register. Malicious B_i can be publicly decryptable and dependent on all honest PK. The adversary may receive all C plaintext shares, C encryption coins, malformed-key secrets and auxiliary information independent of protected roots. No honest-key exposure, future honest corruption, source-opening oracle in superposition, unmodelled hidden-coin public receipt, or independently T-leaking auxiliary input is permitted.

The entire public record comprises the **actual restricted relation and statement**, all public A/B keys, claim/UTXO, challenge branch, intended native VK, anchors/window/graph/context, all target and related capsules and ciphertext bytes, Dsig_j = sigma_j XOR pad(G(T_j)), the joint manifest J binding all ciphertexts, native VK, descriptors and Dsig, checking key CK_j = F(check(G(T_j)),J,Dsig_j,ctx_j,related descriptors), and Aux_j = F_aux(check(G(T_j)),CK_j,J,keys,VK,ctx_j). Every public attestation must be classically simulatable from the actual ciphertext and an independent attestation key; it must not reveal the private audit receipts or PRG seed. The derivation order is acyclic: ciphertexts/Dsig, then J, then CK, then Aux. Same-claim related capsules have independent roots; any explicitly disclosed related root is **excluded from the protected target set**.

For a fixed nonempty protected set U of undisclosed capsule indices chosen before root sampling, replace every honest-leaf packed ciphertext group in every capsule j in U with honest-key **zero plaintext** encryption by sequential IND-CPA hybrids. To embed each *genuine ordinary LWE-PKE challenger*, use its actual (A,B_i), sample all other honest B_h using that SAME A and independent S_h,E_h, invoke the adversary's malicious generator on the honest public keys, generate all other honest/malicious and related ciphertexts with public operations, and recompute actual J/CK/Aux and public attestations from the challenger ciphertext. Neither challenger secret nor challenge encryption coins are needed. Source-key disclosures would defeat this simulator, and the exact distributional QPT-LWE IND-CPA premise remains **unverified/numerically uncalibrated**.

After all protected honest groups have been zeroed, the joint C-occurrence share vector is T_U-independent, by the actual formula sharing proof, even for repeated C identities; all corrupt ciphertexts/coins are functions of the vector, independently sampled coins and chosen keys. All other capsule roots and records are independent of T_U. Therefore, replace each protected PRG output G(T_j) by independent uniform Y_j using an ordinary straight-line nonuniform QPT PRG distinguishing hybrid, rebuilding **all** masked native signatures Dsig, joint J, CK, Aux and related public data from Y_U. This is not a PRG hybrid on only a marginal pad; the whole bundle is rebuilt. The adversary's retained quantum state from malicious setup was prepared before the roots and remains independent of T_U.

## Full classical-quantum product lemma

In that final uniform world, all root-dependent channels to the public have been removed: protected honest ciphertexts now encrypt ZERO, complete C-occurrence share vectors are perfectly root-independent, and G(T_j) has been replaced by independent Y_j. For any adversary quantum auxiliary register E and complete public classical record V from the above experiment, the exact cq state is

`rho_(T_U,V,E) = (2^(-kappa*|U|) * sum_{t_U} |t_U><t_U|) tensor rho_(V,E)`.

All source setup / challenger / malicious-key correlations are in rho_(V,E); the claim is a **joint state equality**, not ciphertext marginal secrecy. Applying any joint/coherent QPT measurement or channel to (V,E) cannot create information about the independent classical T_U.

Thus an algorithm that examines the ENTIRE related bundle and then outputs **one** index J in U together with one kappa-bit guess g has `Pr[g=T_J] <= 2^-kappa` in this final world — even when it chooses J *adaptively after observing CK/Aux/contexts/other capsules*. (For an always-valid one-pair output, equality holds.) The index may depend on V,E but not on the independent hidden roots. If it outputs h candidate pairs rather than one, the elementary union term is h/2^kappa. If it may choose a revealed capsule, the bound is inapplicable, as that target is already open.

Writing Q_U for the number of honest packed ciphertext groups across **all** protected capsules, and s_U=|U| for the number of PRG replacements, the corrected *conditional* arbitrary post-view, single-protected-target recovery bound is:

`Pr[A outputs J in U and g=T_J] <= Q_U * eps_INDCPA + s_U * eps_PRG + 2^-kappa + eps_binding/audit`.

This pays for ALL protected ciphertext/PRG replacements, so it does not require an *additional* multiplicative target-selection penalty in the **final information-theoretic guessing term**. This is a restricted full-public QPT proof repair; it does **not** give adaptive corruption of honest keys, adaptive selection of U based on T-dependent side information, malicious complete source setup, arbitrary FALSE-instance NP security, a hard-TRUE ORIGINAL-witness extractor, or a proof that actual R101 parameters satisfy 128-bit QPT strength. Accepted native-signature forgery is separate and can require native challenger target-index guessing, even after the root proof.

## Exact OFFLINE executed checker

This is the exact Python source executed offline (not a QPT experiment):

```python
#!/usr/bin/env python3
# Exact finite illustration of R105 (not a quantum-security experiment).
import hashlib,itertools,json
k,L=3,9; K=1<<k; Y=1<<L
G=lambda t:int.from_bytes(hashlib.shake_256(b'R105-TEST-PRG'+bytes([t])).digest(2),'big')>>7
assert len({G(t) for t in range(K)})==K
decoder={G(t):t for t in range(K)}
hits=sum(decoder.get(u,0)==t for t,u in itertools.product(range(K),range(Y)))
assert hits==Y and hits/(K*Y)==1/K and K/Y<1/K
pairs=0
for a,b in itertools.product(range(0,Y,37),repeat=2):
    j=((a*19+b*7)^0xAC)&1
    guess=decoder.get((a,b)[j],(a^b)&(K-1))
    successes=sum((t0,t1)[j]==guess for t0,t1 in itertools.product(range(K),repeat=2))
    assert successes==K
    pairs+=1
print(json.dumps({'run':'R105-FULL-CQ-JOINT-IMAGE-BOUND-CORRECTION-20261105','k':k,'L':L,'exact_single_target_pairs':K*Y,'successful_single_target_pairs':hits,'guess_probability':1/K,'old_image_term':K/Y,'adaptive_visible_pairs':pairs,'outcome':'PASS; source-to-ORIGINAL-witness unsolved'},sort_keys=True))
```

Captured executed stdout, with no edits:

```json
{"L": 9, "adaptive_visible_pairs": 196, "exact_single_target_pairs": 4096, "guess_probability": 0.125, "k": 3, "old_image_term": 0.015625, "outcome": "PASS; source-to-ORIGINAL-witness unsolved", "run": "R105-FULL-CQ-JOINT-IMAGE-BOUND-CORRECTION-20261105", "successful_single_target_pairs": 512}
```

The independent local extended `checker.py` (4,303 assertions) and `RESEARCH.md` include expanded checks and full derivation; these are **LOCAL ONLY** unless separately published. The inline published checker is the exactly executed `checker_publish.py` (SHA-256 `117efcbf04b1901a722206dca97069fc3ba02d734651a132a66ce8edccad93c6`); stdout SHA-256 `3f57cae10e362b82eaf8d4dc728b0f41f89b6095905940472105a0a2d218f27b`. Finite toy fixtures cannot certify QPT hardness.

## Remaining indispensable ORIGINAL equation

Find genuine classical-PPT `Comp(R_original,x)` producing the **source-dependent** LWE public key, witness-opening data, whole capsule/context/CK/Aux/related-capsule joint distribution and a genuine LWE-challenge simulator *together*, so that `Open(Comp(R_original,x),w)=T` for **every** valid ORIGINAL witness and ANY arbitrary unauthorized QPT capability recovery or accepted native forgery yields an **actual ORIGINAL witness** (not merely a supplied internal representation) or independently justified PQ break. The new proof repair does NOT close this. Avoid reusing R89/R98/R99's broken affine/slack source, public invalid near keys, conditional SourceOpen or unproven quantum extraction. Bitcoin original-NP verification and online release authorities remain excluded. Malicious N-of-N abort/graph/DA, qualified SYS/BTC fork evidence, reorg/window/censorship and hypothetical no-EC-key-path native SLH endpoint are also unproved and undeployed. Do not disable the continuing research automation.
