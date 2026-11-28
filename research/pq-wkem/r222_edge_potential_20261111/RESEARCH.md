# R222-EPR — source-edge potential release and exact missing source correlation

**Disposition:** hash-only ORIGINAL-dependent public release attempt failed. No completed Build/Open, QPT theorem, deployed source validation or native signature. This note records the construction and concrete repairs, not a substantive WKEM advance; no routine PR comment or notification.

## Continuity
syscoin/PVUGC PR #1, open/draft/unmerged, actual branch research/pq-wkem-validation-20260918. Observed initial head 76d5218cb7a630104808a702300fd41f7fa001f3. R221 source-carried-Merkle-opening research read at exact blob 3e517f440c0e88da2cfb3308b2f874cd561d32a1; recent ordinary comment query since 2026-11-10T22:00Z was empty. Local intermediate CHECKPOINT_01.md was written before testing; intermediate PR commit d8f33f186e11b0531dbc0e1f46f098bf0a640480 with parent equal to observed head. No web or external literature, independent agent, actual Bitcoin/Syscoin mining or external native signature used. Other files in this directory preserve checker and captured output. Complete longer derivation/checker remain in the local artifact of this run; this publication is a faithful mathematical précis.

## Exact target
Freeze claim/path/UTXO-specific native cancellation authorization before N-of-N graph funding. Later one notary may activate a bound withdrawal. Any outsider possessing original source evidence for R1 heavier contradictory BTC history, R2 finite authenticated PoB refutation or R3 qualified Syscoin claim-prefix inconsistency/applicable tag fault must derive the SAME frozen cancellation capability off chain. R3 must validate actual source anchors/window, child ancestry, every relevant AuxPoW coinbase/tag, SHA256d work and the minimum light-client fork depth; different parent work certificates on the same pure child do not imply a fork. A forged source path or synthesized work proof is not an ORIGINAL witness. The candidate below isolates a putative R3 release carrier, not the final combined relation.

Build_hash must be classical PPT and public Open_hash must give identical precommitted native capability for every qualified (j,w). Arbitrary full-public QPT unauthorized recovery/native forgery must reduce to an ACTUAL ORIGINAL witness or an independent PQ hash/native break; sibling capsules, source-controlled coins, malicious setup and auxiliary correlations are included. An honest Open returning nothing on fake witnesses is not sufficient if another public algorithm reads the key.

## Explicit candidate EPR
Let a be a fixed authenticated claim-prefix anchor. For a future qualified source path P=(v0=a,v1,...,vt), where adjacent edges are purported genuine child-header / AuxPoW ancestry, choose public hash potential p(v)=SHA256(domain || v). Define public edge difference delta(u,v)=p(u) XOR p(v). Let setup choose K uniform and freeze native sigma; publish B=K XOR p(a), D=sigma XOR Hpad(x_W,K), plus x_W, checking key, native VK and source commitments.

Proposed Open reads a qualifying path and computes

    K' = B XOR (XOR_{i=1..t} delta(v_{i-1},v_i)) XOR p(v_t)
    sigma' = D XOR Hpad(x_W,K').

By telescoping over XOR, every honest path gives K'=K, including paths with different states, lengths and work certificates. This meets the *algebraic* common-output identity without canonical witness selection. But **any fabricated path** also gives K, and more simply everyone can compute K=B XOR p(a) before any path or challenge. This defeats both FALSE and hard-TRUE security regardless of PoW, hash hardness or any verifier run only in an honest Open precheck. The true source histories do not cryptographically authorize access to B or p(a).

## Three concrete repair directions examined
(A) **Secret potentials.** Set p_s(v)=SHA256(domain || secret seed s || v), B=K XOR p_s(a). Honest recovery would require every future source edge to carry delta_s(u,v) and an endpoint p_s(v_t). Actual independently mined Bitcoin/Syscoin headers, tags and Merkle siblings contain only PUBLIC data, not s-dependent potentials. Setup cannot publish the correct keyed deltas for every later possible fork in polynomial space. Publishing s releases K immediately; retained source/setup s is a malicious-key bypass; an online signer/delta service is prohibited. This gives a precise missing source-to-correlated-label interface, not a repair.

(B) **Public certified-edge generator.** An algorithm G(C,u,v) could test true ORIGINAL source validity and only then release keyed edge labels. But if G is ordinary publicly inspectable SHA/Boolean code, hiding s or K while returning these labels is precisely the missing public conditional-secret mechanism. Giving G s plainly exposes the secret; using only public potentials reverts to the direct attack. Isolated parent PoW checks are not qualified source-history inclusion; a fake header does not become accepted by naming a Boolean ValidSourceEdge.

(C) **Precomputed table of verified edges.** A table for previously known source paths cannot cover all later one-notary activations, adversarial fork branches and arbitrary qualifying witnesses. Publishing a table/root authenticates its bytes but does not make it a secret opening, and paths already available before withdrawal may permit early release if endpoint labels are public. Pre-enumerating exponential possible future histories is not classical PPT setup.

No source-issued secret labels, hash collision, hidden trapdoor or quantum oracle programming was implemented. No SHA256 standard-model or QROM security theorem follows. The algebraic direct attack is exact even with an ideal random oracle.

## Actual bounded execution
checker.py ran twice locally with byte-identical output.json and rerun.json. Source SHA256 56728032b265f849fa24dcbd0dbc221ee78979a9c1832546fcfaa3caaa384b36; output SHA256 80d788562145abfb3b0e020079d776123c1029869848e9efe542cd284257f02a. Counts: 512 functional checks over 64 deterministic SHA256 contexts, two different synthetic paths and a forged unauthenticated path. They show (i) common K along both synthetic paths, (ii) forged path and public root both immediately release K, (iii) hidden-seed edge labels are absent from independent future source path, and (iv) retained private seed releases K early. This is **not** an actual SHA256d BTC header / target / retarget / AuxPoW / tag verifier, source-membership proof, native signature or QPT test. The equations, not the test counts, establish the failures. Only the exact files in this publication directory are claimed to be published.

## Handoff
The next admissible constructive step is an actual polynomial-size public hash/SHA source compiler jointly with a full-public quantum simulator:

    Build_hash(R_cancel,x_W,sigma_i;coins) -> C_i
    Open_hash(C_i,(j,w)) = SAME sigma_i for every ORIGINAL R_cancel witness.

For EPR specifically, this would require a nonpublic setup-correlated edge/terminal quantity that becomes available **from the real original source history itself**, without a retained source secret, future issuer, public fabricated path or revealed private seed. Real AuxPoW tag hash+height does not provide such tokens. Do not optimize a table, invoke a source verifier only as a post-decryption check, or treat the intermediate telescoping identity as witness encryption. The result is scoped to path potentials, not an impossibility theorem for arbitrary hash-only approaches. The research automation stays enabled.
