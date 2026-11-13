# R213 — AFPI, a public source-digest polynomial/SHA release candidate

**Result: explicit candidate-class failure and repair tests ONLY.** No secure hash-only Build/Open, source compiler, QPT reduction, real mining or native signing. Do not notify as construction progress.

## Provenance

PR #1, draft/open, branch research/pq-wkem-validation-20260918. Initial head c4f6b7cce2790370575c08a438f57298959586dc; prior exact R212 RESEARCH.md read from 780fb62234d5e6b8edeb92403bf129c14dcd8bc4. Intermediate hypothesis checkpoint committed and fast-forwarded BEFORE tests at c4e71a586bfb3ad1629e74e0285ebc0809e4816a. No unrelated repo, external web/literature, independent agent, source code change, real BTC/SYS header, native PQ signature or quantum adversary used.

The full LOCAL Python checker ran twice with byte-identical results: 722 toy algebraic assertions. SHA-256 source a686cfbca693a66c1a82debd0afcf28c25fdaef78cc833e5ff6bc61b10b26903; output 452485e108cab7e33f52577b71c41eecad887c2cdfba018b459e8e96d5a326aa. A separate smaller reproduction, included here and actually executed twice, ran 240 assertions with matching output: source SHA-256 85dfc1ea989d8bb6693d7d15a1d472bf9d1c986c81732dd090037c32cc13e132; output SHA-256 f16c2385056c73a8c528cceef5d2b2c2ee952abdbd6411a8ea3e2d2419da4052. F_257 is a toy field, not a representation of 256-bit Syscoin hashes. One deliberately TRUNCATED eight-bit SHA-256 experiment found a collision at encodings 9 and 16, digest 113; it is not SHA cryptanalysis. The full checker and expanded mathematical notes were preserved locally as well.

## Original target, not replaced

One notary activates a withdrawal using a preauthorized N-of-N graph; anyone with an actual R1 (contradictory greater-work BTC), R2 (finite authenticated missing/invalid bound PoB), or R3 (qualified Syscoin claim-prefix fork or separately defined tag fault) witness must recover the SAME frozen claim/UTXO/path-scoped cancellation capability OFF CHAIN. Source evidence must authenticate actual SHA/AuxPoW, Bitcoin anchor, coinbase, parser, all relevant interval tags, parent linkage, child height, lag/window, real burn/authorization/recipient and exact cancel message/VK. Different parent-work certificates of one pure Syscoin child are not forks. An unrelated synthetic header or mere inequality of fake hashes cannot substitute. No live notary/challenge authority; native Bitcoin endpoint sees only intended signatures.

## Named candidate: authenticated-fork pair interpolator (AFPI)

Fix public withdrawal statement x_W and authenticated baseline. A future qualified R3 source witness P defines semantic digest z(P)=U_claim(P), the pure child hash at the withdrawal-relevant height. A candidate Build chooses uniform secret pad K and publishes a public degree-at-most-d polynomial P_C over a field, intending the public SHA finalizer F_C(z)=SHA256(domain||encode(P_C(z))) to equal K for EVERY genuine qualifying future z. It seals an already frozen native cancellation signature sigma using E=sigma XOR K. Honest Open verifies the source, derives z and computes E XOR F_C(z), then checks the native signature. However source authentication is only an honest-program check in this candidate; it is NOT cryptographically necessary for arbitrary public evaluation and therefore is not a secure witness gate.

### Exact candidate-class theorem

Fix a complete public capsule C and d+1 **distinct** possible qualifying semantic source digests z_0,...,z_d for the SAME fixed statement and future-source-admissibility universe. Assume every qualifying witness must yield common K=F_C(z_i). Either:

(A) Some P_C(z_i) and P_C(z_j) are different. SHA256 has identical K on two distinct encoded field inputs, so the two values mathematically form a hash collision; OR

(B) all P_C(z_i)=a. Then the degree-at-most-d polynomial P_C(z)-a has d+1 distinct zeros and is identically zero. The public polynomial is constant a and an unauthorized adversary computes K=F_C(0), and sigma=E XOR K, WITHOUT any original evidence.

This is deterministic algebra, so an explicit public evaluation also works for a QPT adversary. But collision **existence** is not an efficient quantum collision finder, and merely invoking SHA collision resistance does not exclude specific rare colliding values without a reduction. The theorem requires showing >=d+1 distinct potentially qualifying digests exist under the SAME fixed x_W/C and actual Bitcoin anchor/window rules. This run has not proved that real-source cardinality. It is NOT a generic impossibility of hash-based WE, a statement about arbitrary nonpolynomial public programs or a source-extraction theorem.

For a direct polynomial release P_C(z_i)=K with no final hash, more-than-degree root equality immediately makes P_C constant and publicly discloses K. A public hash finalizer adds only the collision alternative.

## Two explicit attempted repairs

1. **Known-point interpolation.** Choose t setup-known qualifying digests z_i and publish P_C(z)=a+Delta*product_i(z-z_i). At those points SHA(P_C(z))=SHA(a), but for later unknown qualified z it typically differs, violating EVERY-witness same-capability release. The builder cannot pre-select all future valid work-cert identities; a finite table of known source histories is a weaker relation. The executed F_257 checker uses t=3 and a distinct fourth candidate in 80 cases: each rejects the fourth while the first three open.

2. **Hash the entire source certificate rather than its semantic outcome.** Use z=SHA256(serialize(full BTC/Syscoin/AuxPoW source proof)). Future valid source certificate hashes are still unknown at Build and a public F_C can be evaluated on arbitrary fabricated z. The same conditional polynomial dichotomy applies to distinct qualifying certificate digests. A post-hoc verifier does not bind actual source authentication into the secret release; no QROM oracle programming or private issuer was supplied. No proof for this repaired model is claimed.

## Toy execution and exact next step

A full local script tested 80 cases of universal constant opening, unauthorized public recovery, finite-point interpolation and uncovered future witnesses, plus a controlled 8-bit collision-alternative fixture; output contained 722 functional assertions. The smaller published reproduction tested 48 cases and 240 assertions with full SHA-256 on toy field elements. These are arithmetic checks only—not security experiments, not QPT and not real chains.

A genuinely useful repair must abandon *publicly evaluable outcome-only masks* and make the **actual full SHA/AuxPoW Boolean source-certificate constraint** indispensable to computing any unlocking value, with a nonfactorized, globally consistent public encoding that resists direct extraction, label switching, mixed occurrences, affine/quotient evaluation, fake work and retained source coins. The low-degree exposed quotient/zero-residual forms were already ruled out in R207/R212; simply increasing degree or renaming their mask is not a repair. Construct classical-PPT Encap_R3(x_W;coins)->(C,K), Decap_R3(C,w)=SAME K for every ORIGINAL R3 witness, and full-public QPT recovery/native forgery -> actual original qualified source witness or independent hash/native break. Check real source, malicious setup, correlated capsules and honest erasure before considering optimization.

No ordinary PR comment warranted. Research automation remains enabled.
