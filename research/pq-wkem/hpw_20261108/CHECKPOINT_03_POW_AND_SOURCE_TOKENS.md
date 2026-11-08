# HPW-R7 — PoW source-to-token coupling test and exact independence gate

**Status:** Bounded offline construction/repair iteration, not a breakthrough and not a secure witness-KEM. Preserve without routine user-facing PR comment. No lattice, group, obfuscator, size optimization or internet research.

**Continuity:** syscoin/PVUGC PR #1 (open/draft/unmerged), branch \`research/pq-wkem-validation-20260918\`. Start head \`45a465dadd9c0271c8036b62cca9c69f61668ca9\`, prior checkpoint \`CHECKPOINT_01.md\` Git blob \`010b3bea5755b780e05e91860c1818bb2560ace7\`. Intermediate \`CHECKPOINT_02.md\` was committed at \`44e41841336ca7459a23b4dd590bcab8add8ec21\`, read current branch head again before this note. Latest substantive ordinary PR comment at initial lookup: R153 6718361572. All writes scoped to \`research/pq-wkem/\`.

## Candidate A: precommit a hash secret, then release it by source-qualified PoW

Build_hash samples \`K ← {0,1}^d\`, freezes intended native-path signature \`σ\`, and publishes \`CK = H_check(ctx,K)\`, \`D=σ XOR H_mask(ctx,K)\`, with context bound to relation, claim/UTXO, anchored slot, challenge path and intended VK. Source evidence \`w\` is supposed to be an authenticated Syscoin child/header, Bitcoin parent AuxPoW/coinbase and interval/ancestor proof for the ORIGINAL relation. The attempted PublicDerive mines a nonce \`ν\` with a parent work hash whose first \`h\` bits satisfy the public PoW target and whose next \`d\` bits equal K. Since K itself is hidden, the miner checks the candidate next-d-bit value against public CK.

For an ideal independent 256-bit SHA256d work value, **each arbitrary fixed candidate byte string** w, whether it passes the ORIGINAL relation or not, yields probability

    p = 2^(-h-d)

per fresh nonce. Expected mining attempts \`2^(h+d)\`; \`Pr[success by N attempts] = 1-(1-2^(-h-d))^N\`. The raw hash function has no awareness of the off-chain source verifier. Therefore a fabricated header with wrong anchor, coinbase/path or absent canonical parent can be used as the hash input and mined identically. The adversary simply extracts K and ignores honest Open's post-hoc validity check. Binding the capsule root into a toy coinbase/Merkle field or writing R(x,w) into source-level software cannot stop access to SHA on invalid inputs. A full genuine Syscoin verifier would reject that evidence, but the capability was already recovered; this is a classical attack on the crypto release. This theorem is restricted to this prefix-selection family, not every hash-only WE or every possible consensus operation.

**Additional independent leak:** the public CK alone lets an attacker enumerate all 2^d candidate K. In a quantum random-oracle idealization Grover search may use O(2^(d/2)) queries. Choosing d≥256 to target ~128-bit QPT preimage work drives the proposed *honest* extra mining to expected 2^(h+256) hashes, which is not a practical release. Truncating K or spreading it across multiple easy puzzle bits does not fix the fake-source bypass.

### Executed synthetic test

The checked Python standard-library file \`r7_checker.py\` actually computes SHA256d of **80-byte synthetic parent-header-shaped strings**, with toy PoW target h=4 leading zero bits, d=9 secret-reveal bits, a deterministic synthetic merkle field binding the public capsule root, context and purported evidence, and a toy ORIGINAL predicate accepting one exact anchored source string. The forged evidence string violates that predicate; all raw hash searches still operate on it.

Over 16 independent deterministic fixtures, genuine evidence mined and reconstructed the same frozen 96-byte masked native signature 16/16; **invalid evidence also mined and reconstructed it 16/16**. The public CK alone exposed it by exhaustive key search 16/16. Genuine mine count 151,293 total hashes; fake count 138,537, both sample means near theoretical 8192, not a statistical proof of indistinguishability. These are toy fixtures, **not Bitcoin parent-chain validation, true Syscoin consensus, quantum security tests or a deployment.**

The actual executed source is \`r7_checker.py\`, its exact captured stdout is \`r7_captured.json\`. Local SHA-256 of source: \`7400512da9c6a86cf687bade1015f94e16c5a974b05853128b11fd79657de0b8\`. Output SHA-256: \`82582d2611bf42566773d373a7ddb83eecc47d500cf5ecd75eb38da8723d2d04\`. These checks are non-cryptographic functionality evidence; the ideal-domain probability equation is mathematical and separate.

## Candidate B: tie the ORIGINAL PoW evidence directly to the HPW hidden row tokens

Recall the independently sampled checkpoint-1 table. Let F_q contain distinct nonzero x_i and let f be uniformly sampled degree <t, baseline u_i public, and cell tokens \`Z_i,a=u_i+(a-a0_i) f(x_i)\`. For t distinct rows and nonbaseline coefficients a_i≠a0_i, the vector \`(Z_i,a_i)_{i∈D}\` is **jointly uniform** on F_q^t: the Vandermonde map from the t polynomial coefficients to those t evaluations is invertible, followed by independent invertible affine rescaling.

A natural hash-only PublicDerive would set \`z_i(w)=HashToField("source-token",ctx,WorkID(w),i,a_i)\`, with authenticated source evidence w and full PoW transcript. If this domain is independent of the hidden polynomial/table setup (including when work input carries a capsule root), each prospective vector is also uniform and independent. For a *fixed* independently sampled genuine source certificate w,

    Pr[(z_i(w))_(i∈D)=(Z_i,a_i)_(i∈D)] = q^(-t).

Even granting the SOURCE validity of w, the actual preimages required to open the table do not appear. The original source witness cannot open the capability; this is a direct completeness failure, not a security proof. In the F_7,t=3 exhaustive fixture, 343 polynomial coefficient tuples give all 343 possible evaluation triples exactly once and only one of 343 independent source-token triples matches a fixed target. Correlations across >t cells and adaptive work searches require separate analysis; this exact calculation covers a fixed t-row vector, not arbitrary future source correlations.

**Repair check:** defining all token values from a PUBLIC pre-existing source label makes them computable before the event, so secrecy is lost. Defining them from a SECRET setup seed prevents ordinary future source evidence from deriving them unless another secret issuer reveals them; revealing them to a source miner gives that miner early capability access. Defining them from FUTURE unpredictable work hashes makes Build unable to precompute a single consistent frozen σ/K relation for every valid future witness. These observations reject elementary direct-hash bindings, not every possible computational nonlinear construction.

## Syscoin-specific authentication and the missing mathematics

Preserve the two identities: \`OutcomeID=H(claim,slot,pure-child-header-hash)\` and \`WorkID=H(complete authenticated Syscoin/AuxPoW/Bitcoin-parent evidence)\`. Two different parent PoW solutions for one child do NOT define an incompatible source fork. Canonical-chain/parent work, coinbase-tag commitments, ancestor linkage, lag/interval observations and reorg/censorship assumptions must be checked in R_ORIGINAL. Root inclusion authenticates bytes but **does not cause the source transcript to contain hidden precommitted table preimages**. The example source verifier is synthetic and proves none of those consensus checks.

### Handoff

The actual missing constructive equation remains:

    Build_hash(R_ORIGINAL, x, frozen σ) -> (capsule, CK, J, Aux)
    PublicDerive_hash(x,capsule,w) -> SAME σ   for every R_ORIGINAL(x,w)=1

while arbitrary unauthorized QPT final-key recovery/native forgery must yield an ACTUAL ORIGINAL witness or an independently justified quantum hash break, without a token oracle or internal representation offered by the adversary. Need a compact, classical-PPT **cryptographic source-dependent correlation mechanism** whose correct outputs are bound to *authenticated* work rather than simply a public hash of arbitrary evidence strings. Full-public checking/multi-capsule/selective-opening simulation, malicious N-of-N honest-erasure ceremony, pre-funding DA, and a native PQ endpoint remain open. We have **not** built this mechanism, and no claim of secure WKEM or breakthrough is made.

Continue hash/PoW research; do not resume lattices or optimize the restricted credential scheme.
