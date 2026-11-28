# R193 — source-commitment hash garbling: exact family-level failure and repair attempts

**Status: no ORIGINAL-conditioned key release constructed.** A bounded direct candidate SCG was instantiated and falsified, then two repairs were examined. No quantum security test, full Bitcoin/Syscoin consensus verifier, native signing, or production code.

## Provenance

Research run 2026-11-10. Repository syscoin/PVUGC PR #1, existing branch research/pq-wkem-validation-20260918; starting head 08f7ce851fdb059d115cbb7238041af762496cd2. Read exact R192 direct source-hash research and R191 witness-activation research; recent ordinary comments since 2026-11-10T05:00Z were empty. Intermediate hypothesis committed at 1b7c5a78f93d1d3b841aa5739932f8e7fb6aa849 **before** local tests. No outside literature/web, no new branch, no independent subagent. The shorter checker in this directory was actually executed twice, yielding byte-identical captured stdout (320 functional tests); exact checker SHA256 e480f49ab343f1059003fd4a7f9793aecb540d037396d4e5284b89617d6fbb5d, captured-output SHA256 8847a5836980f3ce254a6df983f6160a473bb51bae062dfc8f80afa578808b92. Additional full local checker performed 3,584 base checks plus 768 explicit-consistency-gate checks; preserved at local path /mnt/data/pq_wkem_R193_sourcebound_garbling/ (not asserted GitHub published). Source hash 3278958b4c3ff75ba8f426cc93cb7dff897671aa45d6784c84ff075df665aae6. All are synthetic functional experiments, NOT QPT adversarial-security tests.

## Named proposal: SCG, source-commitment garbling

Target remains the ORIGINAL claim-bound R_cancel = valid stronger competing authenticated BTC work OR authenticated exact burn-authorization fault OR qualified SYS AuxPoW tag/ancestor inconsistency with LC depth. Any one notary can activate; any challenger must recover the SAME frozen N-of-N cancellation contribution from any valid ORIGINAL challenge, with source verification INSIDE release and no online authority or unrelated puzzle.

For each gate g in a bounded Boolean source verifier, Build samples secret independent 256-bit labels L[v,0],L[v,1]. A binary truth-function f_g gets four public rows:

    T[g,a,b] = L[out,f_g(a,b)] XOR SHA256("SCG/row"||z||g||L[left,a]||L[right,b]).

Freeze a claim-scoped native cancellation signature sigma and seal D=sigma XOR SHA256("SCG/pad"||L[accept,1]). The public checking key, capsule and source context are visible. z is a common source-commitment domain-separator. To permit arbitrary future original witness bits without an online issuer or a prespecified witness, public Open receives BOTH input labels for every source input bit. This is a concrete hash-based garbled-program candidate rather than merely an honest Open procedure branching on a visible raw secret.

## Full-public FALSE attack (proof, not QPT estimate)

For R(b)=b XOR b using the *same input wire* twice, every consistent b yields false, but an attacker with both published labels evaluates the local gate row (0,1) and directly recovers L[accept,1]. This decrypts the precommitted sigma with NO original witness and no SHA break. All operations share exactly one public z. A single honest N-of-N contribution with this carrier therefore fails as well.

More generally, if all labels for both input bit values of every circuit input are publicly available, a nonconstant gate table reveals *both* output labels by evaluating its local truth table. Induction yields both internal labels along such a gate network even when no **globally consistent** source witness reaches acceptance. A compiler optimizing a toy contradiction to constant false is possible, but it is not a general security theorem for SHA/AuxPoW NP verifier circuits.

## Attempted repair 1: explicit equality / global source label commitment

For the always-FALSE relation

    R(xA,xB) = NOT(xA) AND xB AND EQ(xA,xB),

honest evaluation for consistent xA=xB yields 0. The adversary evaluates the NOT gate with xA=0, the xB branch with xB=1, and **separately** obtains the equality YES label with xA=xB=0. It combines those public local YES labels to recover the accept=1 label. The checker reproduces this with 64 seeds; the fuller local variant uses 128.

A Merkle root of both input label families or a fixed z=SHA256(public source anchor) authenticates bytes but cannot force a globally consistent choice. Per-occurrence public labels derived as H(public seed, occurrence, z,bit) remain both available. Equality or hash validity checked solely by honest Open does not prevent raw row computation.

## Attempted repair 2: future actual SHA256d source work as z

If the row pad contains z=SHA256d(actual future source header), the setup-generated fixed table at z0 does not decrypt correctly for independently chosen future z1, except accidental hash equality. This fails the requirement that ALL valid future source witnesses recover the SAME secret. Recomputing row tables from public label-generation seeds for each z provides both labels to attackers and restores the false-instance mixing attack. A hidden seed unavailable after setup prevents honest permissionless Open unless some genuinely ORIGINAL-dependent source correlation generates it; no such algorithm was implemented. This is a restriction of this fixed-row hash-garbling family, NOT a general impossibility for nonblackbox SHA witness encryption.

## Exact missing step and next useful experiment

An actual polynomial classical Build_SHA(x,sigma)->C and PublicOpen(C,w)->same sigma for **every** legitimate original challenge must conceal all inconsistent internal label choices even under the full correlated public N-of-N view. Need quantum-safe source-dependent global consistency/extraction, not another public Merkle root, public z, ordinary verifier if-check, hidden online signer, or independent puzzle. R173 retained-source-secret and previous affine/supplied-representation regressions remain relevant. A future candidate must jointly provide the public quantum simulator and extraction of an ORIGINAL BTC-work/burn-fault/SYS-fork witness, rather than an inner representation alone.

No constructive cryptographic progress claimed; no PR progress comment warranted.
