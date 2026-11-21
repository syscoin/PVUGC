# R333 — source-equivocation two-receipt seed escrow (NONQUALIFYING ORIGINAL WKEM)

## Verified continuity and novelty gate

Research began from actual open/draft syscoin/PVUGC#1 at `7923cd2234d382e06590a2c76e2aa33f910aa664` on `research/pq-wkem-validation-20260918`. R332 exact note blob `0406167e34a113db174fd9ba1d065419faeb3f6a` and R331 note blob `2bbfedbd1062ff9dc1c411b8be7feaccb034a77c` were read. The latest top-level issue comments since 2026-11-16T21:00Z returned none. Core #609 metadata read-only resolved `c91539de3c34937e57d7f5fda47c7b0502ff33f6`; public activation remains release-disabled. No fresh Core code/tests or authentic network source witnesses were run.

This candidate changes R330's public garbled-label or R332's graph-cycle model to a *source-native two-receipt equivocation secret*. It constructs source-dependent opening if a SOURCE ISSUER already emits secret-correlated receipts. The decisive test is whether ordinary ORIGINAL SHA/AuxPoW contains such receipts, without adding an online issuer or shrinking the three-branch witness relation.

## Conditional classical Build/Open, with exact equations

Use the ordinary finite field Fp for p=2^255-19 (field arithmetic, not an elliptic/discrete-log group assumption). At hypothetical setup choose a,b independently uniform in Fp, freeze the safe claim-bound native cancellation signature S (or a key solely encrypting that same fixed safe signature), and set ciphertext C = S XOR XOF("cancel" || encode(b)), with domain separation and output length |S|. One issuer signs/authenticates the first slot receipt (m0, y0), where y0 = a + b*m0 mod p. The HYPOTHETICAL SOURCE receipt rule is y(m) = a + b*m mod p, with authenticated same issuer and exact claim/slot provenance.

For any *distinct* second certified message m1 != m0 from this issuer, public Open computes
  b_hat = (y1 - y0) * (m1 - m0)^(-1) mod p,
  S_hat = C XOR XOF("cancel" || encode(b_hat)).
Any qualifying second *issuer-signed* message recovers exactly the SAME frozen S. This is a genuine algebraic common-capability construction for a NEW, equivocation-receipt relation, not for ORIGINAL sources. It needs an independent source receipt authentication mechanism and issuer erasure. A single notary initiation is not this issuer, and N-of-N vault preauthorization is not a source signer.

Restricted one-receipt classical-public distribution: the map (a,b) -> (y0=a+m0*b, b) is a bijection on Fp^2. Thus, for fixed m0, b is exactly uniform conditioned on (m0,y0) and external auxiliary/native VK data independent of a,b, even when VK correlates with S. In an ideal random-function model XOF(b) is pseudorandom against an attacker not learning/guessing b; this is not an exact joint QROM simulator with coherent queries or a concrete SHA native-signature proof. If the signer retains b, it can decrypt C BEFORE any conflict, independently of source authentication or maturity.

## Substituting the actual Bitcoin/Syscoin source — exact failed operation

An ORIGINAL qualified source observation contains SHA256d parent header, authenticated coinbase/strict modern contextual AuxPoW and exact canonical SYS ancestor tag, actual child ancestry and qualified LC history. It does NOT include y(m)=a+b*m from the setup-chosen hidden coefficients. Unique child per authenticated parent commitment does not generate an equivocation share; two different parents for the SAME child are not a child fork. No-PoB or greater-work ORIGINAL grounds need not have any second signature from a common source issuer.

To make the above Open work for every original witness without a signer, one would need a *serialized, classical-PPT, public and offline* function
  G(C, authentic ORIGINAL certificate) = a + b*m mod p
for EVERY qualifying future certificate m, with the SAME secret b fixed at setup, without permitting arbitrary fake/irrelevant certificate evaluation, and while hiding b against the full joint public view. This source-dependent issuer is the MISSING WE operation, not a property of SHA tags or Merkle roots.

A direct hash-only substitution G(m) = SHA256("independent public source receipt" || m) mod p has no common affine b: for three distinct m0,m1,m2, ideal independent uniform G values, (G(m1)-G(m0))/(m1-m0) and (G(m2)-G(m0))/(m2-m0) match with probability 1/p conditional on the first two outputs. This statement is ONLY for independent ideal-hash samples, not a claim that real Bitcoin/Syscoin certificates are independent uniform random field points. Conversely, publishing a globally affine G(m)=a+b*m allows the attacker to choose any two distinct arbitrary messages, compute G twice, and extract b without source evidence. Hiding its coefficient requires an unbuilt public source-gated evaluator. More SHA rounds, larger field size or unrelated hash commitments do not repair either case.

This model is not an actual ORIGINAL Build_inc/Open_inc. In particular no two-receipt source signature may be assumed as a prerequisite of a qualified AuxPoW fork; Source ChainLocks are optional. The three approved OR grounds, exact claim/UTXO/burn/amount/recipient, modern contextual tag/chain ID, BTC work/anchors/windows, actual ancestors, LC-depth, deadline/reset, native message/VK/capsule, and R225 activation portability remain unchanged. The native safe signature may not be an unrestricted theft authorization.

## Actually executed local checks and provenance

Python3 standard-library checker constructed scalar receipts and a 512-byte synthetic S masked via SHAKE256. Two deterministic executions, 1,158 arithmetic assertions each, yielded byte-identical JSON: both genuine issuer receipts recover b/S; 1,024 alternate (a,b) pairs preserve one receipt; retained b opens early; two synthetic unrelated double-SHA source value slopes differ; a public affine receipt generator gives b from arbitrary forged messages.

Checker SHA256: `1999cefc5036b7271bb668ca00134273273357be37c53ab2b26f9177908bace0`.
Both outputs SHA256: `45f02e63497d7dd7d684190101350308ef2a0ec755b60bd258ca0a0ddf8c880c`.
Full derivation, executed checker and outputs saved LOCAL-ONLY archive `/mnt/data/R333_two_receipt_source_screen_20261117.tar.gz`, SHA256 `c5779335748ce94f316ae3c1c9d4cb9b5b0b2f314e019893848d4dfbf309ee70`. The checker uses artificial messages, no contextual real Core admission, Bitcoin best-chain proof, SLH native signing or QPT experiment. The archive is NOT claimed to be GitHub published or persistent after this session.

## Exact next equation and qualification

**NONQUALIFYING, no ORIGINAL advance.** No original-source-dependent serialized Build/Open, complete-public FALSE and hard-TRUE QPT reduction, malicious-N-of-N/source retention proof, or sibling-capsule composition. The constructive two-receipt escrow requires unavailable, additional setup-correlated source attestations and trusted erasure. Do not pursue a larger toy or an independent-hash receipt patch. The next work must independently instantiate original-source-gated public G above, or replace it with an actual different classical-PPT Build_inc/Open_inc and its joint QPT simulator/reduction. No PR progress comment, deployment, Core modification, release, or user notification is warranted.
