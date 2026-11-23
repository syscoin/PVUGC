# Source-WOTS predecessor release screen (NONQUALIFYING for ORIGINAL bridge)

## Continuity and reason for choosing this family

This is one bounded, offline research iteration on the only missing ORIGINAL source-conditioned public release foundation. Before this run, live open/draft syscoin/PVUGC PR #1 was read at \`2ca0291d284554de952fb85ddfa0fd23dd3fc707\`, branch \`research/pq-wkem-validation-20260918\`; its immediately preceding work-share note was read at exact blob \`56c59a7257ab26d6dca54bccd64ebed469d21a43\`. The latest top-level issue comments since 2026-11-20 were empty. Core #609 was checked at PR metadata only (reported head \`af4d78335c6b9b180e3f652909cd2ce3934d07a8\`); no fresh Core source, tests, network evidence, or native signatures were verified.

R327/R366 and the latest polynomial-work-share attempt fail when input-specific secret labels are merely public evaluations. This iteration changes the source of a hidden label: **a genuine one-way predecessor carried by an independently hashed one-time signature chain**, rather than a public source hash or arbitrary accepted-bit label. We test whether that can produce one frozen capability from different evidence. This is a **deliberately narrow constructive screen**, not a claim that ChainLock equivocation is the approved fork predicate.

## Constructed hash-only predecessor-release primitive

Let an abstract WOTS-like chain have base w=16, \`len1=32\` message digits and \`len2=3\` checksum digits. For chain coordinate j let the 16-byte secret be \`sk_j\`, and define successive domain-separated forward hash steps \`F_(j,k)\`. For a valid message m with base-16 digit vector \`a(m)\`, the signature coordinate is

    Sig_j(m) = F_(j,a_j-1) o ... o F_(j,0) (sk_j),

where a_j=0 returns sk_j, and the public chain endpoint extends to step 15. Its checksum integer is \`c(m)=sum_(j<len1) (15-a_j)\`, represented by three big-endian base-16 digits.

Assume setup already knows an exact baseline valid signature on message m0 *and* possesses the corresponding signing secret. Write a_j=a_j(m0). For every j with a_j>0, setup knows one secret predecessor

    X_j = F_(j,a_j-2) o ... o F_(j,0)(sk_j)

(the identity for a_j=1). Publish a fixed frozen capability masked under each predecessor,

    C_j = S XOR H("WOTS-predecessor/KDF" || sid || j || X_j).

The honest public opening algorithm, given a distinct valid signature under the **same leaf**, computes b_j=a_j(m1), locates any coordinate j with b_j<a_j, moves its presented signature coordinate forward from step b_j to step a_j-1 to derive X_j, and XORs the corresponding KDF pad from C_j. Thus any such coordinate returns **the same setup-frozen S**; no unique second signature is required. The capsule has O(len) entries; this is not an exponential table.

### All-distinct-messages correctness lemma (for this restricted WOTS relation)

For any two different message digest vectors a,b, there exists some j (including the checksum coordinates) with b_j<a_j. Otherwise b_j>=a_j for all j. The distinct message digits then imply sum(b_message)>sum(a_message), hence c(b)<c(a). But componentwise b_checksum>=a_checksum would imply the represented nonnegative integer c(b)>=c(a), a contradiction. This uses the standard checksum digit relationship, not a source-history qualification rule.

Consequently, one valid second signature reveals an earlier hash-chain state unavailable by forward hashing from the baseline signature for at least one coordinate. Source evidence need not agree on which coordinate it reveals. **This is a real constructive property of this very narrow one-time-signature-reuse relation.** It does not establish full-public security, and the actual Core WOTS+ tweakable-hash implementation was not executed.

## Decisive ORIGINAL bridge and malicious-source failures

The approved ORIGINAL source relation accepts qualified competing Bitcoin histories, finite authenticated burn refutations, and qualified Syscoin inconsistency/tag faults at LC depth. **None of these three implies an equivocation under one preselected WOTS signing leaf.** Competing modern AuxPoW certificates can be valid without any ChainLock; two different Bitcoin parent certificates may support the same Syscoin child and are not themselves forks; two Syscoin branches do not necessarily contain two signatures from one selected sentry leaf. ChainLocks are optional in the approved bridge. This construction therefore FAILS every-witness ORIGINAL completeness.

More decisively, the WOTS signer can itself compute every X_j from its retained signing secret. Because the capsule entries are public, a malicious signer can recover S with no fork proof whatsoever. Even absent retained source coins, an otherwise correctly signed **unrelated second message** under that leaf unlocks C_j after local WOTS verification, before any authenticated BTC/Syscoin relevance check. The executed checker demonstrates this irrelevant-message opening. An external software \`VerifyOriginal\` check after release cannot repair it; the cryptographic gate is about WOTS equivocation, not qualified ORIGINAL history. An honest setup participant cannot exclude other source signers' retained private coins, and independent vault setup participants are not in general the actual chain's WOTS operators.

The \`n=16\` chain also does not establish 128-bit QPT preimage security: generic quantum search gives square-root asymptotics before accounting for multitarget/auxiliary effects. This is an additional limitation, not the decisive failure. Neither the many-ciphertext joint distribution \`{C_j}\` nor sibling/selected-opening/native-VK correlations were proved secure in QROM. No concrete native safe cancellation, actual Core source signature, post-PQ contextual AuxPoW or original certificate was built.

## Reproduced local computation and provenance

The executed standalone Python3 standard-library checker \`check.py\` implements an **abstract domain-separated SHA256-derived WOTS-like chain**, not the scheduled WOTS+ implementation in Core. It generated a baseline signature, public endpoints and the masked capsule. For 256 seeded distinct messages, each same-leaf second signature reconstructed the same 32-byte synthetic S; there were 8 distinct winning coordinates. It also signed a completely **unauthenticated unrelated statement** with the same key and recovered S. This is an explicit unsafe-source case, not a cryptographic proof. The checker was executed twice with byte-identical outputs.

Local checker SHA256: \`38a4087b39c4e0779f4a3a3bce3a3f3f5c14fea4ac3ce10b92b669eeef381990\`.
Both output SHA256: \`28334a5310109c72effe40080c0d0cced55ea2b3c74c80ee37f6ebaa21a808a3\`.
Expected git blobs from local bytes: checker \`a0f37b4f375e0ccaaa35b868a57c4b6630d0de52\`, output \`90d4fdc875773a7dbe936f86a3f28436d04ec27e\`.

## Status, exact next operation

**NONQUALIFYING.** This produces a hash-only fixed-capability release on WOTS same-leaf equivocation under a non-malicious signing-secret assumption, but NOT on any qualifying ORIGINAL Bitcoin/Syscoin certificate. It does not meet one-honest setup with arbitrary malicious source-coin retention, full-public FALSE/hard-TRUE QPT security, or all-witness completeness. Do not count it as a bridge advancement or add a progress comment.

The next legitimate construction must use an authenticated ORIGINAL certificate, not a signer-retained secret or synthetic OTS label, to execute a publicly serialized source-gated secret operation:

    C = Build_orig(x_W,S;r),       Open_orig(C,w) = S for every R_orig(x_W,w)=1,

with a joint-public unauthorized-recovery/forgery -> actual ORIGINAL-certificate (or independent hash/native break) reduction. The current WOTS predecessor technique offers no such reduction and must not replace the three OR challenge grounds. Do not promote this source-equivocation subset to an ORIGINAL solution.

Only research-path writes are authorized. No top-level progress comment, Core/production change, deployment, fund movement or automation change was performed.
