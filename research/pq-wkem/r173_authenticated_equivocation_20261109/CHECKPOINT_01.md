# R173 checkpoint 01 — source-authenticated dual-opening hash carrier (intermediate)

**Research-only, no generic WKEM or deployment claim.** Starting syscoin/PVUGC PR #1 branch research/pq-wkem-validation-20260918 at verified head a66979b8d1b730d1981ef67ba2101e502691efe3 (open/draft/unmerged). The preceding R172 bound was read at exact blob b78d3a4c491592f7c24cb4febc87a97a984d9516. Ordinary PR comments since 2026-11-09T00:00Z were empty. No web/external literature, lattice/group, or independent subagent.

## Hypothesis
A naturally authentic source *equivocation* could supply both halves of a committed hash label pair and trigger the SAME precommitted native signature without enumerating all source witnesses. Distinguish semantic Syscoin child *OutcomeID* from the complete BTC parent AuxPoW *WorkID*: two parent-work solutions on the same child are not contradictory source outcomes.

Let every eligible semantic outcome ID have an injective length-L bit encoding e. Independently sample secret labels s_{i,0},s_{i,1} and a random 256-bit K. Publish one-time hash-signature verification tags V_{i,b}=H_ver(ctx,i,b,s_{i,b}) and rows
    E_i = K XOR H_pair(ctx,i,s_{i,0},s_{i,1})
for all i. Also publish CK=H_check(ctx,K), D_sig=sigma XOR H_sigpad(ctx,K), native VK, claim/path, source anchor/window, signature-context identity. To sign outcome o, a source signer releases s_{i,e(o)_i} for each i. Given two valid signed incompatible outcome IDs o != o', there is a differing i; the two labels reconstruct the same K via E_i, then D_sig unveils the frozen sigma. Thus all different genuine signed outcome pairs release precisely the SAME precommitted capability; semantic same-outcome parent-work variants do not.

The release is *intrinsic to cryptographic source signatures*, unlike a post-hoc R(x,w) check. But it is only a special-equivocation trigger, not a generic arbitrary-NP Build/Open.

## Critical adversarial countercase to investigate
A dishonest source signer initially KNOWS s_{i,0} and s_{i,1} and can derive K from any E_i **before signing anything**, before any source event, and without presenting ORIGINAL evidence. Honest N-of-N funding erasure cannot constrain a separate source signer who retained labels. Sharing the labels among signers may withhold K if one is honest, but then a source fork requires that honest participant to release both labels; this is an online release committee/authority and outside the requested system.

The next pass within this execution is to test complete two-outcome correctness, same-child dual WorkID non-release, forged-signature rejection, and retained-source-key early opening. Check whether a repair avoids both early knowledge and online involvement, and separately whether ordinary native ChainLocks/AuxPoW supply these special hash signatures (they do not by assumption). Do not count the special-signature relation as ORIGINAL completion. The full-public QPT simulator and generic polynomial Build/Open remain open.
