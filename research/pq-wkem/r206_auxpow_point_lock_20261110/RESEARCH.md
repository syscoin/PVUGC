# R206 — precommitted point-hash lock against ORIGINAL authenticated AuxPoW challenge

**Scope:** one substantive hash-only Build/Open-shaped attempt and repair. The point-lock operation is real, but an actual ORIGINAL source-to-token algorithm is **not** instantiated. No reportable bridge breakthrough, QPT proof or deployment claim.

## Provenance and exact versions

Repo syscoin/PVUGC draft PR #1, branch research/pq-wkem-validation-20260918. Starting head f310e907b7f93ca06eed75440b0b75e2451bba2b, starting tree dd7279d8d3417f5e8a79f7524738861be1321ac9. Exact R205 note blob 91ac49b9ed9778df996bc4e120592a9552290813 and R204 static-slot checkpoint blob a3a9c21a92db26fc5d6c793e1d7effd7e0631dc1 were read, with no newer ordinary comments since 2026-11-10T15:00Z. The pinned relevant Syscoin code is syscoin/syscoin@1180dad257fb3cda797187f51ccc519b684e148d, already reviewed in prior runs; no new external research or source-repo modification. Genuine intermediate local checkpoint was written before tests. The full local derivation, source and run is additionally preserved in an archive; the GitHub checker and captured output below are its executable experiment.

Exact locally executed checker: SHA256 57f1bc6d618551f7bf79afa08b1578bb60224c7954d15666caf8c3b86313eab0; captured and byte-identical rerun SHA256 27bb1ebb322cfbbc2b5742f190cd2ecfd996d1c80cfcbeca42155fc9b185ee38. 128 deterministic seeds, 1536 functional assertions. The inputs are deliberately synthetic; no actual BTC/SYS header prover, native signature or QPT experiment ran. No independent subagent, web or lattice.

## Exact ORIGINAL task

One notary may activate a withdrawal in the existing N-of-N preauthorized graph; any watcher must open the SAME precommitted claim-scoped native cancellation signature from ONE qualifying source challenge. The bounded ORIGINAL disjunction includes R1: contradictory higher cumulative-work Bitcoin history, R2: authenticated absence/invalidity of this withdrawal's PoB, R3: qualified claim-prefix Syscoin fork or explicitly admitted authenticated AuxPoW tag fault. Source anchors/window, real SHA header/coinbase/Merkle/ancestor/height checks and withdrawal context must be bound in x_slot and/or the authenticated future SegWit activation. Bitcoin receives an ordinary native cancel signature, not the verifier/trace. Generic NP is not a prerequisite, but a source-specific relation cannot be silently replaced with point preimage evidence.

## Candidate PointLock

Classical-PPT Build samples uniform n-bit private preimage s, fixes native cancel capability sigma and context x, and computes:

    t = H0(x,s)
    D = sigma XOR H1(x,s)
    CK = H_check(x,sigma)
    C = (x,t,D,CK,nativeVK)

PublicOpen(C,z) checks H0(x,z)=t, derives sigma'=D XOR H1(x,z), checks CK and native VK/message, then returns sigma'. For z=s the algebra is exact: Open returns the SAME sigma. H0/H1/check domains must be separate: D=sigma XOR t would expose sigma to anyone immediately. This is a real hash-based *point preimage* release, not a bridge WKEM; the hypothetical source extractor ExtractOriginal(C,w)=s is precisely what needs constructing.

The hash idealization would require a QROM game with coherent queries, arbitrary QPT/nonuniform advice, the actual native VK/CK correlations, malicious setup and sibling capsules. No such full-public QPT theorem is claimed here. SHA256 domain separation by itself does not establish it.

## Actual source-timing cases and repairs

1. Fixed baseline ancestor/tag or claim-prefix PureChildHash: if s=H(known public baseline history), every observer computes s BEFORE a fork, opening C without ORIGINAL evidence. Different parent work proofs of the same child do not change that value, but stability is not secrecy.
2. Future contradictory source child, complete header, SHA internal compression state or parent certificate: Build freezes t,D before that unknown future source data. If Build guessed one future qualified F1, another equally qualified F2 yields s2 != s1 and fails the same fixed point. Both forks can be valid witnesses, so every-witness completeness fails. A SHA midstate based only on fixed public prefix reverts to case 1.
3. Pair-dependent hash H(baseline||alternate) or last-common-ancestor hash: alternative F2 produces another candidate; forcing a fixed earlier ancestor makes it publicly known. Differing source tags are NOT two secret openings of a shared committed preimage.
4. Setup-selected random s: independent existing AuxPoW coinbases, header hashes and tags do not contain that s, so no permissionless ExtractOriginal. Requiring a miner/notary to reveal s later adds a new source issuer/capability not in the ORIGINAL evidence; a dishonest party who chooses and retains s may open early. A fixed source commitment alone authenticates bytes, not disclosure conditional on a fault.

For direct source-parsing extractors E(x,w) independent of setup s, when s is uniform n-bit and an independently sampled future witness is not correlated with s, Pr_s[E(x,w)=s] = 2^-n for fixed w. This elementary statement applies only to that *direct token family*, not to any arbitrary nonblackbox SHA circuit. If E reads public t=H0(s), obtaining s without additional correlation is itself the point-preimage task; an uninstantiated issuer must not be assumed.

Under an ideal random-oracle PoW abstraction, two qualified headers usually have DIFFERENT hash outputs below the target. A public deterministic normalization constant over all successes (e.g. required leading zero bits) is already publicly known, while the unconstrained trailing bits vary. Thus ordinary PoW has no obvious COMMON HIDDEN entropy usable as a precommitted s for every fork. This does NOT prove all SHA-based WE impossible; a secret-output nonblackbox encoding is a distinct challenge.

Concrete attempted repair: choose a unique source semantic prefix U_claim rather than full header/parent work certificate. This fixes parent-certificate invariance but is public early; use a future contradictory U_claim and its value changes with different qualified witnesses. Attempting to hash an unknown setup nonce into the release source supplies no certified route for actual original evidence to reveal it. Enumerating all 256-bit future headers violates PPT Build.

## Executed bounded check and actual limits

The published checker exercises source-independent point correctness, publicly computable baseline/prefix early opening, same-child distinct-parent certificates not qualifying, failure of a precommitted F1 point on F2 and pair-specific fork evidence, an independent setup nonce that future genuine source does not deliver, a dishonest source that retains its nonce, and immediate disclosure if t itself is reused as the pad. There are 128 seeds and 1536 exact functional assertions, with captured byte-identical output. These are not mined chain data and cannot establish QPT security, provenance extraction or native signature validity.

The exact missing equation is:

    Build_hash(R_original,x_slot,sigma_cancel) -> C [classical PPT]
    Open_hash(C,w) = SAME sigma_cancel for every R_original(x_slot,w)=1
    arbitrary QPT recovery/accepted native forgery
       -> ACTUAL ORIGINAL qualifying evidence or independent PQ hash/native break.

A constructive successor must use SHA/AuxPoW circuitry or another genuinely instantiated source binding to protect a global input assignment without source-retained label pairs, public occurrence mixing, unknown future point-specific garbling or an online issuer. Neither the point-lock nor its functional tests are a completed ORIGINAL bridge release. No optimization, source-repo write, normal PR progress comment or end-of-task claim is justified.
