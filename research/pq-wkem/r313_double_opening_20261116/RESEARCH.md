# R313 — Hash-only double-opening escrow: constructive signed-equivocation component, NOT ORIGINAL release

Start: open draft syscoin/PVUGC #1, branch `research/pq-wkem-validation-20260918`, head `5142b35a5fac922233fd2b3f7222f95c8047f95d`, R312 blob `234a8f291f880ba58892d8ba7ef25f8dbd90a5ed`. Last relevant substantive PR comment R225 #6796383617. Core #609 current read-only metadata head `c91539de3c34937e57d7f5fda47c7b0502ff33f6`; no Core code test was run. Research-only; no deployment or production change.

## Construction actually attempted

In contrast to R312's private function `F(w)=S+alpha*Z_orig(w)` with no public encoder, test whether **cryptographic double openings supplied directly by a future source** can release the same frozen capability. Define full immutable claim/capsule context `ctx`, 256-bit independent content key K, fixed safe native cancellation authorization sigma, and 256 independent pairs of 256-bit preimages `a[i,0],a[i,1]`:

```
PK[i,b] = SHA256(domain_pub || ctx || i || b || a[i,b])
CT[i]   = K XOR SHA256(domain_pad || ctx || i || a[i,0] || a[i,1])
W       = sigma XOR SHAKE256(domain_wrap || ctx || K)[0:len(sigma)]
C       = (ctx, PK, CT, W, native message/VK/capsule metadata)
```

A Lamport-style OTS signature on m reveals exactly `a[i, bit_i(SHA256(domain_message||ctx||m))]` at each i. Two **valid** signatures on distinct message digests under this same OTS public key disclose both a[i,0] and a[i,1] at at least one differing bit i, yielding exactly `K=CT[i] XOR SHA256(domain_pad||ctx||i||a[i,0]||a[i,1])`. All such pairs recover the SAME frozen K and sigma independent of the differing index. No future-message enumeration in Build. This is a concrete hash-only full-public algorithm for the *augmented two-authentic-signatures* relation, not a witness-KEM for Bitcoin PoW.

For the synthetic one-signature security game, every i retains one independent unknown preimage. In an ideal random oracle, each corresponding pad is unpredictable to a classical polynomial adversary not finding a hidden preimage. Quantum coherent search, commitment conditioning and joint siblings need an independently rigorous hidden-point QROM reduction; no complete QPT theorem or concrete SHA security theorem is claimed. Real native signature encryption requires standard authenticated wrapping rather than the synthetic XOR fixture.

## Required ORIGINAL mapping failed — decisive checks

The approved ORIGINAL source relation is the OR of (1) relevant same-anchor BTC history of **strictly greater exact cumulative work**, (2) finite authenticated refutation/nonmembership/complete bounded execution of the specific withdrawal burn, (3) qualifying actual-height Syscoin ancestor conflict at required LC depth or separately authenticated claim-wrapper tag fault under adopted maturity. It is not a double-OTS-signature relation. Preserve modern **contextual** child chain ID, exact 41-byte applicable SYS parent-coinbase tag, independently authenticated BTC carrier, separate AuxPoW child commitment, real h_rel ancestor, source anchors/windows, bound claim/outpoint/amount/recipient/capsule/native message, no unsupported best-chain membership claims and R225 native witness-portability limitation. Valid distinct BTC parents for the same child do not constitute a fork.

A valid ORIGINAL BTC/SYS conflict produces different authenticated hashes/coinbases/headers; it does NOT automatically reveal `a[i,0],a[i,1]` under a shared preauthorized Lamport key. Treating an arbitrary future parent header as `a[i,1]` fails: for two distinct valid future headers h0,h1, independent RO values of H(a0||h0) and H(a0||h1) agree with probability 2^-256, so one fixed CT[i] cannot decrypt the SAME K for both. Binding CT[i] to a future certificate hash prevents other authentic alternative witnesses from opening.

The party retaining the full Lamport private key immediately computes K directly from CT[i], even if ORIGINAL is FALSE. It can also sign two entirely fabricated messages and open the encrypted sigma. An outer `CheckSource` after decryption cannot retract the leaked signature. Destroying those private keys at setup prevents future OTS signing and destroys every-witness completeness. Introducing an online source signer / signer oracle changes the problem and is forbidden. An honest N-of-N preauthorization erasure does not convert future original PoW history into the missing secret OTS labels.

## Executed checks and exact provenance

Python3 stdlib deterministic fixture: 256 Lamport positions, 96-byte synthetic signature surrogate, SHA256 commitments/pads and SHAKE256 wrapper. 64 distinct synthetic message pairs, each independently checked for same K and sigma; altered labels fail; duplicate message fails; changed context rejects; retained-key holder recovers K with no source; fabricated pair also recovers. Two executed final checker runs byte-identical, **197 assertions per run**. No authentic BTC header, AuxPoW admission, proof-of-burn, native SLH signature, QPT experiment or N-of-N adversarial ceremony was tested.

Checker SHA256 `f4b3ead81600990344af638afbb835ac5cfd15b50799f833f0bdfe95e3d45a06`; both output SHA256 `fa483e6abfba0ceee169a6c87828bd86aee7e2f646442191e4544064244191a4`. Full local derivation/checker/two outputs/provenance: `R313_double_opening_20261116.tar.gz`, SHA256 `57a0f544a4746a971e24156d628cec8dc850d681494e2566e069d013f78a8e15` (local archive, NOT committed). RESEARCH.md in local archive SHA256 `47e9e4ed974e8eb538d7aaa3dc1b07568db6c9b124453027eae86b649a5e6f7a`.

## Exact unfinished equation

**NONQUALIFYING ORIGINAL.** Signed-equivocation opening is a working restricted cryptographic component but has no provenance in the three approved source challenge branches. Neither TRUE/FALSE security nor native forgery security has been established for ORIGINAL. The remaining actual construction is classical-PPT `Build_orig(x_W,sigma_cancel)->C` and public `Open_orig(C,w_original)=sigma_cancel` for EVERY qualifying ORIGINAL authenticated witness with no other disclosure, including malicious setup and full joint-public QPT security. The missing piece is a *source-derived secret-bearing correlation* available on every ORIGINAL certificate without an online signer, or a genuinely nonspliceable public source-conditioned encoder independent of such correlation. A later hash verifier or proof alone is not that piece. No progress PR comment, notification, production change or automation stop warranted.
