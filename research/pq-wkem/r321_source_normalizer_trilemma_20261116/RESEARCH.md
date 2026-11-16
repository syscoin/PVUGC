# R321 — source-normalizer trilemma across qualified-looking AuxPoW rerandomizations (NONQUALIFYING)

**Verdict:** no ORIGINAL-source hash-only witness-KEM, actual encrypted native cancellation signature, full-public QPT reduction, deployment or Core test. This is a finite-class exclusion of the scalar-public-SHA-normalizer repair considered after R319/R320; **not** a general impossibility statement for nonlinear WE or concrete SHA.

## Starting evidence / scope

PVUGC #1 was open/draft on research/pq-wkem-validation-20260918 at 71d5928e0db2350d3364f8c6f3b60bcdb8b73d0f, R320 note blob a15cefa391669c224a077f8530214ffd33347a82. Read R319 (source-coinbase SHA pad, parent 4d7cc5b0); bundled local R316 checker sha256 921ea00fbd951c0385f60e3660b9622b1e0152b2de567b8dc6769f2f8d8c31ab. Core PR #609 metadata read-only: c91539de3c34937e57d7f5fda47c7b0502ff33f6, release-disabled. Core tests were **not** executed. R225 PR comment 6796383617 on activation-wtxid/native signature portability remains unresolved and separate.

Relation remains ORIGINAL OR of (1) qualified same-anchor *strictly greater exact* cumulative BTC work, (2) finite authenticated specific burn/authorization fault, (3) qualified **actual semantic ancestor** Syscoin inconsistency at LC depth or independently authenticated claim-wrapper tag fault with explicit maturity. Preserve activated contextual modern AuxPoW chain ID, canonical exact 41-byte parent SYS OP_RETURN, distinct indexed child commitment, relevant actual ancestor paths and all required interval tags; the reference schedule h_ref(n)=10 floor((n-6)/10) is not LC depth. Distinct Bitcoin parent certificates of one Syscoin child do not themselves create a fork. x_W must also bind protocol/chain, claim/outpoint, assertion/burn/amount/recipient, baseline, BTC anchors/window, relevant child height, deadline/reset, exact safe cancel message/VK and capsule ID.

## Explicit proposed scalar SHA compiler (REJECTED)

For publicly computable source-certificate features f_i(x,w), consider all coordinate subsets I and

    K_I(x,w) = SHA256("PVUGC/R321/scalar-normalizer/v1"
                       || concat_{i in I}(uint32(i)||uint32(len(f_i))||f_i(x,w))).
    Build_I(x,S,w0) = C := S XOR K_I(x,w0).
    Open_raw(C,w) = C XOR K_I(x,w).

The builder is deliberately and *illegitimately favored*: w0 is a future qualifying witness it cannot normally possess at honest preauthorization. An optional source check after Open_raw is **not** part of cryptographic source-release and does not undo extracted S. The intended safe S is one frozen claim-scoped native capability; tests use only a synthetic 256-bit secret, **not** a native signature.

Four separate synthetic R316-derived challenger histories share anchored child 100, heights 101-102 and exact canonical tag bytes, diverge in actual child ancestor at h_rel=103 from fixed baseline, and reach child 111 for 8-link LC depth. All model modern chain ID, 5-deep deterministic indexed child commitment and separately Merkle-bound parent carrier with synthetic easy target 0x207fffff. Variants: A normal; same A child with parent header nonce/time rerolled at 103 and parent descendants re-linked; same A child with coinbase extraNonce rerolled at 103 and parent descendants re-linked; different semantic challenger B fork beginning at 103. Tags reference height 90 or 100 and remain **identical** in all four; no greater-BTC-work claim is being made. Authenticity is *only synthetic*; no real Bitcoin best chain, full retarget, source membership, live Syscoin admission, ChainLocks, DA, or native PQ signing.

Fourteen f_i coordinates:
  - Fixed **public x_W/baseline**: claim ID, child anchor hash 100, expected canonical tags at child heights 103/111, relevance height 103, modern child chain ID.
  - Future source-dependent: child hashes at 103/111, coinbase txid 103, parent header SHA256d 103, full parent-history digest, baseline/challenger actual-ancestor pair digest, parent Merkle root 103, full coinbase-history digest.

## Exact restricted finite-class lemma with full-public extraction

For each fixed I, RawOpen(C,w_j)=S iff K_I(x,w_j)=K_I(x,w0). This is exact XOR algebra, with no security assumption. The executed enumeration of all 2^14 = 16,384 coordinate subsets found:
  - 64 invariant subsets (precisely I contained in the first six public coordinates). All valid synthetic w_j open S, **but** a classical attacker without an ORIGINAL witness calculates K_I from public x_W and recovers S=C XOR K_I. This breaks complete-public FALSE/hard-TRUE concealment for any similarly instantiated public-invariant pad; QPT security cannot hold if classical recovery succeeds.
  - 16,320 subsets with future-dependent coordinates. At least one of the four qualified-looking challenger alternatives produces K_I(x,w_j) different from K_I(x,w0), so even the favored Build_I fails SAME-frozen-secret every-witness correctness.
  - Zero accidental SHA256 collisions between different selected feature tuples in this *finite fixture*.

This is an **exhaustive enumerated result only for this explicit coordinate-concatenation scalar-normalizer family and these four synthetic certificates**. It does not exclude nonlinear hidden invariants, QROM constructions, general public obfuscation, or independently useful branch-specific cryptography. A publicly computable nonlinear invariant still needs a preauthorization-time secret-correlation mechanism and must defeat full-public recovery, not just an ordinary post-hoc validity test.

**Joint public simulation for invariant cases:** A receives the complete (x_W,C,VK,aux,setup,sibling) transcript and computes the same public coordinates without querying any source witness; A outputs C XOR K_I(x,public_fields). No extraction/log/reprogramming or native forgery assumption. The noninvariant cases already fail correctness. There is no FULL-QPT simulator/reduction for the ORIGINAL task, malicious setup or multi-capsule; this direct attack only resolves the restricted scalar cases.

## Executed reproducibility and exact missing equation

Executed Python3 stdlib: two independent "python3 checker.py" runs (with bundled R316 dependency), byte-identical JSON, **33,067 synthetic assertions per run**; 16,384 subsets, 64 public-recoverable invariant cases, 16,320 correctness failures, zero accidental hash collisions. Checker SHA256 e6a3d98ac60125b20f7e29c93050cc93495bed77785a9f661c7686f7e2ae02d2; output SHA256 3f3949157faad1b8e21c69cd83814979372d81e6d90613a662a7e1c9dd51e128. Full derivation, executable checker, bundled synthetic source checker, paired JSON and provenance are **LOCAL ONLY** in R321_source_normalizer_trilemma_20261116.tar.gz, archive SHA256 76e6d9541900ba12733c7a219ccd2e1c4fe0756a36612f27b0aa99666d214997. Only this note is committed to PVUGC; do not treat tests as real Core admission.

Unfinished crypto obligation (not solved or reduced by the failed scalar family):

    Classical-PPT Build_inc(x_W,S;rho)->C, before any unknown future witness.
    For EVERY qualifying ORIGINAL w: Open_inc(C,w)=the SAME frozen safe S.
    Full-public QPT recover/accepted native forgery ->
       ACTUAL authenticated ORIGINAL certificate or independent PQ hash/native break.

Next construction must enforce nonspliceable authenticated full SHA/AuxPoW preimages and claim/depth/semantic-history correlations **inside a hidden source-release path**, not via a public scalar normalizer or post-release verifier. It must cover independent BTC/burn branches, arbitrary witnesses, malicious retained source coins, native endpoint portability and selected sibling openings. No source-dependent secret-bearing public Build/Open was produced. **No positive ORIGINAL foundation progress claimed; no PR progress comment, production change, deployment or automation-disable.**
