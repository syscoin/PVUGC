# R299 — Nonlinear shared-SHA pad meets exact parent-provenance source fibers (NONQUALIFYING)

## Continuity and source scope

Continuing R298 at PVUGC PR #1 head 9176be2d8c8919e976b919bef59f32e26b0e8ede on research/pq-wkem-validation-20260918 (open draft), before this checkpoint. The precise attempted repair is non-linear secret-key SHA rather than R298's easily interpolated affine features, while preserving an EXACT common frozen cancellation capability under many future ORIGINAL witnesses. Core PR #609 was metadata-read only at c91539de3c34937e57d7f5fda47c7b0502ff33f6; public activation/finality remains sentinel/release-disabled. This experiment reuses R286/R287 SYNTHETIC SHA256d parent/coinbase and depth-five AuxPoW fixtures, not real BTC best-chain membership, Core tests, Syscoin LC depth, or a native SLH signature. No new ordinary PR comments in the date-scoped read after November 14. R225 issue comment 6796383617 remains an independent native-signature activation problem.

The ORIGINAL bridge still requires ANY watcher with one qualifying certificate for the three OR grounds: (1) relevant competing BTC history with strictly greater EXACT cumulative work; (2) finite authenticated defect of THIS withdrawal's burn/authorization; (3) qualified SYS claim-relative inconsistency or independently authenticated exact-parent tag fault at required LC depth, without greater SYS work. Full x_W binds source and chain identity, exact claim/UTXO/withdrawal/burn/amount/recipient, baseline and actual semantic ancestor at h_rel, BTC anchors/window, modern contextual AuxPoW chain ID and canonical exact 41-byte parent tag, separately committed child-merkle root and parent coinbase, interval continuity, deadlines/reset, capsule and native safe-cancel message/VK. Distinct Bitcoin parent certificates for the SAME immutable Syscoin child do not make a fork. N-of-N preauthorizes; one notary initiates. This test does not implement these original predicates.

## Concrete correction attempt and issuer gap

Freeze a 256-bit cancellation surrogate S. Let s_0 uniform and s_1 = S XOR s_0. Let k be a secret 256-bit HMAC-SHA256 key; let t = pi_x(w) denote a certificate fingerprint, F_k(t)=HMAC_SHA256(k, domain || x || t), and d(t)=SHA256(public-domain || x || t) be public. Proposed local outputs are:

    T_0(w) = s_0 XOR F_k(pi_x(w)),                      if C_0(x,w)
    T_1(w) = s_1 XOR F_k(pi_x(w)) XOR d(pi_x(w)),       if C_1(x,w)
    D(t)   = d(t),                                     fully public
    Open(C,w) = T_0(w) XOR T_1(w) XOR D(pi_x(w)).

For every SAME w satisfying both local conditions, Open is exactly S, independently of the value of w. This gives a polynomial PRIVATE seed/share description and genuine nonlinear SHA evaluation, not polynomial public Build/Open. The test calls the local outputs as *ideal private restricted issuers* solely to evaluate whether proposed public delegated-key designs are secure. There is NO implemented source-dependent public T_i issuer, no hard-TRUE security theorem and no claim of a hash-only ORIGINAL WKEM.

## Exact source-fiber mixing lemma

If distinct locally accepted full witnesses w_0,w_1 have equal projection pi_x(w_0)=pi_x(w_1)=t but NO common satisfying witness exists, then straight-line computation gives

    T_0(w_0) XOR T_1(w_1) XOR D(t)
      = (s_0 XOR F_k(t)) XOR (s_1 XOR F_k(t) XOR d(t)) XOR d(t)
      = S.

This is an unconditional classical FALSE recovery even if each issuer PERFECTLY protects its own k and s_i and enforces its respective local predicate. No secret representation, hash inversion, nonlinear interpolation, label-state splice, witness the adversary must volunteer, or QPT rewinding is required. It is restricted to this projected shared-mask issuer architecture; not an impossibility theorem for all WE/obfuscation or concrete SHA. An after-the-fact source verifier does not retract S.

## Exact parent/child source-shaped regression

A fully constructed synthetic Bitcoin-style parent/coinbase and depth-five modern-ID merge-mine fixture gives one valid EXACT 41-byte SYS-tag wrapper and two separately mined malformed-tag wrappers. All three have the same immutable Syscoin child hash; each has a DIFFERENT SHA256d Bitcoin parent hash. C_0 locally accepts the canonical good wrapper, C_1 locally accepts an independently SHA256d-committed malformed outer wrapper. Neither malformed parent equals the claim's GOOD pinned parent; there is NO claim-qualified ORIGINAL tag fault in the fixture. Projecting both into child_hash yields the SAME t and reveals S TWICE, once per malformed wrapper.

Replacing pi=child_hash with pi_full=SHA256(domain || unambiguously serialized FULL wrapper, claim, child, chain ID, height, parent and coinbase) differentiates these source carriers, and both mixed FALSE openings fail in executed tests. For TWO separate good-parent fixtures, each full SAME-witness synthetic TRUE control still opens exactly the SAME S when both ideal issuers operate on that entire single witness. Under an independent uniform-function idealization, two different t values have accidental cross-mask equality with probability 2^-256. The concrete SHA/HMAC code only measures inequality, not HMAC PRF security or a QPT bound. A real pi_full must also bind the complete ORIGINAL ancestry/source/witness scope; this fixture is deliberately narrower.

## Attempted public repair fails at token issuance

The exact-full-witness fingerprint fixes only this mixing regression. A secret k stops real public Open from issuing future unknown-witness T_i values. Publishing k enables ONE locally accepted token from each disjoint class to yield s_0 and s_1 separately, so S is recovered on FALSE even when pi_full differs; executed checker confirms this. An independently keyed pair of HMAC functions has no generally PUBLIC d(t) making both terms cancel for all future w; two independent-key controls do not converge. Ordinary GGM-prefix delegation on a parent digest or Syscoin child hash is insufficient source authentication: it permits outputs for digest strings with no ORIGINAL authenticated source preimage, and projections omit full relevant parent/claim context. A public compiler for hidden nonlinear dynamic functions conditional on full source R cannot be postulated as SourceOpen, iO, a source signer, secret retained coin or QROM programming.

The exact unfinished equations are a classical-PPT fully PUBLIC Build_inc(x_W,S) and Open_inc(C,w) that issue (only INSIDE the cryptographic release) T_i for each ORIGINAL locally authenticated common w, enforce same full-witness consistency across all constraints, and satisfy XOR_i F_i(full(x_W,w)) = public D(C,x_W,w) without revealing the hidden seeds or permitting maliciously mixed proofs. Independent FALSE and hard-TRUE QPT joint-public extraction to an ACTUAL original certificate (or a separate PQ hash/native break), multi-capsule/sibling/selective-opening and malicious-setup security, and native claim/slot isolation are UNPROVED. Do not treat a full fingerprint as a cryptographic source credential. This is a REJECTED candidate, not progress toward a completed WKEM.

## Exact local execution provenance

Two byte-identical Python 3 executions of the provided LOCAL archive's checker.py and inherited r286_checker.py used SHA256d on synthetic 80-byte parent headers and full coinbases, modern ID fixture, deterministic merge tree depth 5, exact 41-byte tag and h_ref lag 6. Checks covered four distinct parent hashes for the same child, two FALSE cross-wrapper secret recoveries with child projection, two rejected cross-wrapper recoveries with full wrapper projection, two distinct correct same-S synthetic TRUE controls, public-key share recovery and two independent-HMAC correction mismatches. Test target 0x207fffff yields toy work 2, NOT real network security. No real chain consensus, BTC best-chain proof, Syscoin LC depth, native PQ endpoint, quantum oracle test or production deployment was run.

checker.py SHA256 87504674d1ddc2ba3e060cea251d7cfaf5498c2fd064a8eee37c221b54352f62
r286_checker.py SHA256 5baf9ff907fc48795d88c03d728124e089ed385188e6ac4db0a424cac83877ec
run1.json/run2.json SHA256 c5c1b8357575d370cc79c7015491e2e1423cdbf54802431b97637a6a28c6bacc
LOCAL full archive R299_source_fiber_mask_20261115.tar.gz SHA256 567a4585d2a0c161755ca7b4e287b8a00768f2139c8a6492372baa215e11ff9f, not a committed Git blob.

Only this research note is intended for PR #1; full executable bytes and outputs remain local unless separately published and verified. No PR comment, notification, release, production change, or automation-stop follows.
