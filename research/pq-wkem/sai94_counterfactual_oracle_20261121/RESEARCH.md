# SAI94 — counterfactual-oracle source gate test (NONQUALIFYING)

## Live continuity

Opened current syscoin/PVUGC PR #1 at head 800c3aa2471e26c0a5e735c505878bf05c56c8f2, branch research/pq-wkem-validation-20260918. Read SAI93 exact note blob 64d11ba2daf035deb06bb5816dbfc27e7e4b7804 and its immediate predecessor SAI92 blob 7510cacbf69a858195fc46b64e01206ae76715c4. A targeted top-level comment query since 2026-11-18T19:24:42Z returned none. Core #609 PR metadata reported b3b4f643383a2149807a25fe38d26b5f058daa60; Core source and tests were not inspected or run. No original network witness or native signing was obtained.

SAI92 excluded unprotected public digest-only terminal decoding. SAI93 showed that punctured GGM labels and published accept-edge patches expose the frozen key before source verification; its exact next step is an authenticated public source-label transition. This iteration asks whether putting *full* source verification inside a public HASH-ORACLE-PARAMETRIC release evaluator, rather than using only a digest, closes that gap. We tested the compiler/public evaluation distributions jointly. Answer in the restricted oracle-relative model: no. This is a negative control, NOT a new practical source-release mechanism and not a blanket hash-only impossibility.

## Formal locally patched-oracle criterion

Let H be a public ideal hash oracle, x the frozen claim and authenticated source prefix, and R^H_x the finite source-evidence relation. Suppose classical-PPT public algorithms B^H(x,S;r) and O^H(C,w) have STRONG EVERY-ORACLE correctness:

    for every oracle G and every w with R^G_x(w)=1:
        Pr_r[ O^G(B^G(x,S;r),w)=S ] >= 1-eps.

Assume a polynomial-time counterfactual-extension algorithm can choose t fresh hash inputs u_j, replacement responses v_j, and syntactically self-consistent full source evidence w_cf such that H'=H[u_j -> v_j] makes R^{H'}_x(w_cf)=1. The same w_cf must NOT qualify for the real H; all preexisting claim, source anchors, native VK, and independently authenticated context are unchanged. This full-source extension is an explicit PREMISE, not an implementation for the approved ORIGINAL relation.

Let classical Build make at most q hash queries (including hash calls in correlated setup proofs, manifests and sibling capsules). Assume each patched u_j has conditional min-entropy >=kappa relative to that transcript. A union bound gives:

    Pr[any patched point queried by Build] <= q*t*2^(-kappa).

On the complementary event, with *the same* random setup coins, the entire generated public package C is byte-identical under H and H'. By the stated universal correctness:

    O^{H'}(B^H(x,S;r), w_cf) = S

except probability eps + q*t*2^(-kappa).

The public attacker can emulate O^{H'} locally, calling real H everywhere except the t known modified inputs. Thus this class of completely PUBLIC, locally interceptable, oracle-parametric evaluators has a classical signature-release attack without real source evidence. The attack does not solve SHA preimages, find a collision, forge real PoW, or require the setup secret, and classical success is sufficient to defeat QPT security. A coherent finite override is also locally implementable with equality tests and XOR differences when quantum oracle access is allowed.

CRITICAL SCOPE: The theorem does not apply to a fixed concrete SHA256d circuit whose SHA Boolean gates are embedded non-black-box INSIDE a protected encoding, to a source predicate requiring independent non-hash authentication which the counterfactual sampler cannot fabricate, or to arbitrary secure FE/iO. It assumes strong correctness even for adversarially altered oracles and a whole-source counterfactual witness. Correctness averaged only over uniformly sampled oracles does not automatically give this conclusion. The synthetic regression below does not instantiate full original source qualification; R170's earlier oracle-relative statements must retain their own scope.

## Bounded executed synthetic source regression

An actual Python3 standard-library checker was executed twice with byte-identical output. It constructs Bitcoin-style 80-byte parent headers, SHA256d parent work and coinbase Merkle commitments, exact 41-byte canonical OP_RETURN PUSH39 (sys || ancestor hash || uint32 height), a synthetic modern-ID-16 child history, a 5-level deterministic child merge-mining tree, and h_ref(n)=10*floor((n-6)/10). A baseline and an alternative agree through child 102 and diverge at 103; both extend to 116. The same source anchors/prefix through 102 are retained. Baseline parents are actually mined against the small, explicit synthetic target 0x2000ffff. The alternative uses 14 separately specified, LOCALLY PATCHED parent SHA256d outputs that meet that target. Each underlying actual SHA256d output for those parent headers fails the target. Child history, canonical tags and coinbase commitments are constructed consistently under the patched oracle. The synthetic total work is equal; no greater Syscoin-work predicate is imposed.

In the two runs: baseline passed the synthetic real-hash checks, alternative failed the real-hash checks but passed the locally patched version; tag hashes were equal at 111 (reference 100) and differed at 116 (reference 110); actual child ancestry diverged at 103. Ninety-six independent synthetic setup-oracle calls were unaffected by the fourteen patches. The executable explicitly checks extra strict-script and Merkle-root conditions, but DOES NOT run actual Syscoin Core contextual checks, bitcoin best-chain membership, a full original bridge relation, any FE Build/Open, native signatures or quantum tests.

LOCAL-ONLY complete derivation, checker and two captured outputs:
  /mnt/data/SAI94_oracle_surgery_20261121.tar.gz
  archive SHA256 a406dd683689b946639efe48a6e8ac8c1a307b413a7d682992c04e740e825fb9
  check.py SHA256 c4243b88e1e31861c771f99bedfb31f783a44fd0dcffa7793fa702d99edab630
  both outputs SHA256 8e9f33aaf3b015b8ca8fe55c0ea7e49d7a3a67086e7ad5a537213107902e2419

The source-check fixture alone is not a genuine original certificate or proof of a native-work bound. The complete local derivation explicitly records the strong-correctness, independent-authentication and min-entropy qualifications. No code fixture is claimed to be GitHub-published by this note.

## Attempted repair and exact next equation

Proposed repair: encode a **fixed SHA256d Boolean circuit** and the full ORIGINAL source verifier *inside* a protected program rather than use substitutable random-oracle queries. A source-code hash, external SHA wrapper, setup-correctness ZK proof, public validity bit, or exposed source label does not enforce that protection cryptographically. This pass produced NO practical public protected evaluator implementing this repair.

Needed next: a practical, serialized, classical-PPT NONRELATIVIZING compiler/evaluator

    (C, pi_setup) = Compile^SHA_fixed_R(x_W, sigma_cancel; rho)
    PublicEval(C,w) = sigma_cancel  for EVERY R_original(x_W,w)=1

whose fixed SHA gate consistency, common frozen safe authorization and entire public native VK/context/capsule distribution resist unauthorized recovery under arbitrary QPT processing, with a reduction to an ACTUAL qualifying ORIGINAL certificate or independently justified hash/native failure. Preserve separately usable Bitcoin greater-exact-work, withdrawal-specific finite burn fault, and qualified strict-post-PQ Syscoin history inconsistency/tag fault at required LC depth, with all original claim/anchor/window/replay/native-message binding. No further mask/digest/puncture parameter sweeps should be promoted until a *non-black-box protected release operation* is actually constructed.

**NONQUALIFYING.** No ORIGINAL foundation, independent QPT simulation or work-preserving FE theorem. No PR progress comment, user breakthrough notification, production write, merge or automation change.