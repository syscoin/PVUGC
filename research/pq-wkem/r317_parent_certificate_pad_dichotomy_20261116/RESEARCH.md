# R317 — Source parent-certificate re-randomization vs common hash-only cancellation pad

**NONQUALIFYING.** One bounded offline continuation of R316's exact authenticated-source-regression step. No classical-PPT ORIGINAL-source witness-KEM Build/Open, complete full-public QPT simulator, native PQ signature scheme, or endpoint closure. This is a narrow, explicit source-crypto interface test, **not** a general hash-only WE impossibility theorem.

## Verified starting point and limitations

PVUGC PR #1 is open/draft on `research/pq-wkem-validation-20260918`, starting SHA `d29cee653165713f58b63263237f8e17bab5a5a2`. Read R315's source-OTS note (blob `385f653c0579dca00ba812b08558d78a9381d2cb`), R316's source regression (blob `00e4d7e2244bf9dae4fa004ec0ee875215f27e4c`) and the separate R225 native activation-portability comment. Read-only Core #609 metadata showed head `c91539de3c34937e57d7f5fda47c7b0502ff33f6` and **draft/sentinel release-disabled** status; no new Core files or tests were read/run in R317. The synthetic verifier is the byte-for-byte archived R316 checker SHA256 `921ea00fbd951c0385f60e3660b9622b1e0152b2de567b8dc6769f2f8d8c31ab`; it is **not** full source consensus/network admission.

Maintain the complete claim-scoped ORIGINAL OR: independently qualified exact greater-BTC-work source history; finite authenticated fault in the particular asserted burn; or relevant actual Syscoin child-ancestor conflict at required LC depth / exact asserted-wrapper tag fault with independently authenticated outer Bitcoin carrier and explicit maturity rule. Activated modern contextual AuxPoW IDs and **exact** 41-byte SYS tags with a *separate* correctly indexed child Merkle commitment apply; nonzero depth five is valid. Same child under different valid Bitcoin parent certificates is NOT a Syscoin fork. The usual amount/recipient/claim/UTXO/anchor/window/deadline/reset/native-message/VK/capsule bindings remain; no label invented here substitutes for authenticated source work.

## New candidate and source-specific completeness test

Try using actual future Bitcoin parent-certificate entropy as an honest source-earned pad:

```
k_B = SHA256("R317|parent-pad" || x_W || SHA256d(parent80_B))
C_B = sigma_cancel XOR k_B0
Open_B(C_B,B) = C_B XOR k_B
```

We **generously grant Build** one known future parent certificate `B0`, which the actual late-claim setup generally lacks. R316 permits many authentic *different* parent wrappers for one identical contextually admitted child (one child per **parent**, not one parent per **child**). Different `B1` has a different 80-byte header hash; under ideal independent SHA outputs, `Pr[k_B0 = k_B1]=2^-256`. Consequently a fixed ciphertext opens on its chosen parent but, except with hash collision, **not on all other admitted source representations** of that same child. That is an EVERY-witness correctness failure, even before hard-TRUE QPT security.

**Executed synthetic fixture:** Hold child header at height 111, parent predecessor, non-SegWit coinbase, exact SYS ancestor tag referencing height 100, five-level child Merkle tree/index/nonce constant. Generate 64 *distinct* easy-work `0x207fffff` parent headers by varying timestamp by 11 seconds and mining a fresh valid nonce. All 64 pass R316's local SHA256d Bitcoin parent work, coinbase inclusion, modern AuxPoW chain-root and canonical tag subchecks; the child hash, tag, and child root are identical. A synthetic frozen 256-bit signature pad encrypted under parent 0 opens correctly ONLY there, failing for all other 63 SHA parent values. These are **synthetic locally accepted parent certificates**, not 64 independently proven real-world ORIGINAL-qualified histories: no full retarget/source-anchor/window/best-chain/LC verification is claimed. The formal conditional statement concerns any *two* genuinely source-qualified distinct parents for the same allowed semantic evidence.

## Repair A: semantic fingerprint normalizer

Try `k_sem = SHA256("R317|semantic-pad" || x_W || F(x_W,w))`, with `F` dropping the variable parent and keeping the claim, baseline, same child or ancestor identity.

* If `F` is already known from the public instance when Build can produce `sigma XOR k_sem`, anyone computes `k_sem` and recovers `sigma` on FALSE **without a witness**. The checker performs exactly this direct classical recovery.
* If `F` depends on an unknown future challenge history, Build cannot form the ciphertext from `(x_W,sigma)` without a genuinely specified noninteractive encoding of that future unknown value. Requiring future setup updates, retained source keys or an online signer is outside the target.
* Inferring a "first/minimum" future admissible parent is not a finite authenticated qualification: it demands excluding unseen histories, disallowed by the ORIGINAL relation.

This is a dichotomy for this explicitly stated simple pad, **not** a disproof of unknown-source witness encryption.

## Repair B: low-degree public field polynomial

Let `t_i = SHA256d(parent_i) mod p`, `p=2^255-19`. Suppose a literal publicly represented field polynomial `P(t)` of degree `d` must equal the SAME `K` at all accepted parent digests. If `d+1` source-qualified digests are distinct, `P-K` has too many roots, hence `P ≡ K`, and its public constant is the secret. This proof uses the exact field-root bound. It does **not** apply to obfuscated nonlinear circuits, hidden-coefficient public evaluators or general WE; none of those is instantiated.

A bounded control used `P_d(t)=K+17*product_{j<d}(t-t_j) mod p` at `d=1,2,3,4,6,8,16`. Each exactly opens on its selected `d` source values and fails on every remaining one of the 64, confirming the root argument. A hypothetical high-degree table over unknown possible future parent digests violates practical Build; keeping coefficients private prevents public Open until a new mechanism is supplied.

## Actual executed work and exact next obligation

Two independent Python3 executions yielded **byte-identical JSON, 151 assertions each**: 64 locally valid SHA256d AuxPoW parent certificates; equal child, equal exact tag, equal AuxPoW root; 63 raw parent-pad alternate failures; no-witness semantic-pad extraction; seven exact finite-field root controls. The standalone local reproducibility archive `R317_parent_pad_dichotomy_20261116.tar.gz` includes complete derivation, checker, exact R316 dependency and paired outputs. SHA256 of the archive before publication: `1056fcbf87e8103ae23b0014e2aa0b669008653a82de7a75f71e956617bf8eb1`. Checker SHA256 `7d7fe79b03a473d6175abcd3f364286e931e446effb205a04068384b4d675db0`; each JSON SHA256 `856b4c66bd99db097544ed3656f40dcf209f46ef8369765143263dde26d1a337`. Neither network, Core C++, native SLH, malicious setup, coherent QPT attack nor real source qualification was executed.

**Next exact cryptographic equation:** find polynomial-time `Build_inc(x_W,sigma;rho)->C` and independently executable `Open_inc(C,w)=sigma` for every genuinely qualifying ORIGINAL authenticated `w`, including witnesses with different parent certs for the same child and different child ancestors under the permitted claim scope. The source SHA/consensus computation must be **inside** the release dependency, not a public check after an arbitrary pad is revealed. Establish a joint-public QPT reduction for hard-TRUE/FALSE under correlated `C,VK,aux`, sibling openings and malicious source/coin retention; do not assume a future shared secret, hidden evaluator, ideal release oracle, canonical unseen witness or native activation confinement. R225's slot-global veto vs actual native activation-bound spend remains unresolved.

**No positive ORIGINAL-foundation advance.** No PR progress comment, production edits, deployment or automation disable.
