# SAI102 — public SHA-stream witness labels, prescreened before implementation (NONQUALIFYING)

## Verified continuity / narrow objective
This bounded iteration read the live open/draft syscoin/PVUGC PR #1 head `fe78f5e523c3758c0e9c046915d49c1329dcc64f`, branch `research/pq-wkem-validation-20260918`, and its exact SAI101 note (blob `c347475c85487e02017937163b388b460c829fcb`). The last note disproved a *fully serialized sparse* Boolean-ideal coefficient compiler. SAI100 had disproved setup-selected independent finite hash lookups by showing that most independently generated future qualifying witnesses missed the setup labels. No source-code reread, on-chain network authentication, native-signature execution, QPT proof or Core test was performed here.

**Selection rule.** Unlike SAI100, the present candidate DOES NOT select a finite lookup set at setup and DOES NOT publish polynomial coefficients, intermediate affine pads, local variable labels or a private oracle evaluator. It instead tries to derive a label *on demand* by hashing the actual authenticated certificate bytes in one globally sequential stream, so every future valid certificate can compute its own label in polynomial time. This is a different explicit operation and avoids SAI100's table-hit failure. We test the first necessary property—common frozen output—symbolically before implementing. It fails. No toy implementation is justified.

## Attempted entirely public algorithm
Let x be the complete claim-scoped ORIGINAL statement and R_x the approved three-branch predicate (qualified greater-BTC-chainwork, finite authenticated burn refutation, or mature qualified Syscoin history inconsistency/tag fault). Let `src(w)=(b_1,...,b_ell)` be a canonical encoding of the complete *actual* authenticated source evidence, not an invented source identifier or arbitrary PoW. Each b_j may be a SHA256d digest or authenticated Merkle/header segment; the exact verifier runs separately and is NOT a hidden source oracle.

Try a public source-derived stream:
```
t_0 = H("stream/root" || x || sid)
t_j(w) = H("stream/step" || j || t_(j-1)(w) || b_j(w))
k(w) = H("stream/pad" || t_ell(w))
C = (x, sid, D = S XOR k_setup, public stream definition)
Open(C,w) = D XOR k(w) if R_x(w)=1; bottom otherwise
```
The desired classical-PPT Build must set the frozen pad k_setup at funding, before future w exists, and public Open must return the SAME S for EVERY qualifying ORIGINAL witness. This is an explicit, fully serialized and practical *public hash stream*, not a secret-evaluator placeholder. It is not a correct witness-KEM.

## Exact two-witness correctness obstruction (classical independent-RO submodel only)
Choose two qualifying ORIGINAL certificates w0,w1 for the same claim that have unequal canonical source streams. This is allowed: different Bitcoin parent work certificates can certify one child, and a genuine Syscoin conflict uses distinct histories; no global common hash preimage is guaranteed. Assume the two domain-separated stream trajectories do not merge by a prior SHA collision. In the ideal independent-output RO model, terminal pads k0,k1 are independent uniform n-bit strings. Thus, even after Build learns w0 and uses k_setup=k0, the probability that w1 opens the SAME frozen S is exactly 2^(-n), up to the bounded collision probability of the stream trajectories. If Build chooses a pad independently of both unknown future paths, both must match, with probability 2^(-2n). For n=256 this is negligible, not overwhelming correctness. Canonicalizing the sequence and authenticating every element do not cause different real histories to share final states.

If one *forces* a merge by discarding all divergent source bytes and deriving the terminal pad only from the common pre-fork baseline or known 41-byte canonical ancestor tag, k_setup becomes publicly computable and an attacker obtains S=D XOR k_setup without original challenge evidence. The strict canonical tag format is a commitment to the actual reference ancestor, NOT a hidden trapdoor or common unknown token. A stream that still includes divergent certified parent bytes cannot converge without either a hash collision or additional secret-dependent merge machinery.

The proposed possible repair is a public Merge(x,sid,t_ell(w),w) satisfying
```
for all ORIGINAL R_x(w)=1:
    Merge(x,sid,t_ell(w),w) = y_(x,sid)
Build before w exists: k_setup = H("pad" || y_(x,sid))
```
where y is unavailable to unauthorized attackers even given ALL public capsule bytes and correlated source coins. But constructing Merge and setup's y together, with source authentication governing recovery and hard-TRUE extraction to an ORIGINAL certificate, is exactly the uninstantiated SAI99 common-token/FE-like release obligation. Giving y as a secret oracle or assuming a witness-PRF is not an independent instantiation. No repair is claimed.

## Simulation and endpoint check
The public distribution for this attempt is `(x,sid,D,code)`. With independent k_setup, D is uniform for fixed S, hence the *ciphertext marginal* has an elementary all-FALSE simulation; but correctness fails for authentic future witnesses, and conditioning on any publicly computable k_setup reveals S. The full joint view (native VK, setup proof, sibling capsules, malicious source coins and selective openings) has NOT been simulated, so even this candidate's marginal hiding is no security claim. Source-positive proof verification outside the protected computation would not fix a publicly exposed k_setup.

This screen keeps the native endpoint separate. Existing first-release Bitcoin ECDSA signing may be classical, but the missing FE/WE hash-only release substrate and its QPT security do not follow from that endpoint concession. R225 activation-portability and the need for exact transaction/outpoint binding remain independent obligations.

## Disposition and next unfinished equation
**REJECT this stream-carrier family at the correctness equation; do not implement a larger source fixture, different domain separators, different stream compression, alternative pad entropy or a prefix-hash sampling test.** This is an independently stated submodel calculation, not a general impossibility for computational hash-only ORIGINAL witness encryption.

Still missing is a genuinely *serialized*, classical-PPT public `Build_original(x_W,sigma_cancel)->C` and `Open_original(C,w)=sigma_cancel` for every qualifying ORIGINAL witness; both the source-conditioned key-convergence operation and complete-public FALSE/hard-TRUE arbitrary-QPT recovery/native-forgery reduction must be instantiated together. Any candidate using an unconstructed hidden Merge, perfect-label oracle, FE compiler, iO or witness-PRF as an assumption fails this gate. No breakthrough, no user progress notification, no PR comment and no production or automation changes were justified.

This pass consisted of actual GitHub reads and mathematical screening. No checker, Core test, native signing, network input or QPT computation was run; do not infer such tests from this note.
