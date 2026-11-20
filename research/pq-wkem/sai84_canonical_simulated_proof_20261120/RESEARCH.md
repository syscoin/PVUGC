# SAI84 — canonical simulated proof as a source-release carrier: explicit construction attempt and preflight rejection (NONQUALIFYING)

## Provenance, scope, and anti-spinning test
On the current run, read syscoin/PVUGC PR #1 open draft head `848c6001c0426ad8f8720bfe09a18e0916b344fe` on `research/pq-wkem-validation-20260918`, its immediately preceding SAI83 native-first-hop note, and ordinary PR comments since 2026-11-18T19:00:00Z (empty). SAI83 is endpoint work; it does not implement source-conditioned signature release. No Core source or tests reread; no new Core fact inferred. No web search/external paper. This run investigates exactly one **distinct** alternative to the previously failed R327 coefficient-function and R366 finite-cover tensors: can a *single globally canonical accepting proof* allow all ORIGINAL witnesses to recover the same hidden hash key, with no local-label mixing? No prior failed coefficient/tensor construction is retried.

## Proposed hash-only capsule *conditional on a missing primitive*
Let x be the complete original bridge claim, including the three independent OR challenge grounds, strict post-PQ contextual AuxPoW history checks, actual ancestor relevance and maturity, exact claim/burn/amount/recipient, BTC anchors/window, reset/deadline, native exact cancellation signature/message/VK, and capsule/session domain. The ORIGINAL relation R_x(w) has many genuinely distinct potential certificates, none designated as canonical.

Hypothetical canonical proof algorithms, **not instantiated**:

    (crs,tau) <- Set(1^lambda)
    pi_x      <- Sim(tau,x)           # even if no R_x witness exists
    pi_w      <- Prove(crs,x,w)       # for any authenticated R_x(w)=1
    Verify(crs,x,pi_w) = 1
    pi_w == pi_x                    # for ALL qualified witnesses, as bytes

With independently domain-separated SHA random-oracle roles Hv/Hk (this is explicitly an idealization):

    Build(x,S):  pi <- Sim(tau,x); t=Hv(sid||pi); D=S XOR Hk(sid||pi);
                 publish C=(crs,x,t,D,native_vk,manifest), erase tau,pi
    Open(C,w):   pi <- Prove(crs,x,w);
                 require Verify(crs,x,pi) and Hv(sid||pi)==t;
                 return D XOR Hk(sid||pi)

If these *very strong* interfaces existed and were correct, different original certificates would open the same frozen safe cancellation bytes. This moves all source consistency into one global proof; local finite covers/mixed label artifacts from R327/R366 do not directly apply. The public compact bytes are still not an ACTUAL Build/Open because Set/Sim/Prove are absent.

## Joint public distribution, FALSE, hard-TRUE and exact failure

1. The simulator **must** generate an accepting pi_x for FALSE x, or Build cannot know the pad when no source challenge exists. Consequently Verify accepts some fake proof for a FALSE original statement. Ordinary *statistical* original-source soundness is impossible for this simulated CRS; at best computational soundness with tau concealed. The public t is a commitment to the simulated proof, not evidence of a real source fork.
2. For a random pi of entropy kappa, a generic adversary can find pi by inverting t=Hv(pi) and then derive S from D without producing an ORIGINAL certificate. Classical exhaustive preimage cost O(2^kappa), idealized quantum search O(2^(kappa/2)), assuming the verifier commitment uniquely identifies pi. These are independent hash-puzzle routes. They may be classified as independent hash breaks when adequately parameterized, **but cannot be advertised as forcing the source history/PoW work**. For a source work budget substantially above this search cost the desired quantitative no-faster-than-original-evidence theorem fails.
3. Merely knowing a valid public proof pi does NOT generally furnish an ORIGINAL source certificate. Since the setup simulator itself creates pi_x for a FALSE x with no certificate, no unrestricted extractor `AcceptedPi -> ORIGINAL w` can hold for every accepting proof under that CRS. A restricted knowledge theorem excluding simulator-trapdoor access plus a joint-public proof of how an adversary obtained pi would be needed. The simulated-CRS standard soundness or ordinary NIZK zero knowledge alone cannot give hard-TRUE recovery-to-ORIGINAL.
4. S and the native VK are correlated: native signature verification supplies an independent offline candidate-key test, so the security game must simulate (t,D,VK,manifest,related capsules) jointly, not simply assume that a one-time pad is uniform when conditioned on all other published bytes. Full QPT adaptive/coherent adversaries are not covered by a classical RO query-log argument.
5. If all N parties use one globally shared simulated pi and any malicious party knows its setup tau/pi, it can decrypt **even the honest participant's** D (the same Hk key). Per-party independently generated canonical proof traps and domain-separated keys would be required for one-honest setup. This fixes a composition detail, not the proof primitive.
6. Tried source repair: include authenticated AuxPoW/actual ancestor data inside pi so `pi -> source witness` is trivial. Then distinct qualifying witnesses produce different pi and the same-output property fails. Selecting one canonical witness is not permitted; finding the first/winning fork or proving absence of unseen alternatives is outside the approved relation. Keeping pi witness-independent restores the missing trapdoor/unique-proof functionality.

## Explicit new equation, not a renamed security assumption
The required independently constructible operation is:

    SourceCanonicalize(crs,x,w) = Sim(tau,x)
          for EVERY R_x(w)=1,
          with compact classical PPT representation and no tau for Open,

together with a real joint-public adversarial reduction

    RecoverNativeSig(A,C,Aux) -> ORIGINAL qualifying certificate
                                OR independently justified hash/native break

under malicious setup, retained source coins, sibling capsules, QPT interfaces and the actual context-dependent source verifier. No concrete SHA/AuxPoW algorithm realizing SourceCanonicalize was found. Assuming this operation would largely repackage the very release capability sought. Building it by Fiat-Shamir proofs, public proof bits, hash target prefixes, retained source secrets or a private evaluator was explicitly rejected as uninstantiated or insecure. The algebra is a candidate interface/diagnosis, NOT a release primitive, and no QROM-to-concrete-SHA proof is asserted.

## Run actions / result
Read current relevant PR metadata, last commit and latest ordinary comments using the connected GitHub read actions; performed the symbolic Build/Open/joint-public analysis above. **No source program, runnable release algorithm, cryptographic proof or quantitative PoW theorem was completed; no checker or external agent was invoked for this run.** No user breakthrough notification or PR progress comment. This is a single nonqualifying research checkpoint; its precise next viable step is an actually instantiated globally source-consistent public source-to-secret operation, NOT another hash-commitment parameter sweep. The active research automation must remain enabled.
