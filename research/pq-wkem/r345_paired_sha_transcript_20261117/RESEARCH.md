# R345 — Paired SHA transcript response cannot deliver arbitrary ORIGINAL witness cancellation (NONQUALIFYING)

## Continuity and hypothesis
One bounded offline analysis, following PVUGC #1 branch research/pq-wkem-validation-20260918 at observed head 9d8c72ad773586178ae0a690a549e94effa6f7ce (R344, blob 6cbdaf9548c985e7ffa343628c83a8ca435e144b). Also read R342/R343 exact notes; recent issue comments since November 15 were empty. No web, external literature, Core tests, authentic source evidence, native signing or QPT experiments.

This pass tests a DIFFERENT candidate from low-degree masks, prefix seed covers or finite hash-state graphs: use a hash-committed setup transcript and a second response computed from any future original witness. The original bridge statement and three independent OR grounds are NOT changed.

## Explicit SHA-only release equation
Let Hc,Hp be domain-separated hash functions and x be the frozen original claim, source, LC and exact native cancellation context. Build knows frozen sigma, samples hidden uniform r, publishes a=Hc(r) and D=sigma XOR Expand(Hp(r),len(sigma)), and erases r. Propose a public responder with original witness w:

    Resp(a,w) -> z such that Hc(z XOR Encode(w))=a.
    Open(C,w) = D XOR Expand(Hp(z XOR Encode(w)),len(sigma)).

Any response to a which recovers the original r gives the SAME sigma for every original w, without selecting a canonical witness. But Resp IS NOT IMPLEMENTED. Plaintext VerifyOriginal after releasing the pad would not be sound cryptographic gating.

## Inverse-direction reduction and two failed repairs
For any fixed known w independent of fresh setup r, an algorithm yielding z with Hc(z XOR Encode(w))=Hc(r) immediately inverts Hc on its random-image distribution: output z XOR Encode(w). Success probabilities are identical; no rewinding, adversarial state or query logs. The argument applies to an arbitrary classical or quantum responder having that known w as auxiliary input. It is not a proof that real ORIGINAL witnesses can be PPT-sampled as independent advice, nor a proof of concrete SHA security.

1. Publishing r lets ANYONE evaluate Hp(r) and unmask sigma on FALSE instances; a source verifier placed after this release cannot help.
2. Publishing b=Hc(r XOR Encode(w0)) for one anticipated w0 cannot support another w1 with different encoding unless the hash inputs collide. Per-future-witness commitments return to enumerating exponentially many potential certificates. Actual SHA/AuxPoW source evidence is not guaranteed to contain independent builder-selected r; requiring it would narrow the ORIGINAL relation.

A pair of consistent responses can expose Encode(w), not transform arbitrary w into setup secret r. Special-soundness-like extraction from two transcripts runs in the opposite knowledge direction. Standard Fiat-Shamir or MPC-in-the-head proof soundness alone is NOT an instantiated source-dependent secret delivery algorithm. This toy equation is not a full Sigma protocol.

## Joint public view and remaining gaps
The (a,D) transcript may hide sigma when r is independent and unknown under explicitly idealized, domain-separated QROM hash assumptions, but no complete-public QPT simulator was proved for native VK/context correlations, sibling selective openings, malicious setup, retained source-coin auxiliaries or the actual three-OR relation. FALSE hiding is irrelevant if valid original witnesses cannot open. No classical-PPT Build_inc/Open_inc or hard-TRUE recovery/native-forgery reduction was established.

## Actually executed synthetic checker and provenance
A Python3 SHA256 script executed twice with identical JSON bytes. It selected two unrelated 32-byte strings satisfying an artificial SHA prefix-5 predicate; verified that a SHA commitment for r XOR w0 differs from one for r XOR w1, checked XOR extraction, and checked that making r public reveals a synthetic 32-byte capability. This did NOT exercise actual Core rules, source admission, Bitcoin membership, native signatures, or quantum security. check.py SHA256 813d27141f5b82352541aa8c2f724eabb0272424d2ec203688b0ded9adfa188c; both output SHA256 92422bb6e0ad7629f97540688546c00ed5f925bc846a779065884da513ed4a84. Full local note, checker and results in /mnt/data/R345_paired_transcript_screen_20261117.tar.gz (SHA256 4f03aa6ec7c2efa8bed05e26c7cb635cc55ac36b357fbeb732a7ec24cc9a628b). Code/results remain LOCAL only; no claim of committed test bytes.

## Decision
NONQUALIFYING. Do not vary transcript count, SHA prefix, salt or nonce size and call it progress. The next necessary mathematical object remains a serialized polynomial-size issuerless source-dependent PUBLIC release program that delivers the same frozen native safe cancel capability on EVERY qualified ORIGINAL certificate while refusing unrelated/spliced inputs, with independent full-public FALSE/hard-TRUE QPT security and malicious N-of-N/sibling/native composition. None is constructed. R225 activation-portability remains separate, and the strict post-PQ light client was not shown defective by R316. No user/PR progress comment, production change, deployment or automation change.