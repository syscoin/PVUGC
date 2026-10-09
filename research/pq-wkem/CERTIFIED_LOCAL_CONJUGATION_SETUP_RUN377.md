# Run 377 — A certifiable local-conjugation completeness invariant, not a WKEM

Live starting PR head: 49a1d084724766d46ae7fad7b929de57c1612516, branch research/pq-wkem-validation-20260918, open/draft/unmerged. Latest substantive comment 6067040320. Exact dependency blobs: Run 376 727c59155061c758ab6efc5c0f31ed359f10e5fe; Run 259 c7f3b77f0273ca1cbe6f0b31c1a086b8eb3acbf2; CLZ c19d9d9cd515140e3ce62eac960cd548c0add622. The earlier Run 375 denied packet is not retried or republished.

## Exact constructive theorem A: universal correctness of one fixed compiler family

For a Boolean source circuit V_x(w), assign ONE mask r_i to every wire i, shared across all fan-out occurrences. Represent its bit b_i by encoded e_i=b_i XOR r_i. Replace each two-input gate g with the local table G'(u,v)=g(u XOR r_a,v XOR r_b) XOR r_c. Encode the witness and public context input wires and decode the final validity bit, then release the same K iff that decoded bit is 1.

By induction on topologically sorted gates, for EVERY statement x, mask vector r (even maliciously biased), and ORIGINAL witness w, the transformed gate sequence evaluates exactly to V_x(w), with distinct internal states allowed. Thus every valid ORIGINAL witness returns THE SAME K; invalid witnesses return bottom when the whole honest entrypoint is followed. This is a semantic correctness statement, not a secrecy statement.

## Conditional theorem B: compiler-origin certificate bypasses a generic coNP audit

Fix a deterministic polynomial compiler Comp(x,ctx,K;r) with an established universal correctness theorem for ALL accepted coins, and a bound context/UTXO/branch/graph predicate GraphCheck. The NP relation
RelComp((x,ctx,P,vk),(K,r)) = [P=Comp(x,ctx,K;r) AND vk=PK(K) AND GraphCheck(ctx,vk,P)] 
is polynomial-time checkable. Suppose a concrete certificate/argument for this relation is adaptively statement-sound against arbitrary QPT adversaries (including coherent computation and public correlated inputs). An accepted malformed P that selectively denies some valid ORIGINAL witness cannot satisfy RelComp by theorem A, hence yields a false accepted NP statement. The probability of this *malicious completeness-fault event* is bounded by the argument's soundness error. This is a straight-line implication: no QPT extraction or rewinding is needed for completeness. Multiple capsules require adaptive multi-statement soundness (or a justified Q-fold loss), not pointwise soundness against a fixed statement.

This is conditional: no argument or distributed proof is implemented. Publishing the witness (K,r) discloses K. A privacy-preserving implementation would require a suitable ZK protocol and distributed proof generation over N-of-N secret shares: a single prover possessing K defeats the original one-honest-secret setup. A sound certificate also does not detect retained copies of K, malicious seed bias that compromises confidentiality, incomplete pre-signatures, or bypass edges outside GraphCheck. The protocol must verify the *actual* complete graph and abort before irreversible funding if checks fail. No keyless builder is claimed.

## Decisive falsification of security inference

The finite example publishes the output release table containing K and is deliberately insecure. Even an ideally sealed final gate with an independently callable raw acceptance-bit input can be bypassed by supplying the accepting label; neither source-to-frontier authentication nor false-statement hiding follows from local conjugation. The public native checking key is bound correctly, yet the key itself is visible. This is exactly why a structural all-witness *completeness* proof does not imply WE-like *authorization* security.

Attack taxonomy: (1) local raw seam breaks; (2) publicly conjugated gates can synchronize into a global readable circuit; (3) gate classes are statistically recognizable; (4) related views/capsules may only increase leakage; (5) chosen raw accepting input wins classically, hence against QPT; (6) a selective-failure edit is rejected by an exact compiler-trace check, but malicious coins/retained secrets remain uncovered; (7) cross-UTXO/branch binding needs a real GraphCheck and sighash audit; (8) vk=PK(K) does not protect K; (9) no separate quantum-only security result is asserted.

Run 259 applies only AFTER a complete representation meets its specified residual/encoding acceptance conditions; a raw success label, recovered K, or native signature is not automatically such a representation. The missing authorization/key recovery -> accepted ORIGINAL representation or independent arbitrary-QPT break remains UNPROVED.

## Reproduction, status, literature

The exact published checker local_conjugation_compact_run377_check.py exhausts 2^11 mask assignments, evaluates each 4-bit witness, checks same-K correctness, distinct encoded states, and rejection of local gate and vk tampering. It explicitly checks the terminal plaintext K leak. Python py_compile passed, two executions produced byte-identical outputs; 59,776 finite assertions passed. An independent longer local checker passed 83,328 assertions. Both have toy 16-bit K, no real ZK, no MPC, no SLH/P2MR, and NO cryptographic QPT security proof.

Prior literature for the syntax-versus-security distinction: Bellare–Hoang–Rogaway, Foundations of Garbled Circuits, CCS 2012, https://doi.org/10.1145/2382196.2382279 ; Wang–Ranellucci–Katz, Authenticated Garbling and Efficient Maliciously Secure 2PC, CCS 2017, https://eprint.iacr.org/2017/189 . Only abstracts/records were checked here, not their complete proofs; neither supplies our public noninteractive release primitive. The full merged Canetti–Luo–Zhang proof audit remains pending.

Ledger: all-coins correctness unconditional for the specified XOR-gate grammar; certified malicious completeness conditional on a genuine adaptive QPT-sound NP argument, sound distributed transcript and complete graph check; false-instance full-public QPT hiding, true-instance key/signature -> ORIGINAL extraction, auxiliary quantum advice, malicious N-of-N secrecy/erasure/abort, related capsules, 128-bit resources, and conditional native Bitcoin PQ endpoint all UNPROVED. Production unchanged, PR draft/unmerged, practical WKEM stopping condition unmet.
