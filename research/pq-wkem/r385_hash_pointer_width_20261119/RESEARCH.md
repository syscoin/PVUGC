# R385 — Hash-pointer streaming-state gate (NONQUALIFYING)

## Provenance and exact construction step

The actual open/draft syscoin/PVUGC PR #1 was read at head 9408f893b5109f47e3a12ad60cbee8caa6be1796, branch research/pq-wkem-validation-20260918. The last commit is R384, whose directionally encrypted hash-edge graph correctly releases the same payload along accepted **explicit** graph paths, but enumerating future SHA/AuxPoW certificates makes Build exponential. New issue comments since 2026-11-18 18:00 UTC: none. No Core source was reread or Core test run, and no external web search was performed.

The candidate here changes the *representation* rather than repeating R384's hash placement: merge paths by the internal state of a deterministic streaming source verifier, then encrypt directional transitions with one-way hash pads. The exact question is whether a polynomial-width verifier can represent ORIGINAL source qualification without enumerating possible future source histories. The attempt and independent full-public simulation are considered together.

## Serialized Build/Open for a restricted bounded-width automaton

For a publicly specified length-L layered DFA, let Q_i be the states at position i, q0 the start, delta_i(q,a) the public transitions over alphabet Sigma, and F the accepting terminal states. Let W=max |Q_i|. Build(x,S) samples independent random lambda-bit k_(i,q) for all states, publishes k_(0,q0), and publishes for every transition

    E_(i,q,a) = k_(i+1,delta_i(q,a)) XOR
                SHA256("edge"||sid||i||q||a||k_(i,q)).

For every accepting terminal state q, publish

    D_q = S XOR SHA256("out"||sid||q||k_(L,q)).

Open(C,a0...a_(L-1)) follows the publicly indexed transitions and decrypts one successive state label per step. If the path ends in F, it decrypts D_q. By induction, **every accepted input returns the SAME S**, without a common witness or common input hash. The serialized capsule has O(L W |Sigma|) hash-wrapped transitions and classical polynomial runtime **only if W and Sigma are polynomially bounded**. Source authenticity must be inside the actual accepted language, not checked as an optional if-statement after recovery.

For FALSE instances, no root-reachable terminal belongs to F. Partition states into reachable R and unreachable U; no edge from R enters U. In an *independent random-pad replacement* hybrid, every ciphertext whose tail is in U and every terminal D_q on U is independently uniform conditional on the reachable public transcript. This admits an exact joint-public simulator **only for that idealized pad model**. Concrete SHA256, QROM coherent access, malicious setup, native VK and correlated siblings have NOT been reduced to it. This is not a secure ORIGINAL WKEM.

There is a decisive HARD-TRUE limitation even before cryptanalysis: the public transition table permits breadth-first search in O(L W |Sigma|). If any accepted path exists, the adversary obtains its input without mining or learning hidden state labels. Thus a polynomial-width explicit DFA cannot encode expensive ORIGINAL source-witness acquisition unless the edge labels themselves require genuine authenticated work not given away by the public table. Making edge validity a cryptographic condition inside a succinct key-private transition evaluator is exactly the missing primitive.

## Lower bound at one authentic source subcondition

Take a k-bit expected hash pointer y and next bytes z, and require SHA256(z)=y. For any H:{0,1}^m -> {0,1}^k define L_H={(y,z):H(z)=y}. Every exact deterministic automaton that reads y first and z afterward has at least |Im(H)| states after y: for distinct y,y' in Im(H), choose z such that H(z)=y; this suffix accepts from y and rejects from y'. This is a Myhill–Nerode distinguishability argument applying to explicit-state, read-in-this-order automata. It does NOT apply to ordinary polynomial-size SHA verification circuits holding y in k public registers, nor to an independently constructed cryptographic protected-transition compiler.

In the explicitly idealized *random-function* model with m-bit domain and k-bit range,

    Pr[H is not onto] <= 2^k (1-2^(-k))^(2^m)
                       <= 2^k exp(-2^(m-k)).

For m=512,k=256 this supports 2^256 required distinct explicit states with overwhelming random-function probability. **It is not a theorem asserting concrete SHA256 surjectivity**, nor a general WE impossibility claim. It is a structural objection to R384's finite explicit-state compilation of a subcheck that original authenticated history verification actually needs.

## Attempted repair: succinct master-secret indexed states

A natural table compression sets

    k_(i,q) = H_state(sid||i||q||master_secret),
    PublicTransition(C,i,q,a)
       = k_(i+1,delta_i(q,a)) XOR
         H_edge(sid||i||q||a||k_(i,q)).

This is efficient for a **private** holder of master_secret. But a stateless public opener must compute the transition for as-yet unknown original source states without receiving that secret. Revealing master_secret immediately reveals the terminal masks and S; publishing an ordinary program containing it does likewise. Publishing the entire transition table costs at least the explicit state width; retaining an online private signer violates the required offline/public interface. A setup ZK proof that the private formula was compiled correctly does not implement its public hiding.

The missing operation is therefore a genuinely **serialized, secret-dependent, publicly usable original-source transition**, with joint-public security against mixed-state and invalid-source queries. Treating this equation as an ideal SourceOpen/FE interface is not a construction. Do not rerun prefix-width, rank, interpolation, feature, or graph hash-placement variants without an independently instantiated transition primitive.

## Executed bounded local checker (not a source-security result)

Python3 standard-library check.py was executed twice, and both captured summaries were byte-identical. On truncated SHA256 with 16-bit input and 8-bit output it enumerated all 65,536 inputs; all 256 possible pointer hashes occurred, confirming the 256-state exact DFA lower bound for that fixture. A separate 8-bit nonce toy **enumerated all 256 candidates at Build**. It formed actual hash-wrapped edge ciphertexts with freshly sampled 256-bit private labels: two accepting nonces for target 6 opened the same synthetic S, and target 2 had no accepted nonce. The public edge table itself revealed accepted nonce 104. This is explicitly SOURCE-INCOMPLETE and confers no ORIGINAL mining-work bound.

Local checker SHA256: ea37ca5e49bf63b4a5fc72eed5ff04d6cfb08bc28ee86deb41a24bd8712da203.
Both local output JSON SHA256: d35fba08eee198e05da3103c146f78724fb0cf14c9da68a4a67e4a475883c3a3.
Complete local-only derivation, executable checker, both captured summaries, and provenance: R385_hash_pointer_width_20261119.tar.gz, SHA256 de6615385ea666a28e0c7830f67de6abbde90d40cc8694327947430e06d9342b. Its private sampling tapes are not in the summaries; identical summaries do not mean identical random ciphertexts. The checker and output files are NOT published by this research note.

## Exact remaining obligation / status

**NONQUALIFYING.** Neither a practical classical-PPT Build_orig(x_W,sigma_cancel)->C and public Open_orig(C,w)=sigma_cancel for every ORIGINAL qualifying witness, nor a full-public FALSE/hard-TRUE QPT security reduction to an ACTUAL original certificate or independent native/hash break has been instantiated. R384 explicit-graph failure was refined to a concrete hash-pointer state-width obstruction and a precise missing secret transition equation, but this is not a major foundation advance. Do not notify it as a breakthrough.

Keep all three independent OR challenge grounds, strict contextual AuxPoW and actual ancestor relevance/LC depth, complete claim/burn/amount/recipient/anchor/window/reset/cancellation-message/VK/capsule binding, one-honest N-of-N setup, native preauthorization, siblings, malicious source coins, and pre-funding completeness. The initial Bitcoin ECDSA endpoint may be classical as approved; it does not prove end-to-end QPT security. No PR progress comment, production/core change, deployment, or automation change occurred during this research iteration.
