# R296 — static serial nonlinear join and sibling-state transposition (NONQUALIFYING)

## Continuation and exact source scope

Continues R295 research note blob ef69f9be656b13b714a00f6452e84754b1ba4277. Starting PVUGC PR #1 head a42681d9a9a897ae882237d653c47a83f9cf0c1c, branch research/pq-wkem-validation-20260918, open/draft. Core #609 metadata read-only head c91539de3c34937e57d7f5fda47c7b0502ff33f6, not a network-deployment assertion. Most recent substantive ordinary comment checked: R225 #6796383617. No external literature, real Core tests, consensus admissions, native PQ signing, QPT experiment or production modification.

ORIGINAL stays unchanged: one notary initiates; any watcher with one qualified alternative BTC greater-work certificate, specific authenticated burn defect, or relevant qualified SYS inconsistency/tag fault may cancel. Bind full x_W (exact claim/UTXO, assertion, burn/amount/recipient, anchors/window, baseline, h_rel semantic ancestor, source height/depth, reset/deadline, native cancel message/VK, capsule ID). Enforce activated modern contextual AuxPoW ID, exact canonical SYS output tag, independent outer carrier authentication for tag faults and exact claimed wrapper provenance. Alternative parent certificates of the same child are not automatically a fork. N-of-N is preauthorization, not a challenge quorum. R225 requires slot-global veto policy or genuinely activation-bound native spend.

## Concrete continuation of R295 nonlinear two-input join

For a deterministic layered finite automaton with public Q_i, transitions delta_i(q,b), start q0, final accepting states A, select independent hidden lambda-bit L_(i,q), freeze K. Build publishes start label L_(0,q0), transition graph, and rows

    R_(i,q,b) = L_(i+1,delta_i(q,b)) XOR H("TRANS"||cap||i||q||b||L_(i,q)).

For accepting final a also publish

    E_a = K XOR H("END"||cap||a||L_(n,a)).

Public Open follows each bit through the graph, decrypts the next active state label with the row, and if its terminal state is accepting returns E_a XOR H("END"||cap||a||L_(n,a)). Induction on i proves exact same-K completeness for **every accepting path**, with different possible final state labels, in O(n |Q| |alphabet|) row setup and polynomial evaluation in the explicit state graph. This is an actual Build/Open for the simple *public automaton relation*, **not** Build_inc/Open_inc for ORIGINAL evidence. No SHA/AuxPoW source-credential generator or QPT FALSE security theorem has been instantiated.

The public transition graph itself has an O(n|Q||alphabet|) BFS accepted-witness extractor, without recovering hidden labels. Therefore if this exact public-state compiler were polynomial-sized for a mining-hard original source predicate, it would make finding its source witness easy. Any practical SHA/AuxPoW compiler must avoid publicly enumerable polynomial-state transitions or must source-authenticate the transitions with cryptographically earned credentials. Secret labels alone do not hide graph reachability.

## New complete-public sibling-label leak beyond R295's reused-pad attack

Take two capsules with different END domain strings A and B. A is a FALSE finite-state relation with accepting state a unreachable; B has a genuine accepted path to state a. If setup reuses terminal label L_(n,a) across claims, both publish

    E_A = K_A XOR H("END"||A||a||L_(n,a)),
    E_B = K_B XOR H("END"||B||a||L_(n,a)).

Adversary publicly evaluates the B accepting path and retains the terminal label L_(n,a) computed by its OWN Open, then recovers K_A = E_A XOR H("END"||A||a||L_(n,a)). No A witness, no builder private key, no request for a victim's intermediate representation, no collision/inversion and no need to learn K_B. Different capsule-scoped end hashes DO NOT repair cross-capsule label reuse. Independent per-capsule hidden intermediate and terminal labels eliminate this particular transfer; that is not general malicious-setup or selective-opening security.

Executed 4-layer/4-state fixture: B public DFA accepts 0011; A has no accepting length-four path. B's computed terminal label decrypts A's frozen 256-bit K despite distinct final hash domains, while independent A labels make this substitution fail. Full public data includes a synthetic K-correlated VK surrogate; it is explicitly not an SLH verification key.

## Source-specific residual-state feasibility calculation

For 80-byte synthetic header(p,z), let f_p(z)=1[SHA256d(header(p,z)) passes a target]. Any exact *deterministic* serial automaton must keep prefixes with distinct suffix-residual functions in distinct states: if two prefixes reached the same state, every suffix would necessarily have the same answer. With an explicitly ideal independent-random-digest function, m prefix bits, k suffix bits, and acceptance probability alpha, distinct residual functions match with probability

    (alpha^2 + (1-alpha)^2)^(2^k),

and a union bound on even one collision among 2^m prefix functions is

    choose(2^m,2) * (alpha^2+(1-alpha)^2)^(2^k).

Thus a sufficiently rich hash prefix/suffix split requires 2^m distinct deterministic states with high probability *in this narrow automaton model*, before other original consensus constraints. This is NOT a lower bound for all possible SHA circuits, witness encryption, concrete SHA or quantum computation.

Checker actually ran SHA256d over 1,048,576 synthetic 80-byte headers (256 prefixes x 4096 suffixes), numerical five-bit toy target alpha=1/32. All 256 4096-bit residual vectors were distinct; 32,823 hashes passed numerically. The ideal independent random-digest union-bound log10 is -106.59. No chain membership, valid AuxPoW, real tag, source depth, burn or native signing was checked. This is a bounded fixture, not realistic miner work or a QPT test.

## Exact outstanding source-release equation and disposition

Need to replace publicly traversable delta with an actually source-earned noninteractive transition:

    AuthTrans_(x_W,C,i,L_i,e_i) -> L_(i+1)

such that forall w satisfying the full ORIGINAL Verify(x_W,w), public Open_inc(C,w) produces one *frozen native-safe K*, while complete-public unauthorized QPT recovery or native forgery implies an ACTUAL qualifying ORIGINAL certificate or independent PQ hash/native break. This includes unrelated-fork rejection, sibling openings, malicious setup, retention of source-secret coins, and exact claim/UTXO/endpoint isolation without an adversary-volunteered trace. This note does not construct the function or prove security, and does not justify optimizing a restricted compiler.

Complete derivation, source, two matching captured outputs, and provenance are preserved in local archive R296_serial_join_source_residual_20261115.tar.gz (SHA256 a3bd463492c05a7d4af7c451262f59457d57ca74b67973154cc0d40f820ecb1b). Source checker SHA256 e2a837e21203f9d5eeed605375fadbc58cb1743fcc64915947b0ce6ef06702c0; run1 and run2 SHA256 2b4c5601994671c2d406be25ef0a15272b2586c64b56efe54fa311b05bd902db. Python 3 stdlib, two complete matching executions; 80-byte header length asserted. No regular PR comment/notification or automation stop: ORIGINAL release and independent joint-public QPT proof remain absent.
