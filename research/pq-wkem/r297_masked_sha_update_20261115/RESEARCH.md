# R297 — Exact nonlinear masked-SHA update interface (NONQUALIFYING)

## Provenance and continuation

This bounded offline pass continues R296's exact unfinished AuthTrans_(x_W,C,i,L_i,e_i) -> L_(i+1). Starting PVUGC PR #1: open/draft, research/pq-wkem-validation-20260918 at 1b7931266c169c1eab1e13d121919c485987ebd1. R296 path research/pq-wkem/r296_serial_nonlin_source_join_20261115/RESEARCH.md, blob 04bf25952fb42613658f475cef95219752a. Core #609 metadata at c91539de3c34937e57d7f5fda47c7b0502ff33f6; release/activation disabled, no Core test rerun. Date-scoped ordinary PR comments: no recent new comments; R225 #6796383617 remains an independent native endpoint concern. No external web/literature, agents or unrelated repositories.

ORIGINAL x_W is unchanged: exact protocols/chain, claim/UTXO, assertion/burn/amount/recipient, baseline and relevant semantic ancestor at h_rel, BTC anchors/window, contextual modern AuxPoW chain-ID, exact applicable 41-byte parent SYS tag, merge-mining index, interval tag continuity and LC depth, independent actual faulty-parent carrier, reset/deadline, exact safe-cancel message and VK, capsule ID. Three independent challenge OR grounds remain qualified greater-work BTC competitor, finite authenticated specific-burn defect, or qualified SYS inconsistency/tag fault. No greater SYS work, no second notary, no new source signer or on-chain NP verifier. N-of-N preauthorizes; a single notary initiates and any qualified watcher challenges. R225 activation-bound native signature issue remains.

## Proposed repair of the R296 public-state graph

R296's explicit polynomial public DFA admits easy BFS witness discovery; exact SHA256d residual functions generally need huge explicit state width. Here the candidate replaced the explicit graph by a Boolean SHA circuit operating on privately XOR-masked state bits. Build samples secret input/output masks and publishes a *small exact ANF* for each nonlinear gate acting on encoded wires. Open could evaluate the ANF on live encoded source state without enumerating future states. An intended frozen endpoint was E = K XOR SHA256("R297/END" || (1 XOR d)), where d masks the accept output bit. This is polynomial in gate count if the hidden masks remain secret. The question is whether they do under the *complete public coefficient representation*.

### Exact AND gate lemma

Let u=x XOR a, v=y XOR b, output encoding be (x AND y) XOR d for unknown bits a,b,d. The unique exact public ANF valid for all four inputs is

    P_AND(u,v) = uv XOR b*u XOR a*v XOR (a*b XOR d).

Anyone reading the public coefficients directly recovers

    a = coefficient[v],
    b = coefficient[u],
    d = constant XOR a*b.

No SHA inversion, witness representation, source certificate, evaluator trace or hidden-label guess occurs. A classical full-public break is automatically a QPT break. This is an exact lemma only for invertible affine-XOR wire encodings and a publicly readable exact polynomial gate, not a general hash/WE impossibility.

In the FALSE predicate Phi(z)= z AND (NOT z), no original satisfying witness exists. Nevertheless the encoding of logical accept-bit 1 equals 1 XOR d and is recovered directly from the coefficient table, so the publicly published E decrypts to K. This is an *unauthorized capability-opening counterexample* for the tested encoder, not a concrete native signature or real ORIGINAL challenge.

### Ch/Maj shared-input extension

For input masks a,b,c and independently masked output bits dCh,dMaj, Boolean Ch(x,y,z)=xy XOR xz XOR z and Maj(x,y,z)=xy XOR xz XOR yz yield these exact public ANFs:

    P_Ch(u,v,w)=uv XOR uw XOR (b XOR c)u XOR a*v XOR (1 XOR a)w
                XOR (a*b XOR a*c XOR c XOR dCh).

    P_Maj(u,v,w)=uv XOR uw XOR vw XOR (b XOR c)u XOR (a XOR c)v
                 XOR (a XOR b)w XOR (a*b XOR a*c XOR b*c XOR dMaj).

For the SAME masked input wires, a=coeff_v(P_Ch), c=coeff_v(P_Maj) XOR a, b=coeff_w(P_Maj) XOR a; both constant terms then recover their output masks. Exhaustive enumeration confirms all 32 input/output mask combinations. Ch alone and Maj alone each retain a twofold input-mask ambiguity, so neither alone proves total disclosure. SHA256's real Ch(e,f,g) and Maj(a,b,c) do NOT share one input triple; this joint-mask lemma must NOT be misreported as an immediate full-SHA mask extraction. Bit-level AND gates in an explicitly transparent masked-gate decomposition do satisfy the individual lemma.

## Constructive repairs actually examined

A public reversible ANF basis change or renamed coefficients does not help: a public exact evaluator can be queried on all four (or eight) encoded inputs to recover the same truth table and its ANF.

A nonlinear hash-state encoding L_i(t)=SHA256("L"||secret_i||t) avoids the linear coefficient recovery, but a static setup cannot issue rows for all unknown future authentic SHA/AuxPoW state tags without a source-conditioned dynamic evaluator. A public master derivation key allows arbitrary fabricated transcript rows; a hidden key prevents independent future Open; finite explicit rows fail completeness for other qualifying witnesses. This locates the next needed mechanism precisely at the nonlinear state transition, without assuming it exists. Conventional all-input reusable garbling implements one gate but permits the earlier mixed-evaluation/cut attacks; a whole-witness hash row tag still requires unknown-future row issuance.

The pass therefore does NOT instantiate source-earned AuthTrans or ORIGINAL Build/Open. The explicit polynomial gate encoder fails complete-public FALSE security at its first nonlinear AND. This eliminates this specific implicit-SHA-state representation only, not SHA-only WE in general. No generic obfuscation/WE/WPRF, lattice, discrete-log, programmable QROM, online signer, or extra PoW credential is smuggled into the repair.

## Executed checks, precise security scope

Local Python 3 standard-library checker (SHA256 for frozen payload-mask surrogate only) executed twice with byte-identical JSON. Both runs checked 8/8 AND mask triples and all Boolean inputs; 256 exact public frozen-secret recoveries under modeled FALSE Phi; 32/32 Ch/Maj shared-input mask quintuples and all Boolean inputs; and exact twofold ambiguity for standalone Ch or Maj. A finite 1024-tag static row control was also checked; this is not a random-oracle or source-history theorem. The recovered surrogate K is NOT a native SLH-like signature.

Local archive R297_masked_sha_update_20261115.tar.gz includes full derivation, executable checker, two JSON outputs and SHA256 manifest. Archive SHA256 d2a0d7c9919b00085c42fbc43965e8c95bee53bd71a2d383aac2ca7dffe8cea6. Checker SHA256 3f6fc67c66a419116f6cc5e8a3675be5665545b91fbae869be8e00fa0fb1a504; both JSON SHA256 195cefb5e8adf56f512a68fb704dc2d98dfbc6cf4d9d0ffc5b50ee609f9e61cc. These are local conversation artifacts, not repo code. No real chain admission, BTC best-chain selection, actual original witness, native PQ signature, quantum experiment or Core test was executed.

## Exact unresolved obligation

Build_inc(x_W,sigma_cancel)->C must run in classical PPT; every authenticated ORIGINAL w must cause public Open_inc(C,w) to produce the SAME frozen safe cancellation capability, for all three OR grounds without a forced canonical witness. Unauthorized FALSE/hard-TRUE complete-public QPT recovery (and accepted native forgery) must straight-line imply an ACTUAL qualifying ORIGINAL certificate or independent PQ native/hash break with full auxiliary, sibling-capsule and malicious-setup handling, not a voluntarily supplied algebraic representation. The needed *opaque*, source-earned nonlinear state update remains unconstructed. This is NONQUALIFYING for release and QPT security; no PR comment, notification, production change, release authorization or automation stop is warranted.
