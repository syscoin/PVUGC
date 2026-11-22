# SAI113 — source-constrained GGM output-range ticket, nonqualifying

## Continuity and selected operation
Started from open draft PVUGC #1 branch research/pq-wkem-validation-20260918, head 0609b1f5cce7f095c09d98da4b154f300d4451b6, tree 48fe57d6a05e08c6e04b04ed45e78c2ee93198c7. Read exact SAI112 note blob 391ceae320c07a2fd81f8bdfc4c623c3f09931db. Recent issue comments since Nov 19 UTC empty. Core #609 metadata read (b3b4f643383a2149807a25fe38d26b5f058daa60); no new Core source read/test. R327 and SAI112 prohibit raw publicly callable invalid-trace pads and exposed source-independent BP transitions. Here the structural change is a hash-only GGM PRG subtree for an eligible PoW **output interval**, instead of the old algebraic local gate. The indispensable missing operation is to bind that range authorization to an actual hash preimage with a source-authenticated ORIGINAL certificate.

## Concrete candidate and failed repair
For a claim/session sid (containing exact UTXO, withdrawal/burn, amount, recipient, baseline, authenticated BTC/SYS source and anchor/window/LC depth/reset/deadline, safe cancellation and VK/capsule), let z be the complete original source certificate, h(z)=SHA256d(parent_header). One PoW subcondition is h(z)<T. It is NOT the full original relation; raw work does not establish BTC best-chain membership, admitted Syscoin ancestry, fault relevance or finite burn refutation.

A hash-output interval [0,T) admits at most 256 maximal binary prefixes when h has 256 bits. When T=2^(256-d), there is just one prefix 0^d. A conventional hash-PRG/GGM tree can distribute constrained subtree material compactly. Proposed Build publishes the output-prefix subtree material and a payload correction; proposed Open would extract a branch pad for h(z) in the accepted interval. **But any public subtree key usable on h(z) is usable on a fabricated value h=0, without a preimage, parent coinbase, anchored history, or original source certificate.** External VerifyOriginal(z) is bypassable. If the subtree seed and correction recover the common native signature, the h=0 caller also recovers it. If a GGM leaf only returns F_s(h), varying accepted h produce varying values rather than one frozen signature; no compact, secret-hiding corrections are supplied. A correction S XOR H(seed_p) with public seed_p exposes S outright. Hidden seed_p leaves no public Open.

Repair tested: constrain GGM on source *preimage input bytes* z, not h(z). In a random-function model V={z:SHA256d(z)<T} is a random sparse subset of the input domain; only fully accepted dyadic subtrees can receive a public subtree key without authorizing invalid inputs. For m input bits with independent acceptance probability p, the expected number of **maximal** fully accepted prefixes of subtree size 2^j (0<=j<m) is

E[N_j] = 2^(m-j) (p^(2^j) - p^(2^(j+1))),

with expected root term p^(2^m). In particular E[N_0]=2^m(p-p^2), exponential in m for fixed 0<p<1. A compact hash-output range does NOT imply a compact exact source-input prefix cover. This is a limitation of GGM **prefix-subtree restriction in the iid random-acceptance model**; not a lower bound for every circuit-constrained PRF or FE, and not a proof about concrete SHA pseudorandomness or QPT adversaries.

A global SHA Merkle commitment to z gives binding of supplied bits, not secret seed delivery. A public output-prefix seed remains accessible using h=0. An inaccessible IfVerifyOriginalThenReleaseSeed is precisely the missing cryptographic primitive; neither a normal software if-check nor an ordinary proof-of-correct-setup instantiates it. Adding specific burn/alternative source branches is not addressed by the PoW-only toy; the ORIGINAL three-ground OR must remain.

## Executed bounded checker
A Python3 standard library checker used SHA256d over a deterministic fictional header-input family with one 16-bit variable, leading 16 output bits <2^12. It exactly computes the minimal dyadic input-prefix cover of all accepted leaves and verifies no invalid leaves are included. Observed 4056 accepted toy headers; minimal input cover 3948 keys (3840 singletons and 108 size-two pairs), versus one hash-output prefix. h=0 trivially selects the output prefix without any source certificate. Independent expected-cover formula gives 3967.7499980926514 for m=16,p=1/16, including 3840 expected singletons. This is a synthetic census, NOT actual 80-byte PoW headers, contextual targets, accepted Bitcoin/Syscoin evidence, native signatures, FE, or any quantum experiment. An initial syntax-error run is not counted; the corrected final invocation exited zero.

Executed local checker SHA256: 0fb0daafdbf338e834417435d26517b34f3393022e434a74f27280d1730e3e8a.
Captured output SHA256: ce1eec83456c3eb55b89a505300b6835df479bdb0a81ef7badf7c1ffaf2e8200.

## Handoff
No actual classical-PPT source-conditioned Build_inc(x,S)->C / public Open_inc(C,z)=same frozen cancellation authorization for every qualified ORIGINAL z, no complete-public FALSE/hard-TRUE QPT simulator/extractor to an actual source certificate or independent hash/native break, no one-honest malicious setup composition and no source-work theorem were supplied.

Next candidate MUST independently instantiate a **source preimage-and-history-bound key dispenser** whose full public bytes are unusable with arbitrary target-range h, *before* adding GGM prefixes. It must also support all three independent OR challenge types and release the fixed claim-scoped safe native capability. Naming SourceBoundSeed or applying an external proof verifier is not an advance. Do not spend more passes changing prefix length or seed encoding without this source binding.

NONQUALIFYING. No user notification, PR comment, deployment, Core/production edit, approval, merge or automation change.
