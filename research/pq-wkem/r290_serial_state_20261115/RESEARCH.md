# R290 — Serialized hash-garbled state: repeat-read coherence (NONQUALIFYING)

## Continuation and provenance
PVUGC PR #1 on research/pq-wkem-validation-20260918, start head 9f75285203d561087603449771bd0eca990541b4 (R289 blob b68a3104900ba2c0fb0c544d567f00aca0622e40); Core #609 observed head c91539de3c34937e57d7f5fda47c7b0502ff33f6. Last relevant ordinary comment R225 #6796383617. Connected GitHub reads and bounded local standard-library Python only; no external sites, Core test, quantum experiment, production change, deployment or network claim.

This **does not** implement ORIGINAL three-OR-branch source challenges, authentic parent certificates, modern contextual AuxPoW or native signing. No secure WE, no generic impossibility claim.

## Attempt: make the public evaluator serial, not spliceable at parallel cuts
In R289, parallel clause garbling lets an adversary combine legal labels from different witness evaluations. Replace it by one active encrypted state label at a time. For transition T_j(q,b), sample hidden 256-bit state labels L[j,q], publish both input labels I[j,b] and

    C[j,q,b] = L[j+1,T_j(q,b)] XOR SHA256("pad"||j||L[j,q]||I[j,b])
    selector = Trunc128 SHA256("select"||j||L[j,q]||I[j,b]).

Publish only L[0,start], encrypted transition table, external input labels, and

    E = K XOR SHA256("seal"||L[final,ACCEPT]).

The evaluator selects an input bit at each stage, traverses its one active state label, and can recover the same frozen K on an accepting traversal. Build is polynomial **in the explicitly enumerated state machine**. This removes R289's multi-cut patching without positing an online signer.

## Executed FALSE public recovery
Use the unsatisfiable *single complete witness* relation (x=y) AND (x!=y). The synthetic state machine reads four positions (x1,y1,x2,y2), checks equality of the first pair, then inequality of the second. Every honest consistent encoding (x,y,x,y) rejects. An arbitrary public evaluator may instead choose (0,0,0,1) and reach ACCEPT, recovering K. It knows none of the unexposed state labels or K. Thus serializing gates removes cut-splicing but does **not** enforce repeated-bit consistency; source validity cannot be postponed to a separate if-check.

## State/memory repair and exact restricted lower bound
Remember earlier witness bits inside the active state so second occurrences cannot change. This is semantically sufficient for consistent inputs. But the deterministic one-pass copy language COPY_n={u||u : u in {0,1}^n} has >=2^n distinguishable states after its first n reads: if two distinct prefixes u!=v reached the same state, appending u would both accept u||u and accept v||u, contradiction. Hence an *explicit one-hidden-label-per-state table* for COPY_n is exponential. It is not a lower bound for arbitrary obfuscation or real Bitcoin/Syscoin verification.

SHA/Merkle transcript commitments give a genuine **semantic** alternative: bind every claimed indexed witness bit under one root t, with canonical path/direction/height. Two conflicting authenticated values at the same index/root straightforwardly yield a hash collision by following the paths upward to the first divergent hash input. This is a straight-line collision *extraction from supplied classical openings*, including openings output by a QPT algorithm; it assumes hash collision hardness, rather than proving it for concrete SHA.

But secret release remains uninstantiated. For a *future* certificate-dependent root t, consider

    L[j,q,t]=SHA256("state"||secret_seed[j,q]||t)
    C[j,q,b,t]=L[j+1,T_j(q,b),t] XOR H(L[j,q,t],I[j,b]).

Build cannot publish a single static row at t0 that works for every future t. Disclosing the hidden seed allows public derivation of the accepting label and K without an ORIGINAL certificate. An opaque future-tag row generator assumes, rather than constructs, the missing hash-only source release.

## Executed local evidence
Python 3 standard-library SHA256 checker, 64 deterministic tapes: 256 honest consistent input evaluations rejected; 256 inconsistent public paths recovered K on a FALSE relation. 4,096 pairwise SHA commitment-equality checks and 128 static-row/future-tag mismatches. Two byte-identical executions; 4,809 assertions each. The checker uses synthetic tapes and a 256-bit payload surrogate; no real AuxPoW, Bitcoin membership, malicious ceremony, native PQ signature, QPT adversary or full-source witness proof.

checker.py SHA256 468713a94d2dd9d381dea8ec94609942f9f7cd1a6d88092a32b2b0b27bc25be6
run1.json = run2.json SHA256 5e8daec7a9a6d81247be815dc3e70021d0b35d1f0f237464c95abee82f264c17
Local-only complete checker, captured runs and full proof: R290_bp_consistency_20261115.tar.gz SHA256 9920c71417514f1c187a044c588000c186dc7d1faf4892e0c27323e0a36260aa. These bytes are not claimed to be present in this repository.

## Unresolved next equation
Instantiate a fixed-size, public classical-PPT RowEval with an **unexposed** root-coherent state for *arbitrary future ORIGINAL authenticated certificate roots*, correct for EVERY qualifying witness and inaccessible on complete-public FALSE/hard-TRUE states, rather than merely verifying public t after recovering secret labels. The R290 state-machine/commitment composition does not construct RowEval or its joint-public QPT reduction. No notification/completion/automation stop warranted.
