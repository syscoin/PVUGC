# R168 checkpoint 2 — PoW class/certificate dichotomy and public XOR affine closure

**Status:** Two exact scoped construction exclusions, not a secure hash/PoW generic WKEM or a universal impossibility theorem. This work does not weaken or replace the ORIGINAL relation, prove QPT security, or justify returning to optimization.

## 1. Source semantic outcome versus complete work certificate

Let a pre-funded source claim select a canonical semantic child outcome O. The source can authenticate O using many alternative complete parent PoW/AuxPoW certificates W with distinct nonce, parent header, Merkle path, and anchor. `OutcomeID=H(claim,slot,child)` is not a cryptographic witness of authenticated parent work. `WorkID=H(canonical complete evidence)` is bound to one precise certificate. If a release ciphertext's decryption key is `H(OutcomeID)` or another completely public function of a finite, publicly enumerable outcome class, an adversary can compute the key on a fabricated certificate with the same semantic child without producing any valid ORIGINAL work evidence. A post-hoc source verifier cannot undo raw key recovery.

If instead ciphertexts are keyed by independent complete WorkIDs, Build must prepare one correction for each possible future certificate unless a new correlated multi-witness release primitive exists. In the ideal independent-hash model, let each n-bit nonce yield an h-leading-zero PoW success with probability 2^-h. The number M of syntactically valid nonce certificates is binomial Bin(2^n,2^-h), with expected 2^(n-h). When the eventual certificate is selected uniformly from that set, and an independent Build prepared q_B exact WorkIDs, its coverage is at most q_B/M. Without a correlation that maps fresh WorkIDs to precommitted K, every-witness release fails. Merely grouping WorkIDs into a polynomial number of public labels is not a repair: all labels are publicly enumerable, and CK or ordinary native signature verification lets an adversary test all candidate recovered keys. This theorem is restricted to *independent per-WorkID hash pads and publicly enumerable semantic buckets*, not arbitrary hash WE, and canonical chain membership must be modeled separately from syntactic PoW.

Executed `workid_vs_semantic.py` over four fully enumerated toy 16-bit nonce spaces with four-zero-bit SHA256 work target. Each contains 4,010–4,219 passing complete certificate hashes, yet 16 prepared WorkID entries cover only 16. A fabricated wrong-work certificate shares the semantic OutcomeID and so passes any raw semantic-only key derivation. 24 assertions. Neither this fixture nor R7 proves live Bitcoin best-chain validity or 128-bit PQ strength.

## 2. Universal affine closure in a *newly tested* XOR clause-mask attempt

An attempted hash-independent K release selects random K_j with K=⊕_j K_j. For every variable i and bit value b, choose independent per-occurrence masks R_{i,b,o} subject to ⊕_o R_{i,b,o}=0. For each 3CNF clause j and each **satisfying** local occurrence-bit pattern p, publicly release

    T_{j,p} = K_j ⊕ (⊕_{k=1}^3 R_{i_k,p_k,o_k}).

Any truly consistent global witness selects one row per clause. Every variable bit is the same at all occurrences, so all masks cancel and the public XOR is K: exact SAME-K correctness for arbitrary valid ORIGINAL witnesses. No source oracle, native Bitcoin verifier, or secret postcheck is needed to *run* this attempt. However the public XOR closure defeats the construction on **every** CNF formula, including fixed-FALSE instances:

For any global assignment v, each clause's local occurrence-bit pattern p(v) is either satisfying or the sole forbidden 3-bit pattern u. In the satisfying case choose the published row T_{j,p(v)}. In the forbidden case define e1=(1,0,0), e2=(0,1,0) and choose THREE published satisfying rows at patterns (u⊕e1), (u⊕e2), (u⊕e1⊕e2). Their XOR has odd K_j coefficient and exactly the same per-occurrence mask coefficients as the nonexistent row T_{j,u}, because

    (u⊕e1) ⊕ (u⊕e2) ⊕ (u⊕e1⊕e2) = u

and 3 is odd. Across all clauses, this gives the same mask cancellation as any globally consistent assignment, irrespective of whether its clauses are satisfied. Thus K is the public XOR of at most 3m published rows, **for every formula and every selected v**. This is an exact unconditional classical polynomial-time unauthorized recovery, not merely a toy random attack.

The independently executable `affine_closure_universal.py` checked this identity for 3,500 deterministic CNF fixtures, including 142 false formulas and varying variables, clause counts and signs. The earlier `constraint_mask_search.py` ran 3,600 samples; public linear algebra found K in the span for every tested TRUE and FALSE formula. These checks support the exact algebra but do not constitute a QPT proof. The candidate is rejected; adding a public hash of K does not prevent raw K recovery.

## 3. Why the next attempt must differ structurally

The two exclusions show where source-specific PoW *alone* fails in this normal form: semantic labels collapse authenticated work distinctions, certificate labels are too unpredictable for independent precomputed pads, and linear clause masks allow unauthorized affine combinations. Nonlinear source-consistency enforcement must be cryptographically inside the release, with a classical-PPT Build that does not know future work and a QPT full-public reduction from arbitrary capability recovery to an ACTUAL ORIGINAL witness or an independent quantum hash break. A hash-sealed finite state machine with public input choices has already shown exponential state growth; do not merely rename such a machine a compact proof. No proposal of online source signers/retained coins, R-only postchecking, helper SourceOpen or external PoW oracle counts as a repair.

### Exact executed local provenance

- `workid_vs_semantic.py`: SHA256 af4536db97871d95115a19680c5ba2be6102ab59ef5b6eecf83dfe3d5cea41bd; output SHA256 70358100dea0c526b5ba66cc140904dafbccaf8b373666187a7862de7899e11f.
- `constraint_mask_search.py`: SHA256 7859615944c00c6968ff04c2ad5bc4432adea6e35fdd1e7bcc3098422044917c; output SHA256 a9ecc3aa845ac40ca70e55e2858e9f9296bcc5982beb708ac680b0867b12c97f.
- `affine_closure_universal.py`: SHA256 e4d1698f28e08e430d9f7508a5bd3d0fd68de597c3762e2cd689d15cda228fd0; output SHA256 3f73126118bcac2f6ad06b8e5c931469025257f49adfcb4c5dda642b36cef823.

All executed locally/offline. Publication status of these local code files is separate from this note. No independent agent or external paper was used.
