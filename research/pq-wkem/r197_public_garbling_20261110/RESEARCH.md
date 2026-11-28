# R197 — public-source-input SHA garbling: a candidate and its provenance-repair test

**STATUS: unsafe family; not a hash-only ORIGINAL Build/Open, not a source verifier or QPT security result. No progress report warranted.**

## Continuity and verified test provenance

- syscoin/PVUGC PR #1; open/draft branch research/pq-wkem-validation-20260918.
- Starting branch SHA 349fbdb646bd5ae3cdceaae56a76f32f7ee986b7, R196; read the exact R196 RESEARCH.md at that SHA. Latest relevant ordinary comments since 2026-11-10T04:00Z: none returned.
- An intermediate checkpoint was written locally before test execution, then published as commit 726216f2b4267d85bfe007e8e04b7431564a0666. Source file checker.py SHA256 f1a39e682e82eeb3e26be1a9a901edaba84a4bd702bbfc3790ebceb20ee28905, Git blob f28649c39711c930c1d790fce91789bb70b3676d. Exact captured output SHA256 728dcfa6fc5491c6739f7c5b66661a973fc3ea3b5975b6d6e9432d000654bb96, Git blob ca6d43eba12ff6289b9de2a212e0be2d7129463c. Executed twice locally, outputs byte-identical; 600 functional assertions.
- No external research or web, no native signing, no real Bitcoin/Syscoin source verification, no source mining, no independent agent, no QPT simulation. Only the authorized research directory is changed.

## Exact proposed hash-only release construction

Given fixed original claim x and a bounded Boolean checker C_x(w) for the ORIGINAL BTC-work, PoB, or Syscoin-prefix/tag inconsistency challenge, let each wire v carry 256-bit labels L[v,0] and L[v,1]. For a two-input gate g(u,v) outputting t, setup creates SHA-domain-separated garbled rows

    T[g,a,b] = L[t,g(a,b)] XOR H("gate",g,L[u,a],L[v,b]).

A one-input gate has analogous rows. Domain-separated SHA and point-and-permute bits select the corresponding encrypted row. Publish both labels for every witness INPUT bit (because any future permissionless challenger must supply freely chosen ORIGINAL evidence), all garbled tables, a public checking hash CK=Hcheck(K), and a fixed cancellation ciphertext

    E = K XOR Hpad(L[accept,1]).

Build is classical polynomial in the checker size. Honest Open follows a single input witness assignment through the garbled circuit; each valid witness ends at the SAME accept-1 label, hence recovers exactly the SAME precommitted K. This is an actual functional proposed algorithm on a Boolean circuit, not a claimed secure WKEM. Its full source checker is only conceptual in this run; the bounded implemented circuit is deliberately one bit.

## Deterministic false-instance attack and exact closure criterion

Choose C(b) = (NOT b) AND b. There is no globally satisfying b. Honest executions on b=0 and b=1 each yield accept=0. But both public input labels allow the adversary to independently evaluate the NOT gate at b=0, yielding the first child's true label, and the identity gate at b=1, yielding the second child's true label. Combining those labels decrypts the AND gate's accept-1 row, recovers K and validates CK. Neither a SHA collision/preimage nor an ORIGINAL source witness is needed. The checker reproduced this direct unauthorized recovery for 120 seeds.

General family statement: let S_v denote the set of labels obtainable at wire v. Initially all publicly disclosed witness input labels are in S_v. For every locally decipherable garbled gate g(u,v) define

    S_out(g) = { Decode_g(a,b) : a in S_u, b in S_v, corresponding row exists }.

Each wire has at most two intended labels, so this Cartesian-product dynamic program runs in time linear in gate count up to a constant factor. It computes LOCAL label reachability, NOT reachability by any SINGLE globally consistent witness assignment. If L[accept,1] enters S_accept, the public ciphertext and checking key expose K. The explicit fixture proves that the criterion can hold for a FALSE relation. This is the known occurrence-mixing problem in a concrete candidate; it is not a general impossibility theorem for nonblackbox SHA cryptography. Some constant-output circuits may not saturate.

This is a straight-line CLASSICAL attack, therefore also a QPT attack, without a random-oracle query bound. Adding additional SHA/AuxPoW/PoB gates with labels open to both inputs does not by itself enforce global source provenance.

## Attempted hash-of-original-witness provenance repair

Try salting each gate pad with one global transcript digest t(w)=H("witness-global",x,w):

    P_g(t,a,b) = H("salted-pad",t,a,b).

Builder must publish fixed gate tables before the future challenge witness is known. If it uses setup-fixed t0, then a different but equally valid future witness w1 has t1 != t0 and its gate decryption fails. The checker implements a constant-TRUE 1-bit relation (both witnesses valid) and demonstrates t0-table correctness for w0 but failure for w1. Conversely, using a publicly chosen t as a free input to a universal row evaluator does not make t source-authentic; the holder can choose fabricated evidence labels and mix locally. Enumerating all future 256-bit transcript salts is not a polynomial-size Build.

Thus this exact attempted repair either loses EVERY-witness correctness or needs the unbuilt universal source-dependent hidden-label compiler. This conclusion concerns only the specified row equations, not every possible hash-only WKEM.

## Exact missing algorithm and next attempt

A qualifying original BTC-work, burn-fault, or SYS inconsistency witness must confer *nonmixable globally source-authenticated input-label access* without an online signer, issuer, or a static table over all future witness hashes. It must cause all valid witnesses to recover ONE frozen native cancellation signature per honest N-of-N setup participant, while raw public code, unrelated private work and contradictory local fragments fail. The source SHA/AuxPoW/coinbase/Merkle/ancestor proof must enter that cryptographic release, rather than appear only in an honest evaluator's if-condition.

A true repair must specify Build_inc(R_original,x,sigma) and Open_inc(C,w), and independently establish the full-public joint QPT FALSE/hard-TRUE recovery-to-actual-ORIGINAL-certificate or PQ hash/native forgery reduction. The current capsule has neither the secure source-to-label interface nor that theorem. N-of-N ceremony and one-notary runtime activation are unchanged.

No ordinary PR progress comment is warranted under the reporting threshold. This file is a negative candidate checkpoint preserved to avoid repetition.
