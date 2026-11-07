# Run 77 — standard-LWE directional transport composes, but public verifier branching collapses to forward closure or state explosion

**Status:** constructive composition of the positive Run-72 LWE transport with a verifier-state capability graph; exact global forward-closure theorem; branch-credential audit; scoped state-size lower bound. **Not a completed generic-NP public offline PQ witness KEM.**

Starting verified PR head: `bae74cbc16fd07255d9ddb430c1d6d460aa7b195`.

No external literature/web search was used. Production code is unchanged.

## 1. Starting point

Run 72 proved a useful native primitive under ordinary search-LWE:

* if a high-entropy parent capability `s_u` already exists,
* a public bitwise LWE token can transport it one-way to a child capability `s_v`,
* the holder of `s_u` recovers `s_v`,
* recovering the missing parent after the child is revealed is exactly a search-LWE instance.

Runs 73–76 then isolated the unresolved part: obtaining the **source** capability from a witness without exposing both local alternatives, affine pseudorepresentations, or an assumed witness-encryption compiler.

A natural reaction to Run 71 is therefore:

> keep the now-clean Run-72 one-way edge transport, but put those transports on the directed state graph of a verifier.

This run audits that composition.

The result is a simple but important separation:

> one-wayness of each edge does not imply witness restriction of the whole branching program.

If the parent capability alone opens every outgoing edge, a holder of the start capability can forward-close the whole polynomial-size graph.

## 2. Constructive candidate: capability branching program

Let

\[
G_x=(V,E)
\]

be a layered verifier graph for public statement `x`.

There is a public root `r`, a set of accepting states `A`, and each edge is labeled by a local witness choice, for example a bit `b`.

Setup chooses an independent high-entropy capability

\[
s_v\in\mathbb Z_q^d
\]

for every state `v`.

For each edge

\[
e=(u\xrightarrow{b}v)
\]

publish the Run-72 directional token

\[
\tau_e=\mathsf{LWETransport}(s_u,s_v).
\]

The start capability `s_r` is made available to the evaluator.

A valid witness follows the verifier path. At each step it applies the public Run-72 decoder to the token selected by its next witness bit and obtains the next state capability. When it reaches an accepting node, that capability can either be the KEM parent itself or can unlock a final Run-72 transport to the common key.

### Local cryptographic property

This candidate does **not** reopen the Run-71 reverse-edge problem.

For one isolated token, Run 72 already gives the exact search-LWE reduction for recovery of the missing parent. The present failure is global and forward-only.

## 3. Forward-closure theorem

### Theorem 1 — explicit public capability graphs are forward-closed

Let `G=(V,E)` be a public directed graph with root `r`. For every node `v` let `s_v` be a capability. For every edge `e=(u,v)` let public token `tau_e` and polynomial-time decoder `D_e` satisfy

\[
D_e(s_u,\tau_e)=s_v
\]

whenever the edge token was honestly generated.

If `s_r` is public, then there is a polynomial-time algorithm which computes `s_v` for **every graph-reachable node** `v`.

### Proof

Run ordinary graph search.

Initialize

\[
\mathcal K=\{(r,s_r)\}.
\]

Whenever a known node `u` is processed, enumerate its public outgoing edges. For each edge `(u,v)`, compute

\[
s_v=D_{(u,v)}(s_u,\tau_{(u,v)}).
\]

Insert a previously unseen `v` into the queue.

Every reachable node has a finite directed path from `r`. Induction on path length shows its capability is eventually recovered. Runtime is

\[
O(|E|\,T_D).
\]

For bounded-error Run-72 tokens with deterministic decoding margin, this is exact. With per-edge correctness failure at most `epsilon`, a direct union bound gives global failure at most `|E| epsilon`. ∎

### Corollary 1 — accepting capability and path recovery

If some accepting state `a` is reachable, the same search obtains `s_a`.

Keeping predecessor pointers also returns an explicit accepting path.

If edge labels encode witness choices and the graph is a sound verifier graph, that path gives a source witness or the verifier transcript from which the witness is reconstructed.

Thus this is **not** a key-only attack. It is source-witness extraction.

That distinction matters.

## 4. Why this still kills the candidate for a hard generic-NP source relation

The requested WKEM is useful only when the source witness is not already efficiently obtainable from the encapsulation.

For the candidate above, the ciphertext itself plus the public start capability implements a polynomial-time source-search algorithm whenever the explicit graph is polynomial-size:

1. construct/receive the graph and tokens;
2. forward-close it by Theorem 1;
3. stop at an accepting node;
4. return the recorded path/witness.

The LWE assumption is never attacked. Every edge is used in its intended forward direction.

For a compiler whose accepting paths are exactly the witnesses of a generic hard NP search relation, a polynomial-size explicit graph of this form therefore trivializes the source search problem after encapsulation.

This is compatible with the *logical* statement “key recovery implies witness extraction,” but only vacuously useful: the public ciphertext makes the witness extractable before any special key adversary is needed.

In particular, one cannot claim this as a practical witness-restricted release mechanism merely because reverse edge traversal is LWE-hard.

## 5. Complete-public-output attack algorithm

The complete transcript contains:

* the public state/edge indexing;
* every edge token;
* the start capability;
* the accepting-state designation or final token.

The attacker never guesses an LWE secret and never invokes a reverse decoder.

Pseudo-code:

```text
known[root] = s_root
queue = [root]

while queue nonempty:
    u = pop(queue)
    for (u --b--> v) in public outgoing edges:
        candidate = LWE_Dec(known[u], token[u,b])
        if v unseen:
            known[v] = candidate
            predecessor[v] = (u,b)
            push(v)

if an accepting v is known:
    reconstruct the path using predecessor[]
    output its accepting capability / final key and the path
```

The local checker implements exactly this algorithm using fresh bounded-error Run-72-style tokens.

## 6. Natural repair: use a branch credential and the Run-72 AND transport

Run 72 also supports a `k`-parent/AND transport.

So try to make an edge require both

\[
(s_u,\ell_{i,b})
\]

where `ell_{i,b}` is a credential for the witness bit.

Publish

\[
\tau_{u,b}=
\mathsf{ANDTransport}
((s_u,\ell_{i,b}),s_v).
\]

This does not by itself solve the source layer.

### Case A — both branch credentials are public

Then Theorem 1 applies unchanged: at every state the attacker possesses both `ell_{i,0}` and `ell_{i,1}` and opens both edges.

The checker tests this exact construction on 300 fresh graphs and obtains an accepting state in all 300.

### Case B — the credential is publicly derived from the raw bit

For example,

\[
\ell_{i,b}=H(i,b)
\]

with public `H`.

There are exactly two candidates and the attacker computes both. Cryptographic stretching of a one-bit public choice does not create entropy or authorization.

### Case C — `ell_{i,0},ell_{i,1}` are random hidden labels

Now the LWE AND edge would be useful **if the legitimate witness could obtain exactly the label matching its bit**.

But setup has no witness and nobody is online after setup. Supplying that selected random label is exactly the source input-label transfer problem already separated in the earlier record.

Publishing both labels returns to Case A.

Hiding both labels makes honest decapsulation impossible.

Adding an assumed public mechanism which delivers exactly one hidden label from a witness bit simply renames the missing source primitive.

So the positive Run-72 AND transport composes cleanly *after* branch authorization, but it does not manufacture that authorization.

## 7. Avoiding forward closure by refusing state merges

One way to keep a witness path cheap while making blind exploration expensive is to give every witness prefix its own state.

At depth `n`, the complete binary prefix tree has

\[
2^{n+1}-1
\]

nodes and

\[
2^{n+1}-2
\]

edges.

A valid witness traverses only `n` edges, whereas exhaustive exploration is exponential.

But if every edge has an independently randomized destination capability and therefore needs its own Run-72 token, the **public ciphertext is exponential too**.

For the checker’s deliberately small finite parameters (`d=4`, `q=4093`), each edge token already contains

\[
d\lceil\log_2 q\rceil=48
\]

LWE samples. The validation file records symbolic residue counts through depth 128. These are resource controls only, not production/security parameters.

A globally compact public transition function could avoid one token per prefix, but then it must update/merge a hidden verifier state without exposing a polynomial explicit forward-closure graph. That is a different primitive; ordinary Run-72 point-to-point transport does not provide it.

## 8. Exact state-size control: separated equality

The need to remember witness history is not only a counting artifact of the full binary tree.

Consider the relation

\[
\mathrm{EQ}_n(a,b)=1\iff a=b
\]

under the read order

\[
a_1,\ldots,a_n,b_1,\ldots,b_n.
\]

### Theorem 2 — width `2^n` at the midpoint

After the first `n` bits have been read, every possible value `a` must correspond to a distinct deterministic state.

Proof: suppose two distinct prefixes `a != a'` reach the same state. Feed suffix `b=a`. The computation starting from prefix `a` must accept, while the computation starting from `a'` must reject. From the same state and same suffix a deterministic program cannot do both. Contradiction. ∎

Therefore any deterministic branching representation in this separated order has width at least

\[
2^n
\]

at that cut.

The checker verifies the `2^n` distinct residual functions for `n=1,...,12`, totaling 8,190 midpoint states.

### Scope

This is **not** an all-order lower bound for equality; interleaving `a_i,b_i` makes equality small-state.

It is a concrete control showing that “just put consistency in the verifier state” can require exponential state when dependencies are separated. No general OBDD lower bound or generic-NP impossibility theorem is claimed here.

## 9. The actual dichotomy exposed by the composition

The candidate produces a useful three-way boundary.

### Polynomial explicit state graph

If a parent capability opens every outgoing transition, forward closure is polynomial and recovers any accepting path.

### Prefix-distinct state graph

Blind search can be exponential, but independently randomized per-prefix capabilities/tokens make the public representation exponential.

### Compact witness-selected merge

This is the only interesting escape.

It must:

* let one witness path advance in polynomial time;
* prevent a root holder from cheaply advancing all alternatives;
* merge many histories into compact verifier state;
* preserve one common accepting key;
* remain entirely public/offline after setup;
* not require setup to know a witness;
* and reduce its complete public representation to an independently justified PQ assumption.

That is precisely the source restriction still missing after Run 76.

Calling it an “LWE branching program” does not obtain it from ordinary LWE edge transport.

## 10. Fresh implementation and validation

`lwe_branching_forward_closure_run77_check.py` is deterministic and standard-library-only.

It was executed twice; the two JSON captures were byte-identical.

The captured run validates:

* 1,200 fresh bounded-error Run-72-style edge decodes;
* 350 random true explicit layered graphs, with accepting capability recovered in all 350;
* 10,772 recovered reachable node capabilities, all byte-for-byte/equality identical to setup’s hidden node capability;
* all 350 recovered accepting paths replayed successfully;
* 350 false controls with isolated accepting nodes and zero accept hits;
* 300 `AND(parent, public-branch-label)` graph controls, with accepting state recovered in all 300 and 7,153 exact reachable-capability matches;
* 2,000 exhaustive raw-bit credential candidate trials (`0` and `1`);
* exact separated-equality width `2^n` for every `n=1,...,12`;
* symbolic full-prefix-tree resource counts through depth 128.

The finite tests validate the implementation, forward-closure identities, and resource counts only.

They do not prove LWE hardness. The edge one-way statement is inherited from the explicit Run-72 reduction.

## 11. What is proved and what remains open

### Proved here

1. Exact forward closure for any explicit public capability graph whose parent capability alone enables every outgoing edge.
2. Exact accepting-path/source-path recovery in such a polynomial-size graph.
3. Public or raw-bit-derived branch credentials do not change the closure result when used with the Run-72 multi-parent transport.
4. Per-prefix independent capability unrolling gives exponential public state/token count.
5. Separated equality requires width `2^n` for deterministic state merging at the midpoint.

### Constructed and implemented

A full finite capability graph using the same algebraic Run-72 LWE transport shape, plus the AND-credential repair and BFS attacker.

### Not proved

This run does **not** prove:

* impossibility of every compact cryptographic branching program;
* impossibility of a hidden-state/noisy lattice merge primitive;
* a generic-NP lower bound on every branching-program ordering;
* an LWE break;
* a completed masked-verifier compiler;
* malicious-secure ceremony composition or final practical parameters.

## 12. Precise handoff

Run 72 solved native one-way **edge transport**.

Run 77 shows why simply wiring those edges into a verifier does not solve **source selection**:

* explicit polynomial state gives public forward closure;
* branch labels derived from raw witness bits give both branches;
* independent prefix state avoids closure only by expanding the public representation;
* a compact merge/update that keeps branch authorization witness-restricted is still missing.

The next constructive target is therefore narrower than “put LWE on a branching program”:

> construct a compact PQ hidden-state transition/merge primitive whose public evaluator can advance one witness-selected history, but for which advancing enough inconsistent histories to reach the common accepting key yields a source witness or breaks ordinary LWE/LWR/SIS (or another independently justified PQ assumption).

The proof must cover the **complete public representation**, not only reverse security of each edge.

If that primitive is obtained, the Run-76 ideal-oracle QPT extraction theorem and the Run-72 downstream transport remain reusable components. The generic-NP WKEM stopping condition is not met.
