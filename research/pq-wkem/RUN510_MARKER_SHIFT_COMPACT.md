# Run 510 — quantum hidden-shift leakage from two XOR-marker orbits

Research-only, October 14, 2026. Starting head 638673dec73785e05ca3b95ac5806d2983976106. New focused falsifier for a hypothetical *one-vector-action* compression of Run 507, not a security break of Run 507, RIO, CLZ, or a complete WKEM.

## Exact setup and honest semantics

The Run 507 guarded terminal has h separate bit-actions on (k,z,t), each disclosing one native signing-seed bit using an equality test after an ORIGINAL-valid witness. Consider a proposed compression to ONE reversible h-bit marker action:

  B(k,z,t) = (k,z,t XOR (k * f_x(z)))

where f_x is the genuine ORIGINAL relation, or a COMPLETE Run-259 representation predicate subject to its exact residual/SIS conditions. Publish a mixed terminal A_B=P B P^{-1}, marker translations M_j=P S_j P^{-1}, S_j(k,z,t)=(k,z,t XOR e_j), and source loader operations. This remains purely an ideal/conditional interface: no concrete classical-PPT mixer was built.

A valid ORIGINAL z, loaded from the source-specific anchor, produces y=P(K,z,0), and its terminal result is y'=A_B(y)=P(K,z,K). The marker group translates y by M_v=product of marker generators for 1-bits of v. The public marker generators are classical efficiently evaluable and can be run coherently by QPT attackers. The following exact theorem needs no randomness or hardness assumption on P.

## Theorem 1: exposed shifted pair implies polynomial quantum recovery

Assume the marker action is free on the orbit of y: M_u(y)=M_v(y) iff u=v. Given two public labels y and y'=M_d(y), define

  F(v)=M_v(y),    G(v)=M_v(y')=F(v XOR d).

F is injective. Define H(b,v)=F(v) if b=0, G(v) if b=1. H is exactly 2-to-1 with unique nonzero XOR period s=(1,d). Since the marker translations are public reversible classical algorithms, QPT adversaries implement a coherent H oracle. Simon's algorithm recovers d in O(h) H-queries, with O(h) marker evaluations per H-query and polynomial classical GF(2) solving. It needs no P inverse, native checking key, knowledge of a source witness, special quantum advice, or quantum rewinding.

For a measured output of H, the state is the two-point coset (|0,v>+|1,v XOR d>)/sqrt(2). After Hadamards, (alpha,beta) is uniform on alpha=<beta,d>. Each sample provides one uniform linear equation; after m>=h samples the EXACT recovery success is

  product_{i=0}^{h-1} (1 - 2^(i-m)),

with failure at most 2^(h-m). Hence h+c samples give failure at most 2^-c. Even with a 256-bit seed, this is polynomial quantum work, NOT a 2^128 Grover search, whenever the two related public labels and translations are exposed. This is a new two-orbit XOR-shift application of Simon, distinct from Run 501's approximate one-function periodicity analysis.

## Theorem 2: generic classical black-box readout is not practical

Let d be uniform in F_2^h and F be an independent uniformly random injective labeling. Grant classical evaluation-only access to F(v) and G(v)=F(v XOR d). For fixed F-query set A and G-query set B, let D={a XOR b : a in A,b in B}. A cross-orbit label collision identifies d iff d in D; otherwise, the remaining shifts are equiprobable. Thus the exact optimal success is

  min(1,(|D|+1)/2^h) <= min(1,(|A||B|+1)/2^h).

The standard deferred-decision/birthday argument gives Theta(2^(h/2)) classical query complexity for constant success in this *random opaque-label* two-orbit model. The bound does not apply to arbitrary inspectable correlated white-box circuits, which might leak even more. An ordinary classical watcher cannot efficiently decode one giant XOR displacement from generic hidden labels at h=192 or 256 without extra public information. Adding a decoder changes the public attack surface. Run 507's h individual equality-readable actions avoid THIS completeness barrier, but remain uninstantiated cryptographically.

## Exact soundness boundary

With an invalid z, f_x(z)=0 and y'=y, so Simon recovers the *effective shift zero*, not K. A correctly enforced source guard still requires ORIGINAL evidence; this result does NOT break false-instance hiding, recover the specific anchor K from arbitrary off-anchor states, or produce an unauthorized native signature. It does prove an unconditional QPT exposure risk for ANY source-independent public pair (y,M_K(y)) under the same public marker actions, including pairs inadvertently exposed by setup, cached release assistance, preauthorization, or related-capsule composition. The native checking key is unnecessary for the attack.

Attack families: no local seam, no gate fingerprint, and no inverse frame; instead the two public orbits synchronize their XOR gauge; chosen-input coherent evaluation and two-view/multiple-capsule leakage suffice. Malicious setup, public checking-key correlations, branch/UTXO reuse and source binding must be assessed separately. The theorem itself holds even against a perfect mixer.

## Exact checks, assumptions, references

The compact JavaScript checker and its captured output are from one deterministic function, executed twice byte-identically. An independent standard-library Python checker (local extended artifact) verified literal finite Fourier amplitudes with exact rational arithmetic and exhaustive tiny classical transcript success, also twice byte-identically. These validate algebra, not practical quantum resources, a concrete secure white-box mixer, or genuine QPT witness-KEM security.

Starting exact sources: Run 509 blob 44fe66f6265fd93b2e21ddd0f70b991b916948bc; Run 507 unreferenced commit 3363d237a42f6992b83c40cdcef7b2398c2eedf7, blob 68a408db82ae13abb01b487b2b70d05153e8121b; Run 259 blob c7f3b77f0273ca1cbe6f0b31c1a086b8eb3acbf2. Quantum method: Daniel Simon, On the Power of Quantum Computation, SIAM J. Comput. 26(5), 1474-1483 (1997), DOI 10.1137/S0097539796298637. A complete RIO/CLZ proof or errata review was not completed here.

Security ledger: honest real-world target remains classical-PPT setup/evaluation, arbitrary QPT attacker with all public keys, auxiliaries, multiple capsules and coherent evaluation. Such a construction remains UNPROVED. Still missing: efficiently obfuscated source-guarded terminal, full-public-output false-instance QPT hiding, unauthorized authorization -> ORIGINAL representation or independent QPT break, malicious N-of-N setup/abort and erasure, graph enforcement, multi-capsule security and concrete parameters. Conditional P2MR/SLH endpoint unchanged. Production unchanged; PR draft/unmerged; stop condition unmet.
