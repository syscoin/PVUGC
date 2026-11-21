# R168 — intermediate: finite-field Booleanity-gated release
Status: construction/repair in progress, NOT a witness-KEM, security proof, or source compiler. No lattice, group, web literature, online authority, compression or deployment.

Continuity: syscoin/PVUGC PR #1, open/draft, research/pq-wkem-validation-20260918, observed start HEAD 6c1b9488288390fdb1273302f788a97eebb0498a. Read R167 RESEARCH.md blob 475e3b573b5df83a6e2d460898cbb5bc9abbc6cc, and recent ordinary comments (none). R167's polynomially bounded explicit hash-tag dictionary cannot efficiently enroll unknown accepting sources; no work here treats its query-transcript lemma as a generic WE solution.

Single construction test: Given original Boolean verifier R_original(x,w) with n-bit certificate and its arithmetization V_x(z) over prime F_q, define
    I_q(z)=product_i [1 - (z_i(z_i-1))^(q-1)].
    A_x(z)=I_q(z)*V_x(z).
By Fermat, I_q(z)=1 exactly for z_i∈{0,1} for all i and 0 elsewhere. Assuming Boolean-correct V_x, A_x(z) is 1 iff z is a COMPLETE valid ORIGINAL witness, and zero on every other field vector. It is computed by a polynomial-size arithmetic CIRCUIT, not by a compact *hidden* encoding.

Attempt frozen-key release with K uniform in F_q and random mask T:
    F_{x,K,T}(z)=K*A_x(z)+(1-A_x(z))*T(z).
Then F=K for every valid original witness and F=T for every invalid input, including non-Boolean field points where raw V_x=1. This fixes the elementary off-Boolean probe at the mathematical function level without assuming an oracle that verifies witnesses on access.

Research question, not yet solved: how can honest classical-PPT Build publish a *compact, secure* representation of this function without including readable K constants? The straightforward arithmetic circuit visibly includes K. A full reduced-coefficient representation has q^n entries and supports a public multiplication attack. Commitment roots alone do not supply evaluations and their authenticated openings to every future original witness without an online issuer or enormous precomputation.

The executed local checker / final mathematical treatment will test finite q=7,13 cases, idempotence A*A=A, and the public-coefficient extraction identity F*A=K*A. No assertion of QPT security, native signature release, actual Syscoin/BTC authentication, malicious setup composition, or ordinary PR-comment threshold.