# Robust-distance sampled QAP and unique paired rank-release selection

**Checkpoint 2026-10-23. POSITIVE, PROVED HONEST-SETUP SUPPLIED-PAIR COMPONENT; NOT A SECURE PRACTICAL WKEM.**

## Exact prior and what changes

The current open/draft `syscoin/PVUGC#1` head was verified as `3b66eb3fe5926024520b67edf6d15edfba9d5edb` on `research/pq-wkem-validation-20260918` before work. This checkpoint extends, without replacing, the exact sampled Frobenius QAP (`sampled_frobenius_qap_20261023/sampled_qap.py`, blob `3c568a1035865a20a98a271fd1d9c186db20c755`), its original Frobenius interpolation (`qap_frobenius_projective_20261022/frobenius_qap.py`, blob `d5b35ae77076e0e6bbf927a41b819130ac84fead`), and the paired rank interface (`rank_threshold_20261023/RANK_THRESHOLD_COMPOSITION.md`, blob `a07925249d3f1681cd7122b0835e27d769cd5d5f`). The latter proved **supplied** representation -> ORIGINAL witness at `N=4L+h`, with `h=6752` in a 128-bit illustrative bound, yielding 11.886405060096 PB of public coefficient matrices. Arbitrary key-only / native-forgery -> representation is still unproved.

**NEW:** A robust-distance theorem says that honest public sampling of only 90 additional off-domain nodes makes **every** normalized invalid source violate at least 83 local gates, not merely one, simultaneously even against an adaptive observer of all public coefficients. The paired matrix's rank-distribution proof can use this distance to shrink the slack from `h=6752` to **`h=165`** while retaining supplied-representation ORIGINAL extraction. A separate, direct uniform-matrix lemma rejects **all wrong field keys** at this threshold: valid `Encode(w)` recovers the unique rank-accepted scalar K without a verifying-key lookup as a selection oracle. The same claim-bound native public key remains in the complete public output for transaction authorization and checking. The public matrix payload falls **10.33609307%** to **10.6578151704 PB**, still wildly impractical.

This is an information-theoretic, honest-setup, full-public-output **pair** soundness result, not a K-hiding reduction, and specifically **does not** close arbitrary K-only -> ORIGINAL extraction. Previous public-tensor attacks and the needed separate QPT release argument are not swept away.

## Explicit algorithms and complete public output

Let F=GF(q), q=2^κ, with an honestly committed complete original R1CS statement x, m rows, n free Boolean coordinates, and explicit Booleanity. The authenticated statement binds the ORIGINAL relation identity, claim/UTXO, challenge versus normal branch, anchors, cumulative-work window, context/epoch/replay domain, and the intended native verification key. It must not let a later actor substitute another relation after tail sampling. Let y=(z0,w,ρ) consist of k=n+m homogeneous SOURCE coordinates and a normalized source have z0=1.

**Setup/Build:** Select m original R1CS interpolation nodes t_i and m−1 fixed distinct off-domain nodes b_i. As in the exact predecessor, interpolate linear-form polynomials A_z(T), B_z(T), C_z(T), set Z(T)=∏(T−t_i), and use Frobenius variables ρ to encode arbitrary H_ρ(T)=Σ_{j=0}^{m−2}ρ_j²T^j. After the complete relation is fixed, draw r fresh distinct uniform off-domain nodes excluding the original and fixed nodes. `L=m−1+r`. At node e the public five linear forms give `(a,b,c,d,s)` with d=z0 and `ab+cd+s²=F_{z,H}(e)`. Use the predecessor's exact 8×8 gate

```
P(a,b,c,d,s)  = [[0,a,d,s], [a,0,s,c], [d,s,0,b], [s,c,b,0]]
P*(a,b,c,d,s) = [[0,b,c,s], [b,0,s,d], [c,s,0,a], [s,d,a,0]]
G_e(y)         = [[P, η_e(y) I_4], [0, P*]],
η_e(y)         = Σ_j η_ej y_j .
```

Choose independent uniform **secret** outer factors U_e∈F^(N×8), V_e∈F^(8×N), independent private affine coefficients η_ej∈F and claim-specific native seed/field capability K. Define `D=4L`, `N=D+h`, and publish **every** full coefficient matrix

`C_j = 1[j=0] K I_N + Σ_e U_e G_e(e_j) V_e`.

Also publish **all** source coefficients, original/fixed/random node locations, full native checking key/selector, statement and full relevant ceremony transcript and public graph bindings. No private factors, coins, leaked signing seed or online signer belong in the public output. Setup uses classical polynomial-time sampling over parameters but the enormous concrete size prevents practical deployment. The baseline is N-of-N honest erasure; malicious setup, retained-coin/keyless Build, abort fairness and ceremony/graph security remain unproved. No key path or native PQ opcode on Bitcoin is assumed deployed.

**Encode(w):** For any valid ORIGINAL witness, form z=(1,w), compute the exact quotient H_z=(A_z B_z+C_z)/Z of degree at most m−2, square-root its coefficients uniquely in F, and output y=(z,ρ). Distinct witnesses keep different y and possibly completely different intermediate matrices.

**Recover(y):** Evaluate `C(y)=Σ y_j C_j` entirely off chain. Compute its characteristic polynomial (or a suitably verified probabilistic minimal-polynomial procedure), factor over F, and, among its field roots λ, accept **the unique λ with** `rank(C(y)−λ I_N)≤D`. On the proved GoodSetup event, every valid ORIGINAL witness recovers the **same** K and no other field scalar can pass on *any* normalized y. Verify the claim-bound native public key before using K to produce an ordinary native transaction signature for the pre-authorized branch. No exhaustive scan over q is part of the large-field algorithm. Large evidence and y never appear in a Bitcoin verifier.

**SuppliedPairExtract(λ,y):** If y0=1 and the public rank threshold passes, return w; the simultaneous theorem below says λ=K and R(x,w)=1 except with the stated **setup** probability. This extractor requires the attacker to supply y. It cannot extract an ORIGINAL witness from a standalone K, signature, arbitrary proof, or arbitrary quantum state.

## Lemma 1: simultaneous robust off-domain distance (new)

Define the degree-at-most-2m−2 polynomial

`F_{z,H}(T) = A_z(T) B_z(T) + z0 C_z(T) + Z(T) H(T)`.

For z0=1, F≡0 **iff** z is an ORIGINAL valid witness and H is its unique correct quotient (because evaluating at all t_i gives every original R1CS residual, while Z is monic). Otherwise F is nonzero. For any normalized y, write v(y) for the number of violated constraints among all L fixed+random off-domain nodes.

Fix an integer 1≤T≤r, and abbreviate `A=m+T−2` and `d=q−2m+2−r`. Assume d>0, A<d, q≥2r(2m−2+r), and honest uniformly distinct tail draws independent of the already fixed source. Then

```
Pr_nodes[exists normalized nonvalid y with v(y)<T]
     ≤ q^(n−r+T−1) (q/d)^r A^r binom(m−1+r,T−1)
     ≤ 2 binom(m−1+r,T−1) A^r / q^(r−n−T+1).         (RD)
```

**Proof.** Choose s∈{0,…,T−1} fixed-node violations and their exact support S, with binom(m−1,s) choices. There are q^n normalized original z. For each z and S, demanding F=0 at all m−1−s fixed points imposes independent linear equations on the m−1 coefficients of H, because Z(b_i)≠0 and evaluation at m−1 distinct points is invertible. Hence at most q^s H's remain; this counts every possible adaptive SOURCE and does not assume a canonical witness. For each nonvalid (z,H), F is nonzero of degree≤2m−2 and has m−1−s known distinct fixed roots, so it has at most m−1+s≤A roots among the random-tail universe. To have fewer than T total violations, at least `r−(T−1−s)` tail draws must hit those roots. Union over their specified positions yields

`binom(r,T−1−s) (A/d)^(r−T+1+s)`.

Sum the products `q^(n+s) binom(m−1,s) binom(r,T−1−s) (A/d)^(r−T+1+s)` over s. Every summand is at most `q^(n−r+T−1)(q/d)^r A^r binom(m−1,s)binom(r,T−1−s)` because d≤qA. Vandermonde's identity gives the first bound. Finally the excluded-universe size is `e=2m−2+r`; Bernoulli `(1−e/q)^r≥1−re/q≥1/2` yields `(q/d)^r≤2`. This is a setup event over **all** q^(k−1) normalized y, so no oracle/rewinding extraction or assumption about later classical/quantum choice of y enters. □

The prior sampled theorem only certified T=1. We count low fixed-node violations separately, recovering a much larger minimum distance with nearly the same r. A deterministic Reed–Solomon minimum-distance claim would be invalid for this r<m; the randomized and statement-committed quantifiers are essential.

## Lemma 2: use the distance to reduce matrix padding (new)

As proved in the predecessor, the paired G_e has rank four when its node equation is satisfied and z0=1; it has rank eight when violated, independently of η. Thus its direct sum has rank `R_y=D+4v(y)`. For fixed y and η, independent uniform two-sided outer factors imply

`M(y)=C(y)−K I_N ≡_d A_R B_R`, with `A_R←F^(N×R)`, `B_R←F^(R×N)` independent uniform and `R=R_y`.

Let h=N−D and suppose v(y)≥T with 4T≥2h. Then R≥N+h. Write u=R−N≥h. For A_R of row-rank N−a, the elementary rectangular random-matrix kernel bound gives, for a≥1,

`Pr[rank A_R ≤N−a] ≤ γ_q q^(−a(u+a))`, `γ_q=∏_{j≥1}(1−q^(−j))^(−1)<4`.

Conditional on rank(A_R)=N−a, its product with uniform B_R has the nonzero-row distribution of an independent uniform (N−a)×N matrix. If a≤h, to have `rank M≤N−h` this matrix must lose at least h−a rows, an event of probability ≤`γ_q q^(−h(h−a))`; for a>h the rank of A_R itself must already lose h+1 rows. Splitting the a=0, 1≤a≤h and a≥h+1 cases yields

```
Pr[rank M(y)≤D | v(y)≥T]
 ≤ (2γ_q + γ_q² h) q^(−h²)
 < 16(h+1) q^(−h²).                           (RANK)
```

The middle terms are at most `γ_q² q^(−h²−a(u−h+a))` because u≥h; the a≥h+1 tail is bounded by `γ_q q^(-(h+1)(u+h+1))`. Unioning all q^(k−1) normalized sources after public disclosure gives

`ε_rank ≤ 16(h+1) q^(k−1−h²)`.

Combining the RD setup event and this independent full-public-output event proves that **every normalized representation passing the true-key rank threshold is an ORIGINAL witness** with error ≤ε_RD+ε_rank. The robust gap is what permits h≈sqrt(k) instead of h≈k/4, without a new release oracle. □

## Lemma 3: every wrong field key fails the public rank selector (new)

Fix normalized y, a nonzero δ∈F, and any R_y. For a fixed h-dimensional subspace W≤F^N, `M(y)|_W=δ·id_W` is impossible if B_R|_W has rank<h. Otherwise, conditional on the full-rank B_R|_W, the independently uniform A_R maps its h independent columns to **uniform** N×h values, so the event has probability exactly q^(−Nh). The number of h-subspaces is at most γ_q q^(h(N−h)). Thus

`Pr[rank(M(y)−δ I_N)≤N−h] ≤γ_q q^(−h²)`.

Union over all normalized y and all nonzero δ, including adaptively selected candidates after inspecting the complete coefficient tensor, yields

`ε_wrong ≤γ_q q^(k−h²)<4q^(k−h²).`                        (UNIQUE)

Therefore every rank-accepted **pair** (y,λ) has λ=K and, by Lemmas 1–2, an ORIGINAL witness, except with setup probability bounded by `ε_RD+ε_rank+ε_wrong`. Unlike a native-checking-key correlation assumption, this claim uses only the actual independent public-matrix distribution, and the theorem works even if the attacker knows the native checking key. It does **not** say a QPT adversary cannot recover K alone from the matrices. □

## Large exact certificate, resources and reproduction

For q=2^256, n=11,000, m=16,000, k=27,000, choose **T=83, h=165, r=11,726** (compared with prior r=11,636). Then `L=27,725`, `D=110,900`, `N=111,065`; `4T=332≥330=2h`, `h²=27,225>k`. In `robust_distance_check.py`, arbitrary-precision integers verify **without floating-point approximations**

```
(2 binom(m−1+r,T−1) (m+T−2)^r) · 2^212
    < (2^256)^(r−n−T+1).
16(h+1)·2^130 < (2^256)^(h²−k+1).
4·2^130 < (2^256)^(h²−k).
```

Consequently `ε_RD<2^−212`, both ε_rank and ε_wrong <2^−130, and their total is <2^−128, **for honest-setup supplied (y,λ) semantic soundness only**. The checker also confirms r−1 does not satisfy this same conservative 2^−129 RD certificate; no claim of a global r optimum is made.

Raw coefficient storage is `kN²` field elements, or **10,657,815,170,400,000 bytes = 10.6578151704 decimal PB**, versus prior `11,886,405,060,096,000 bytes = 11.886405060096 PB`. Saving: **1,228,589,889,696,000 bytes (10.33609307%)**. This is not remotely a practical implementation. Actual setup time/memory, proof/signature overhead, native authorization and graph construction are additional. The toy test is an explicit 3-gate synthetic relation with every invalid y violating at least two distinct gates. It exhaustively tests 256 normalized source inputs ×16 candidate λ, for two independent uniform fixture seeds: 8,192 public key+input rank decisions, 0 invalid/wrong-pair acceptances, two valid distinct witnesses sharing one K per seed; **9,216 Python assertions**. GF(16) fixture RNG is deterministic and insecure; this is a regression, not the QPT proof. The large RD/RANK/UNIQUE inequalities are independently derived above and certified with exact integers.

Run in a repository checkout: `OPENBLAS_NUM_THREADS=1 python research/pq-wkem/robust_distance_20261023/robust_distance_check.py > /tmp/robust-distance-validation.json`; byte-compare with captured `validation.json`. Python 3 and NumPy required. The companion `PROVENANCE.json` pins the tested input hashes and read-back commit after publication if a publication occurs.

## Missing security proof and honest interface boundary

**NOT PROVED:** false-instance full-public-output QPT secrecy of K; arbitrary unauthorized **K-only** recovery or accepted native signature forgery -> rank-accepted (λ,y) or an independently motivated QPT-hardness break; malicious N-of-N setup / abort / retained secrets; coherent multi-capsule/related-statement / chosen-input/auxiliary-key attacks; realistic public package; deployed P2MR-like + native SLH verification; censorship-aware 1-of-N watcher enforcement and covenant graph. The supplied-pair extraction theorem is not an iO/WE/RIO implementation or a QPT key-security reduction. The old Run 259 SOURCE theorem applies only after its exact accepted-source interface is obtained; this rank proof supplies such an interface for *pairs*, not for bare key recovery. No public coefficient tensor is assumed secure merely because its former four-moment attack no longer applies.

**Exact next missing implication, unchanged:** for all QPT A with the full coefficient tensor, native checking key and arbitrary auxiliary information, establish (without presupposing WE security) that an unauthorized output of native capability K or accepted signature yields a supplied accepted pair (λ,y) with λ=K, or an explicit standard independently supported QPT-hardness violation. Until then, the paired carrier is a candidate, not a secure WKEM, and no task should be disabled.
