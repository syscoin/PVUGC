# 2026-11-24 UTC — hidden-basis noninvertible exterior transport (NONQUALIFYING)

## Continuity and preselection

Actual syscoin/PVUGC PR #1 open, draft, unmerged; same-repository branch research/pq-wkem-validation-20260918; start a332c601a5d37723a689e1df28fb57892d684b16. Read metadata, latest substantive discussion including R225, exact-head SOURCE_OR_PROOF_CHALLENGE_EXCHANGE_20261124.md (blob 6ce531386e54a095bc01f1f2b66e58001d503a7d), SOURCE_NAMESPACE_GARBLING_SEED_COMPILER_20261124.md and SOURCE_CONSEQUENCE_PAIR_COMPILER_SCREEN_20261124.md. No web/external literature, full PR diff, historical sweep or new Core source claims.

Missing original operation: a witness-blind classical-PPT serialized Build_inc(x_W,sigma_cancel), public Open_inc(C,w) yielding the same safe frozen native capability for every qualifying original w, and joint-public FALSE and arbitrary hard-TRUE security. Keep the entire original three-ground OR unchanged. Symbolically compile its complete bounded circuit to a directed Hamiltonian-cycle instance G with both witness maps. This grants the standard polynomial NP reduction, not an implemented consensus checker.

Mathematical change selected before implementing: combine noninvertible rank-one edge transports (wrong edge concatenation gives zero) with the exterior product of n vertex factors (repeated vertices give zero). Use a secret global basis change for the transport and secret scalar edge gauges, not reusable occurrence labels, accepting row corrections, a low-degree additive private-coefficient oracle or a pair of proof challenges. The original literal label splice/repeated occurrence or arbitrary inverse operation does not pass this product test: one connected walk must use actual consecutive edges and distinct vertices. Test whether the combination can be serialized with the SAME terminal factor for every accepted original witness while retaining source authorization under arbitrary public inspection. The field is merely an arithmetic encoding, not a discrete-log or lattice assumption. No hardness is assigned to the matrix encoding; the hoped-for foundation would need a separate hash reduction after correctness. This is a new candidate screen, not an optimization or claimed independent assumption.

## Actual candidate and every-witness correctness

Let F be a finite field of size exponential in lambda, n=|V(G)|, and r=0 a public anchor. Sample a nonzero scalar K and invertible matrices S,V in GL_n(F); rescale the first column of V so det V=K. Write v_u for its u-th column. Sample independent nonzero t_u in F. For every directed edge u->v and coordinate j=0,...,n-1 publish the n-by-n matrix
    M_uv,j = (v_u[j] t_u/t_v) S E_uv S^-1.
Here E_uv is the ordinary matrix unit. The capsule also contains G, canonical context, and E = sigma_cancel XOR KDF(ctx,encode(K),len(sigma_cancel)). Sampling an invertible matrix by rejection has bounded expected polynomial cost and can be capped with negligible failure, or a direct GL sampler can be used. Encoding size and evaluation are polynomial in n, log|F|. No implicit private evaluator.

For any original w, compute its Hamiltonian cycle, rotate to start at r, and choose for each edge a coordinate j(u) with M_uv,j nonzero. Such a coordinate exists because V is invertible. Choose any nonzero entry of that matrix. Divide the same entry of all coordinate matrices by that nonzero entry, obtaining a vector b_u = v_u/v_u[j(u)] without knowing S or t. Compute the ordered product Q of the chosen edge matrices around the cycle. Because E_uv E_vz=E_uz and all t telescope,
    Q = (product_u v_u[j(u)]) S E_rr S^-1.
Trace(Q) is the scalar product since trace(E_rr)=1. The determinant of the normalized vectors b_u in **canonical vertex order**, not path order, is K / product_u v_u[j(u)]. Therefore
    OpenKey = trace(Q) det([b_0,...,b_(n-1)]) = K.
This also implements the exterior-product idea without storing an exponential exterior algebra basis. A repeated tail cannot yield a nonzero n-fold wedge if the same column direction is used, and mismatched consecutive matrix units multiply to zero. Thus there is genuine common-value correctness for every cycle, including all original witnesses under the assumed witness-preserving reduction. No fake work, source-specific common preimage or post-recovery verifier check provides correctness. The problem is whether the product is the only public way to recover K.

## Arbitrary full-public recovery: disconnected covers

It is not. Form the bipartite graph with left and right copies of V(G), edge (u_L,v_R) for every original u->v. Find a perfect matching by ordinary augmenting paths (polynomial). A Hamiltonian cycle always gives a perfect matching, so this works on every TRUE graph. The matching gives a permutation p of the vertices, decomposed into disjoint directed cycles D_i. This need not be a Hamiltonian cycle. For each matched edge use the same public ratio operation to obtain b_u. For each component D_i, separately multiply its chosen matrices starting at any component vertex r_i and take the trace:
    q_i = trace(Q_i) = product_(u in D_i) v_u[j(u)].
All q_i are nonzero. Their product times det([b_0,...,b_(n-1)]) is exactly K. This computes the key without the original witness, without guessing secret coefficients, without an oracle transcript, without any hash break, and without submitting an invalid path to the prescribed Open. It works independently of whether the graph has a Hamiltonian cycle. No discrete-log operation is used. A perfect matching is only a relaxation of the source relation, not admissible evidence. The separate multiplication of public scalar traces is available even though the direct product of matrices from different components would vanish. Consequently correctness of the joint noninvertible product does not imply unauthorized recovery is impossible. Any TRUE security argument for this construction would still need an independent extraction of a Hamiltonian cycle/original w from the matching attack; nothing in the attack supplies it. A graph consisting of two separate directed cycles is a FALSE counterexample for the graph-level candidate; no assertion that this exact graph occurs in the image of the actual source reduction is needed or made.

## Repair attempt: retain the anchored operator, not the scalar

Instead of KDF of K, use KDF of the complete secret-dependent matrix L=K S E_rr S^-1. Build knows S,K, and every honest source cycle produces L by multiplying Q by the normalized-column determinant. This explicitly tries to keep the connectedness information in the terminal object; do not merely test another field size or coefficient basis. However rotate the cover component containing r to start at r. Its Q_r/q_r equals S E_rr S^-1. Once the attacker computes K via the independent component traces, it constructs the exact L, without S and without an original witness. Hashing L instead of K, retaining its canonical bytes, or hiding S more carefully does not fix this exact attack. A nonfactorizing transport that destroys the component trace recovery would also destroy the exhibited telescoping argument unless a new mechanism establishes common-value correctness. No such mechanism or simulator is obtained. Do not continue by changing the gauge, exterior basis, field or hash placement; the missing operation is a genuinely nonfactorizing, witness-blind transport compiler with same terminal secret and an independently justified full-public security reduction.

This is not a general impossibility result for hash-only WKEM, noncommutative encodings or NP reductions. It is an explicit attack on this candidate and its anchored-matrix repair. The field arithmetic is not relied on for security. No QROM claim, concrete SHA theorem, same-message native forgery proof, or adversarial representation assumption is made.

## Scope and reproducibility

Executed the exact Python 3 standard-library checker below locally, using F_257 as an arithmetic regression only, not a security parameter. It implements the public encoding, honest path and polynomial cover decoder, plus a tiny independent exhaustive truth audit of the two graphs solely for fixture labeling. The FALSE two-component graph opens the scalar and the anchored matrix. The TRUE graph's particular matching happens to be one cycle; the algebra above, not that fixture, establishes arbitrary perfect-matching recovery. No native signing, actual source reduction, real consensus verifier or QPT experiment run. Captured source SHA-256 55184885b8d2c0d91c196b3fc1df7f80b79b9c78f450955f7877d85fcccb0ba7; captured stdout SHA-256 42667c911c432c25bdc633b6ee008d9afd0efb8f9ea9167d827dc966c436753b.

Preserve authenticated same-anchor greater exact BTC work, finite authenticated specific burn refutation, and relevant mature incompatible Syscoin histories / properly typed carrier-tag fault. Preserve claim/outpoint, reserve, recipient, amount, burn/replay, source commitments/anchors, deadline/reset, LC depth and DA/inclusion assumptions. R316 only coverage regression. Preserve malicious capsule correctness before funding, one-honest N-of-N preauthorization/erasure, explicit R225 slot-global veto vs activation-specific native message, off-chain source verification, and arbitrary QPT joint/auxiliary/sibling/selective-opening and retained-source-coin model. None of those missing proofs is repaired by the candidate. NONQUALIFYING; no ordinary PR comment or user notification.

### Exact executed checker

```python
"""Finite arithmetic check of hidden-basis exterior transport, not a KEM."""
import random
from itertools import permutations
P = 257
rng = random.Random(20261124)

def eye(n):
    return [[int(i == j) for j in range(n)] for i in range(n)]

def mul(a,b):
    return [[sum(x*y for x,y in zip(row,col))%P for col in zip(*b)] for row in a]

def scale(c,a):
    return [[c*x%P for x in row] for row in a]

def trace(a):
    return sum(a[i][i] for i in range(len(a)))%P

def det(a):
    a=[r[:] for r in a]; n=len(a); d=1
    for j in range(n):
        i=next((i for i in range(j,n) if a[i][j]%P),None)
        if i is None: return 0
        if i!=j: a[i],a[j]=a[j],a[i]; d=-d
        p=a[j][j]%P; d=d*p%P
        for i in range(j+1,n):
            c=a[i][j]*pow(p,-1,P)%P
            a[i]=[(x-c*y)%P for x,y in zip(a[i],a[j])]
    return d%P

def inv(a):
    n=len(a); a=[r+s for r,s in zip(a,eye(n))]
    for j in range(n):
        i=next(i for i in range(j,n) if a[i][j]%P)
        a[i],a[j]=a[j],a[i]
        a[j]=[x*pow(a[j][j],-1,P)%P for x in a[j]]
        for i in range(n):
            if i!=j:
                c=a[i][j]; a[i]=[(x-c*y)%P for x,y in zip(a[i],a[j])]
    return [r[n:] for r in a]

def rand_gl(n):
    while True:
        a=[[rng.randrange(P) for _ in range(n)] for _ in range(n)]
        if det(a): return a

def build(n,edges,key):
    s=rand_gl(n); si=inv(s); v=rand_gl(n)
    c=key*pow(det(v),-1,P)%P
    for i in range(n): v[i][0]=v[i][0]*c%P
    assert det(v)==key
    t=[rng.randrange(1,P) for _ in range(n)]
    capsule={}
    for u,z in edges:
        e=[[0]*n for _ in range(n)]; e[u][z]=1
        b=mul(mul(s,e),si)
        capsule[u,z]=[scale(v[j][u]*t[u]*pow(t[z],-1,P)%P,b) for j in range(n)]
    anchor=[[0]*n for _ in range(n)]; anchor[0][0]=1
    return capsule, scale(key,mul(mul(s,anchor),si))

def decode_cycles(n,capsule,cycles):
    # Entire decoder uses public edge tuples only; no S, V, or t.
    normalized=[None]*n; scalar=1; anchor=None
    for cyc in cycles:
        if 0 in cyc:
            k=cyc.index(0); cyc=cyc[k:]+cyc[:k]
        q=eye(n)
        for u,z in zip(cyc,cyc[1:]+cyc[:1]):
            ms=capsule[u,z]
            j,a,b=next((j,a,b) for j,m in enumerate(ms) for a,row in enumerate(m) for b,x in enumerate(row) if x)
            val=ms[j][a][b]
            normalized[u]=[m[a][b]*pow(val,-1,P)%P for m in ms]
            q=mul(q,ms[j])
        tr=trace(q); assert tr!=0
        scalar=scalar*tr%P
        if 0 in cyc: anchor=scale(pow(tr,-1,P),q)
    assert all(x is not None for x in normalized)
    k=scalar*det(list(map(list,zip(*normalized))))%P
    return k,scale(k,anchor)

def cycles_of_matching(p):
    seen=set(); cs=[]
    for u in range(len(p)):
        if u in seen: continue
        c=[]; v=u
        while v not in seen:
            seen.add(v); c.append(v); v=p[v]
        assert v==u; cs.append(c)
    return cs

def find_cover(n,edges):
    # Augmenting path bipartite matching; not exhaustive HC search.
    adj=[[v for v in range(n) if (u,v) in edges] for u in range(n)]
    owner={}
    def aug(u,seen):
        for v in adj[u]:
            if v in seen: continue
            seen.add(v)
            if v not in owner or aug(owner[v],seen):
                owner[v]=u; return True
        return False
    if not all(aug(u,set()) for u in range(n)): return None
    p=[None]*n
    for v,u in owner.items(): p[u]=v
    return cycles_of_matching(p)

def check(n,edges,truth,known_cycle=None):
    # Tiny truth audit only; not used by cover decoder.
    found=any(all((u,v) in edges for u,v in zip((0,)+p,p+(0,))) for p in permutations(range(1,n)))
    assert found==truth
    key=rng.randrange(1,P); cap,anch=build(n,edges,key)
    cover=find_cover(n,edges); assert cover is not None
    recovered,rec_anch=decode_cycles(n,cap,cover)
    assert recovered==key and rec_anch==anch
    if known_cycle is not None:
        assert decode_cycles(n,cap,[known_cycle])==(key,anch)
    print(f'graph n={n}, has_HC={found}, cover_lengths={[len(c) for c in cover]}, exact_scalar={recovered==key}, exact_anchor={rec_anch==anch}')

# False graph with two disconnected directed cycles; true graph adds a Hamiltonian cycle.
n=6
base={(0,1),(1,2),(2,0),(3,4),(4,5),(5,3)}
check(n,base,False)
check(n,base|{(2,3),(5,0)},True,[0,1,2,3,4,5])
```

### Captured stdout

```text
graph n=6, has_HC=False, cover_lengths=[3, 3], exact_scalar=True, exact_anchor=True
graph n=6, has_HC=True, cover_lengths=[6], exact_scalar=True, exact_anchor=True
```
