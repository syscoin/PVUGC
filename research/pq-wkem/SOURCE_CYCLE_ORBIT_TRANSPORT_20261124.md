# 2026-11-24 — Witness-induced graph orbit transport (NONQUALIFYING)

## Selection and provenance

Actual start/pre-write head d18191f6189c5d34b3e013db5b6a6b07e48f208d, syscoin/PVUGC PR #1, research/pq-wkem-validation-20260918, open/draft/unmerged. Read PR metadata and recent substantive discussion through R225, exact head commit file list and SOURCE_PROOF_COALESCENT_REFRESH_20261124.md (blob 68bfe71ce207e5d2b1771327ddeb8d6695c0db47), and SOURCE_PROOF_SUPPORT_MINHASH_20261124.md at the same head. Rechecked head and confirmed this new path absent. No external research, Core source changes/claims, entire PR diff, archive reconstruction or production action.

Missing ORIGINAL operation: given different original witnesses and an independent setup trapdoor, derive one common hidden key in classical PPT without matching their proof transcripts, plus extract original evidence or independently justified break from arbitrary unauthorized recovery. The mathematical change is **transport through a witness-induced anchored graph ordering**, not equality of proof commitments, public refresh, minimum over proof support, or mixed labels. A witness supplies a complete ordering of the vertices via a Hamiltonian cycle; distinct orderings may yield exactly the same *ordered adjacency matrix* if they differ by a graph automorphism. The whole matrix is one nonlinear hash input. No enumeration of all cycles is needed by honest evaluation. This avoids the specific support-minimum complexity and preprepared-Fiat-Shamir-refresh attacks, without assuming a canonical original witness or a matching proof random tape. It does not establish that a suitable graph can be constructed, nor that computing its ordered matrix without a witness is hard. Those are the next equations, investigated below.

## 1. Candidate and exact equality condition

Let R_x(w) be the unchanged original verifier (all three independently sufficient grounds). Sample lambda-bit t at setup, publish h=H_trap(t), and let Q_(x,h)(w,t')=R_x(w) OR [H_trap(t')=h]. The setup branch is not an original certificate. Try a public deterministic compiler G(x,h) to a directed graph with anchor vertex a and a witness-to-Hamiltonian-cycle map T. We require a reverse map E from every accepting anchored Hamiltonian cycle to a Q witness. No such compiler with the additional orbit property below has been produced. Ordinary NP-to-Hamiltonicity completeness would supply only the decision relation, not this orbit property. For the candidate-selection calculation, assume just that G and T are PPT and T(u) is valid for each Q witness. This assumption is not a solution to the graph compiler problem.

For cycle c=(a,c_1,...,c_(n-1)), let A(c) be the n-by-n directed adjacency matrix in precisely that vertex order (plus ordered vertex colors if the graph uses colors). The cycle closes with edge c_(n-1)->a. Serialize n, ordered colors and rows canonically. An initially contemplated random relabeling pi and public cycle D=pi(c) are unnecessary: D can be the fixed public order of positions 0,...,n-1. The hidden object is the ordered adjacency matrix, not a secret permutation published elsewhere.

    Build_inc(x,S):
        t <- uniform; h <- H_trap(t)
        G <- G(x,h); c0 <- T(G,(dummy,t))
        A0 <- A(c0)
        K <- H_key(ctx,h,serialize(A0))
        return (ctx,h,S XOR XOF(ctx,K,|S|))
    Open_inc(C,w):
        G <- G(x,h); c1 <- T(G,(w,dummy))
        A1 <- A(c1)
        K1 <- H_key(ctx,h,serialize(A1))
        return B XOR XOF(ctx,K1,|S|)

S is the exact frozen safe capability, ctx binds the complete claim and native VK/message/capsule ID. Setup erases t and c0. A public verifier if-check is not the gating mechanism: the actual full ordered graph is the candidate key input. These algorithms are PPT given the compiler/maps, but their correctness is conditional on A(T(G,u)) being the same for every admissible u, including setup t and every original certificate. Hash collisions cannot be assumed to fix unequal matrices. If the key domain is modeled as a fresh ideal lambda-bit hash, unequal fixed matrices collide there with probability 2^-lambda; an independently modeled pad domain may also accidentally collide, not provide useful correctness. No concrete SHA claim follows from that idealization.

Exact orbit lemma: for two anchored cycles c,d, A(c)=A(d) iff the unique bijection f(c_i)=d_i for each i is a graph automorphism fixing a (and preserving any colors). Proof: equality of every matrix entry says (c_i,c_j) is an edge iff (d_i,d_j) is an edge. All vertices appear once, so this condition covers the entire edge relation. Conversely an automorphism preserves all these entries. If colors are included, equality of ordered color vectors is precisely the remaining condition. Thus a compiler whose produced cycles lie in a single anchored automorphism orbit suffices for equality; it does not require the actual original witnesses to be identical. Requiring every graph cycle in that orbit would be stronger than necessary for equality but useful for extraction. A generic decision reduction does not imply either condition.

## 2. Concrete polynomial repair attempt: clone symmetrization

Try replacing each graph vertex v by m indistinguishable clones, with directed edges in both directions between every distinct pair of clones of v, and complete directed bipartite edges between clone sets for each base edge v->u. Distinguish anchor clone (a,0). Lift a base anchored cycle c to a valid cycle by traversing each clone set in index order, following the original cycle order. This is an actual polynomial graph transformation and witness-to-cycle map. It adds symmetry without making a public list of candidate secret matrices. It cannot implement the required orbit equation for these natural lifts.

For a loopless base graph the normalized blown-up matrix has off-diagonal m-by-m blocks either all ones or all zeros according to the original normalized edge entry, and diagonal blocks J_m-I_m. In particular A(c)_(i,j)=A(lift(c))_(im,jm) for all i,j, including the zero diagonal. Therefore distinct base matrices remain distinct under every positive m. Adding only internal clone permutations cannot remove the distinguishing blocks. This argument applies to the actual lift specified above; it is not a theorem against all possible graph transformations or all possible alternate lifts.

Minimal explicit two-cycle example used in the checker: take c=(0,1,2,3), d=(0,2,1,3), and directed edges from both cycles plus 1->0. There are exactly these two anchored Hamiltonian cycles. The extra edge breaks the swap of vertices 1 and 2, and gives normalized rows respectively

    0110 1011 0101 1000
    0110 0011 1101 1000

The differing entries prove the failure before any cryptographic assumptions. Removing the extra edge gives the positive symmetry control (same normalized matrix, two distinct cycles). Clone blow-up of the asymmetric example retains the differing base matrices. These graphs are explicit combinatorial controls only, not graphs compiled from authentic Syscoin or Bitcoin evidence. No inference that a suitable source-specific compiler is impossible.

## 3. Extraction and full-public simulation obligations

If a common ordered matrix A* existed, recovering it would not by itself give a source certificate. A public key query on its bytes might reveal only an isomorphic graph, not a vertex permutation. For a *given* isomorphism f from the graph on positions with adjacency A* to G preserving the anchor, f(0),...,f(n-1) is an anchored Hamiltonian cycle, since the position-cycle edges occur in A*. Hence E could extract a Q witness from this explicit cycle. But an arbitrary attacker does not volunteer f. One must supply a classical-PPT or QPT isomorphism recovery procedure for the particular compiler's graphs, or some other direct extraction from the bytes. Generic graph isomorphism is not being assumed an independently justified hash hardness primitive. Even efficient recovery of f is insufficient if E gives the setup preimage t: the joint reduction must handle that branch as an independent justified break and simulate native data and related capsules without t-dependent leakage. In particular the hash-key reduction itself needs an actual QROM argument against coherent queries, not a classical observed-query-list argument.

A proposed shortcut of using a publicly computable isomorphism canonicalizer on G to make A* independent of cycles fails if the chosen key input is that canonicalizer's output: the adversary computes it from the same public x,h and derives the pad, with no original witness. This does NOT rule out a witness-aided anchored canonical ordering that is difficult to find but has efficiently invertible transport once its matrix is given. The missing operation for that direction is a **specific classical-PPT source compiler** that enforces the single-orbit equation for setup and all original witnesses, with a non-circular arbitrary-recovery extractor. The clone transformation supplies neither. Do not merely choose a different graph size, add more clones, or assume that generic NP reductions preserve an orbit. A claim that a public normal form is hidden because its derivation used a witness is not security.

The full public view remains ctx,h, capsule mask, relation/checking keys, native VK/message, all source commitments and auxiliary correlations/sibling capsules. Any future simulator must include them. The three OR grounds, original source authentication/relevance and maturity, R316 coverage correction, R225 slot-global versus activation-specific choice, malicious setup correctness/erasure/DA and network assumptions are unchanged. No native signature, genuine source verifier, full-public FALSE/hard-TRUE proof or QROM extraction was produced. No discrete-log or lattice assumption. NONQUALIFYING.

## 4. Exact executed local checker (Python 3, standard library)

Executed with CPython via container, no external network. Script SHA-256 4fadd009acab8e9ced5539ba22b336d45a91e972faa3ca6b70839abd50f270f3. The code below is the exact script with its terminal newline.

```python
from itertools import permutations

def cycles(n, E):
    return [(0,)+p for p in permutations(range(1,n))
            if all((a,b) in E for a,b in zip((0,)+p,p+(0,)))]

def norm(E, c):
    return tuple(tuple(int((a,b) in E) for b in c) for a in c)

def blowup(E, n, m):
    return {(i*m+a,j*m+b) for i in range(n) for j in range(n)
            for a in range(m) for b in range(m)
            if (i==j and a!=b) or (i,j) in E}

def lift(c,m):
    return tuple(i*m+a for i in c for a in range(m))

C0=(0,1,2,3); C1=(0,2,1,3)
E0=set(zip(C0,C0[1:]+C0[:1]))|set(zip(C1,C1[1:]+C1[:1]))
E=E0|{(1,0)}
assert set(cycles(4,E0))=={C0,C1}
assert norm(E0,C0)==norm(E0,C1)
assert set(cycles(4,E))=={C0,C1}
A0,A1=norm(E,C0),norm(E,C1)
assert A0!=A1
print('symmetric control normalized matrices equal:',norm(E0,C0)==norm(E0,C1))
print('asymmetric example cycles:',cycles(4,E))
print('C0 matrix:', [''.join(map(str,row)) for row in A0])
print('C1 matrix:', [''.join(map(str,row)) for row in A1])
for m in (2,3,4):
    F=blowup(E,4,m); l0,l1=lift(C0,m),lift(C1,m)
    assert all((a,b) in F for c in (l0,l1) for a,b in zip(c,c[1:]+c[:1]))
    B0,B1=norm(F,l0),norm(F,l1)
    assert B0!=B1
    for A,B in ((A0,B0),(A1,B1)):
        assert tuple(tuple(B[i*m][j*m] for j in range(4)) for i in range(4))==A
    print('clone multiplicity',m,': valid lifts; base matrices recovered; unequal')
```

Captured stdout (successful exit):

```
symmetric control normalized matrices equal: True
asymmetric example cycles: [(0, 1, 2, 3), (0, 2, 1, 3)]
C0 matrix: ['0110', '1011', '0101', '1000']
C1 matrix: ['0110', '0011', '1101', '1000']
clone multiplicity 2 : valid lifts; base matrices recovered; unequal
clone multiplicity 3 : valid lifts; base matrices recovered; unequal
clone multiplicity 4 : valid lifts; base matrices recovered; unequal
```

Research preservation only, no ordinary PR progress comment or user notification.
