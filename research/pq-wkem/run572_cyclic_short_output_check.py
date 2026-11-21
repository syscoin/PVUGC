#!/usr/bin/env python3
"""Run 572: exact cyclic-interval injectivization identities. Standard library only.
This checks finite algebra/probability, not cryptographic or QPT security."""
import hashlib
import json

assertions = 0

def check(condition, message='check failed'):
    global assertions
    assert condition, message
    assertions += 1


def graph_rank(N, T, d):
    parent = {}
    edges = []
    def root(v):
        parent.setdefault(v, v)
        while parent[v] != v:
            parent[v] = parent[parent[v]]
            v = parent[v]
        return v
    for t in T:
        a, b = t % N, (t + d) % N
        parent.setdefault(a, a)
        parent.setdefault(b, b)
        edges.append((a,b))
        ra, rb = root(a), root(b)
        if ra != rb:
            parent[ra] = rb
    components = len({root(v) for v in parent})
    return len(parent) - components, len(parent), components, edges


def values(N, seed):
    return [hashlib.sha256(f'run572/{N}/{seed}/{i}'.encode()).digest()[0] & 1
            for i in range(N)]


def V(B, x, k):
    N = len(B)
    return tuple(B[(x+t) % N] for t in range(k))

# 1. The consecutive-offset graph is a forest for every nonzero cyclic shift.
forest_fixtures = 0
for n in range(2, 8):
    N = 1 << n
    for k in range(1, N//2 + 1):
        for d in range(1, N):
            rank, vertices, components, edges = graph_rank(N, range(k), d)
            check(rank == k, f'forest failed n={n} k={k} d={d}')
            check(vertices-components == k)
            forest_fixtures += 1
N = 256
for k in [1,2,3,4,8,16,32,64,128]:
    for d in range(1,N):
        rank, vertices, components, edges = graph_rank(N, range(k), d)
        check(rank == k)
        forest_fixtures += 1

# 2. The consecutive condition matters: antipodal offset pairs duplicate an edge.
rank, _, _, _ = graph_rank(8, [0,4], 4)
check(rank == 1)  # two edges but just one independent equality
rank, _, _, _ = graph_rank(8, [0,1,2,3], 4)
check(rank == 4)

# 3. Exhaustively enumerate all one-bit functions for tiny cyclic groups.
#    For fixed x != y, Pr[V(x)=V(y)] = 2^-k, exactly.
exact_probability_fixtures = 0
for n in [2,3]:
    N=1<<n
    for k in range(1,N//2+1):
        for d in range(1,N):
            for x in range(N):
                matches=0
                for mask in range(1<<N):
                    B=[(mask>>j)&1 for j in range(N)]
                    if V(B,x,k)==V(B,(x+d)%N,k):
                        matches += 1
                check(matches == (1 << (N-k)),
                      f'probability mismatch n={n} k={k} d={d} x={x}')
                exact_probability_fixtures += 1

# 4. With injective V, the public two-branch function is an exact dihedral HSP oracle.
#    No quantum algorithm is executed. The construction is tested for every shift.
hsp_instances=0
hsp_fibers=0
N=32; k=16
for seed in range(5):
    B=values(N,seed)
    fingerprints=[V(B,x,k) for x in range(N)]
    check(len(set(fingerprints)) == N, 'deterministic fixture unexpectedly collided')
    for d in range(1,N):
        O=lambda x,b: fingerprints[(x + (d if b else 0)) % N]
        for x in range(N):
            check(O(x,0)==O((x-d)%N,1))
            check(O(x,1)==O((x+d)%N,0))
            hsp_fibers += 1
        check(len({O(x,b) for x in range(N) for b in (0,1)}) == N)
        hsp_instances += 1

# 5. Conservative bound arithmetic and the parameter precondition.
for n in range(3,20):
    for b in [1,2,4,8]:
        for kappa in [4,16,128]:
            k=(2*n+kappa+b-1)//b
            if k <= (1<<(n-1)):
                # Union bound: C(2^n,2)*2^(-bk) < 2^(-kappa-1).
                # Verify exactly using integer arithmetic.
                N=1<<n
                check(N*(N-1) * (1<<kappa) < (1<<(b*k)))
check((2*128+128)==384)
check(384 < (1<<127))

result={
 'checkpoint':'run572_cyclic_short_output',
 'assertions_passed':assertions,
 'forest_graph_fixtures':forest_fixtures,
 'tiny_exact_probability_fixtures':exact_probability_fixtures,
 'dihedral_oracle_instances':hsp_instances,
 'dihedral_coset_fiber_fixtures':hsp_fibers,
 'sample_n':128,
 'sample_output_bits':1,
 'sample_kappa':128,
 'sample_offsets':384,
 'sample_noninjectivity_union_bound':'< 2^-129',
 'model':'public coherent ideal-oracle/independent random-function distribution; exact finite checks only',
 'quantum_algorithm_executed':False,
 'pq_release_security_established':False,
}
print(json.dumps(result, indent=2, sort_keys=True))
