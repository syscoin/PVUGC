#!/usr/bin/env python3
from itertools import combinations, product
from collections import Counter, deque
import json, sys

ASSERTS = 0
def ck(cond, msg="assertion failed"):
    global ASSERTS
    ASSERTS += 1
    if not cond:
        raise AssertionError(msg)

class F16:
    def __init__(self):
        self.mul = [[self._mul(a,b) for b in range(16)] for a in range(16)]
        self.inv = [0] + [next(b for b in range(1,16) if self.mul[a][b] == 1)
                          for a in range(1,16)]
    def _mul(self,a,b):
        z=0
        while b:
            if b&1:
                z ^= a
            b >>= 1
            a <<= 1
            if a & 16:
                a ^= 0b10011
        return z
    def order(self,a):
        z=1
        for k in range(1,16):
            z=self.mul[z][a]
            if z==1:
                return k
        raise AssertionError("non-field element")
F=F16()

def canon(vecs):
    B={}
    for x in vecs:
        v=x
        for p in sorted(B, reverse=True):
            if (v>>p)&1:
                v ^= B[p]
        if v:
            p=v.bit_length()-1
            for q in list(B):
                if (B[q]>>p)&1:
                    B[q] ^= v
            B[p]=v
    return tuple(B[p] for p in sorted(B, reverse=True))

def dim(vecs):
    return len(canon(vecs))

def span_elements(B):
    out=[0]
    for b in B:
        out += [x^b for x in out]
    return out

def enum_rref_subspaces(k=5,n=8):
    # Unique RREF enumeration. Total is [8 choose 5]_2 = 97,155.
    for piv in combinations(range(n),k):
        non=[c for c in range(n) if c not in piv]
        slots=[(i,c) for c in non for i,p in enumerate(piv) if p<c]
        for mask in range(1<<len(slots)):
            rows=[1<<p for p in piv]
            for bit,(i,c) in enumerate(slots):
                if (mask>>bit)&1:
                    rows[i] |= 1<<c
            yield canon(rows)

def pack2(x,y):
    return x | (y<<4)

def unpack2(v):
    return v&15, (v>>4)&15

def pack3(v):
    return v[0] | (v[1]<<4) | (v[2]<<8)

def unpack3(v):
    return v&15, (v>>4)&15, (v>>8)&15

def field_line_bases_2():
    out=[]
    # slopes y=t*x plus vertical line
    for t in range(16):
        out.append(canon([pack2(b,F.mul[t][b]) for b in (1,2,4,8)]))
    out.append(canon([pack2(0,b) for b in (1,2,4,8)]))
    ck(len(out)==17)
    ck(all(len(B)==4 for B in out))
    return out

LINES2=field_line_bases_2()

def line_profile(P):
    ds=[]
    for L in LINES2:
        ds.append(9-dim(P+L)) # dim P + dim L - dim(P+L)
    return tuple(ds)

def act_vec2(v,M):
    x,y=unpack2(v)
    a,b,c,d=M
    X=F.mul[a][x] ^ F.mul[b][y]
    Y=F.mul[c][x] ^ F.mul[d][y]
    return pack2(X,Y)

def act_subspace(P,M):
    return canon([act_vec2(v,M) for v in P])

def rref_f16(rows):
    A=[list(r) for r in rows]
    piv=[]; rr=0
    if not A:
        return A,piv
    for c in range(len(A[0])):
        q=next((i for i in range(rr,len(A)) if A[i][c]),None)
        if q is None:
            continue
        A[rr],A[q]=A[q],A[rr]
        s=F.inv[A[rr][c]]
        A[rr]=[F.mul[s][x] for x in A[rr]]
        for i in range(len(A)):
            if i!=rr and A[i][c]:
                s=A[i][c]
                A[i]=[x ^ F.mul[s][y] for x,y in zip(A[i],A[rr])]
        piv.append(c); rr+=1
        if rr==len(A):
            break
    return A,piv

def null_f16(A,ncols=None):
    if not A:
        return [[int(i==j) for i in range(ncols)] for j in range(ncols)]
    R,piv=rref_f16(A)
    n=len(A[0])
    out=[]
    for c in range(n):
        if c not in piv:
            v=[0]*n
            v[c]=1
            for i,p in enumerate(piv):
                v[p]=R[i][c] # minus = plus in characteristic two
            out.append(v)
    return out

def dotf(a,b):
    z=0
    for x,y in zip(a,b):
        z ^= F.mul[x][y]
    return z

def f2_rank_field(vals):
    return len(canon(vals))

def projective_points3():
    out=[]
    for q in range(3):
        for tail in product(range(16), repeat=2-q):
            out.append(tuple([0]*q+[1]+list(tail)))
    ck(len(out)==273)
    return out

def det3(rows):
    a,b,c=rows[0]; d,e,f=rows[1]; g,h,i=rows[2]
    return (F.mul[a][F.mul[e][i]^F.mul[f][h]]
            ^ F.mul[b][F.mul[d][i]^F.mul[f][g]]
            ^ F.mul[c][F.mul[d][h]^F.mul[e][g]])

def field_line_from_two_normals(a,b):
    ns=null_f16([a,b],3)
    ck(len(ns)==1)
    return tuple(ns[0])

def field_line_binary_basis_3(j):
    return canon([
        pack3(tuple(F.mul[bit][x] for x in j))
        for bit in (1,2,4,8)
    ])

def main():
    profile_hist=Counter()
    candidates=[]
    total=0
    target=Counter({1:10,2:7})

    for P in enum_rref_subspaces():
        total += 1
        ds=line_profile(P)
        prof=tuple(sorted(Counter(ds).items()))
        profile_hist[prof] += 1
        if Counter(ds)==target:
            candidates.append(P)

    ck(total==97155)
    expected_hist={
        ((1,10),(2,7)):61200,
        ((1,12),(2,4),(3,1)):35700,
        ((1,16),(4,1)):255,
    }
    ck(dict(profile_hist)==expected_hist,(profile_hist,expected_hist))
    ck(len(candidates)==61200)

    # The elementary generators below generate a subgroup of GL_2(16).
    # If one orbit already has |GL_2(16)| elements, the subgroup is the
    # entire group and the orbit is regular.
    primitive=2
    ck(F.order(primitive)==15)
    gens=[
        (0,1,1,0),          # swap coordinates
        (1,1,0,1),          # shear
        (primitive,0,0,1),  # primitive diagonal scale
    ]
    P0=candidates[0]
    target_set=set(candidates)
    seen={P0}
    dq=deque([P0])
    while dq:
        P=dq.popleft()
        for M in gens:
            Q=act_subspace(P,M)
            ck(Q in target_set)
            if Q not in seen:
                seen.add(Q)
                dq.append(Q)

    gl2_order=(16**2-1)*(16**2-16)
    ck(gl2_order==61200)
    ck(len(seen)==gl2_order)
    ck(seen==target_set)

    # Canonical representative parity-check matrix H: its five columns are
    # the chosen F2 basis of P0.
    pcols=list(P0)
    H=[
        [v&15 for v in pcols],
        [(v>>4)&15 for v in pcols],
    ]
    Hr,Hpiv=rref_f16(H)
    ck(len(Hpiv)==2)
    G=null_f16(H)
    ck(len(G)==3)

    # G is a 3x5 generator of the dual [5,3] code; its columns form an F2
    # basis of the canonical W <= GF(16)^3.
    Wcols=[tuple(G[r][j] for r in range(3)) for j in range(5)]
    Wbin=canon([pack3(v) for v in Wcols])
    ck(len(Wbin)==5)
    ck(len(rref_f16([list(v) for v in Wcols])[1])==3)

    # Candidate parity-check projective rank spectrum: 7 rank-3, 10 rank-4.
    h_projective=Counter()
    for t in range(16):
        vals=[H[0][j] ^ F.mul[t][H[1][j]] for j in range(5)]
        h_projective[f2_rank_field(vals)] += 1
    vals=H[1]
    h_projective[f2_rank_field(vals)] += 1
    ck(h_projective==Counter({3:7,4:10}),h_projective)

    # Full [5,3] dual-code rank distribution, plus projective W hyperplane
    # profile. These re-check the Run-277 handoff on the canonical object.
    dual_rank=Counter()
    for a,b,c in product(range(16),repeat=3):
        vals=[
            F.mul[a][G[0][j]] ^ F.mul[b][G[1][j]] ^ F.mul[c][G[2][j]]
            for j in range(5)
        ]
        dual_rank[f2_rank_field(vals)] += 1
    ck(dual_rank==Counter({0:1,2:105,3:1590,4:2400}),dual_rank)

    projective_profile=Counter()
    heavy=[]
    for normal in projective_points3():
        vals=[dotf(normal,v) for v in Wcols]
        r=f2_rank_field(vals)
        projective_profile[r] += 1
        if r==2:
            heavy.append(normal)
    ck(projective_profile==Counter({2:7,3:106,4:160}),projective_profile)
    ck(len(heavy)==7)

    # W is scattered: no nontrivial scalar translate meets it nontrivially.
    Welems=set(span_elements(Wbin))
    scalar_intersections={}
    for lam in range(2,16):
        lamW=canon([
            pack3(tuple(F.mul[lam][x] for x in unpack3(v)))
            for v in Wbin
        ])
        d=10-dim(Wbin+lamW)
        scalar_intersections[lam]=d
        ck(d==0,(lam,d))

    # Heavy-plane geometry. Exactly two disjoint collinear triples of dual
    # points; each concurrent primal triple shares one common F2-line in W.
    collinear=[]
    for I in combinations(range(7),3):
        if det3([heavy[i] for i in I])==0:
            collinear.append(I)
    ck(collinear==[(0,2,3),(1,5,6)],collinear)
    ck(set(collinear[0]).isdisjoint(collinear[1]))
    leftover=next(i for i in range(7)
                  if i not in set(collinear[0])|set(collinear[1]))
    ck(leftover==4)

    heavy_Q=[]
    for normal in heavy:
        elems=[v for v in Welems if dotf(normal,unpack3(v))==0]
        Q=canon(elems)
        ck(len(Q)==3)
        heavy_Q.append(Q)

    shared_lines=[]
    for triple in collinear:
        a,b,c=[heavy[i] for i in triple]
        j=field_line_from_two_normals(a,b)
        ck(dotf(c,j)==0)
        J=set(span_elements(field_line_binary_basis_3(j)))
        WJ=canon(list(Welems & J))
        ck(len(WJ)==1)
        shared=WJ[0]
        shared_lines.append(shared)
        for i,jj in combinations(triple,2):
            inter=set(span_elements(heavy_Q[i])) & set(span_elements(heavy_Q[jj]))
            I=canon(list(inter))
            ck(I==(shared,))
    ck(shared_lines[0]!=shared_lines[1])
    leftover_elems=set(span_elements(heavy_Q[leftover]))
    ck(shared_lines[0] not in leftover_elems)
    ck(shared_lines[1] not in leftover_elems)

    # Regular orbit => trivial GL2 stabilizer of P0. Algebraically this also
    # gives trivial GL3 field-linear automorphism group of W: any such
    # automorphism induces an F2 basis change and a GL2 stabilizer of P0.
    out={
        "run":278,
        "python":sys.version.split()[0],
        "field":"GF(16)=F2[x]/(x^4+x+1)",
        "all_binary_5spaces_in_GF16_sq":total,
        "line_intersection_profile_histogram":{
            "10x_dim1__7x_dim2":profile_hist[((1,10),(2,7))],
            "12x_dim1__4x_dim2__1x_dim3":profile_hist[((1,12),(2,4),(3,1))],
            "16x_dim1__1x_dim4":profile_hist[((1,16),(4,1))],
        },
        "target_profile_count":len(candidates),
        "GL2_16_order":gl2_order,
        "target_profile_single_regular_GL2_orbit":True,
        "target_profile_stabilizer_size":1,
        "canonical_P_basis_hex":[hex(v) for v in P0],
        "canonical_parity_check_H":H,
        "canonical_generator_G":G,
        "canonical_H_projective_rank_spectrum":dict(sorted(h_projective.items())),
        "canonical_dual_full_rank_distribution":dict(sorted(dual_rank.items())),
        "canonical_W_field_hyperplane_rank_profile":dict(sorted(projective_profile.items())),
        "canonical_W_scalar_intersections":scalar_intersections,
        "heavy_plane_dual_collinear_triples":[list(x) for x in collinear],
        "heavy_plane_leftover_index":leftover,
        "concurrent_triples_share_distinct_binary_W_lines":True,
        "leftover_heavy_plane_contains_neither_shared_line":True,
        "classification_consequence":"Every field-span-three scattered W5 with the surviving 7-heavy-plane / [5,2] parity-check rank profile is GL3(GF16)-equivalent to the one canonical W above. Its field-linear automorphism group is trivial.",
        "next_tensor_target":"No abstract [5,2] classification remains: test embeddings of this single rigid W normal form into actual Hair-Sahai source field hyperplanes, using the two concurrent heavy-plane triples plus one residual heavy plane as pruning invariants.",
        "scope":{
            "proved":"Complete finite classification of the relevant abstract [5,2] GF16 parity-check code / W5 geometry.",
            "not_proved":"No exclusion of embeddings into the actual Hair-Sahai tensor, no e15(D)=12/d5(C)=10 theorem, no false-instance QPT hiding, ORIGINAL extraction, malicious setup, or practical WKEM."
        },
        "assertions":ASSERTS,
        "status":"PASS"
    }
    print(json.dumps(out,sort_keys=True,indent=2))

if __name__=="__main__":
    main()
