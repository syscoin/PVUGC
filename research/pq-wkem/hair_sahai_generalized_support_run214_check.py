#!/usr/bin/env python3
"""Run 214 exact finite checks: generalized column-support spectrum of the
current Hair--Sahai weighted-table N=3,R=1 false source.

This is a deterministic, standard-library-only validation script.  It rebuilds
the exact compiler used by the current PR source checker; it does not use the
network, production code, or cryptographic secrets.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from itertools import product
from math import comb, log2
import json
import sys

ASSERTIONS = 0

def check(cond, msg="assertion failed"):
    global ASSERTIONS
    ASSERTIONS += 1
    if not cond:
        raise AssertionError(msg)

class Field:
    def __init__(self, q, poly=None):
        self.q=q; self.poly=poly
        self.char=2 if poly else q
        self.add=[[self._add(a,b) for b in range(q)] for a in range(q)]
        self.mul=[[self._mul(a,b) for b in range(q)] for a in range(q)]
        self.neg=[0 if a==0 else next(b for b in range(q) if self.add[a][b]==0)
                  for a in range(q)]
        self.inv=[0]+[next(b for b in range(1,q) if self.mul[a][b]==1)
                      for a in range(1,q)]
    def _add(self,a,b):
        return a^b if self.poly else (a+b)%self.q
    def _mul(self,a,b):
        if not self.poly:
            return a*b%self.q
        z=0
        while b:
            if b&1: z^=a
            b>>=1
            a<<=1
            if a&self.q: a^=self.poly
        return z
    def pow(self,a,k):
        z=1
        while k:
            if k&1: z=self.mul[z][a]
            k>>=1
            a=self.mul[a][a]
        return z
    def integer(self,n): return n%self.char
    def sub(self,a,b): return self.add[a][self.neg[b]]
    def sum(self,xs):
        z=0
        for x in xs: z=self.add[z][x]
        return z
    def order(self,a):
        z=1
        for i in range(1,self.q):
            z=self.mul[z][a]
            if z==1: return i
        raise AssertionError("not field")
    def choose_generator(self,N):
        return next(a for a in range(1,self.q) if self.order(a)>N)

def rref(rows,F):
    A=[r[:] for r in rows]
    if not A: return [],[]
    r=0; piv=[]
    for c in range(len(A[0])):
        j=next((i for i in range(r,len(A)) if A[i][c]),None)
        if j is None: continue
        A[r],A[j]=A[j],A[r]
        sc=F.inv[A[r][c]]
        A[r]=[F.mul[sc][x] for x in A[r]]
        for i in range(len(A)):
            if i!=r and A[i][c]:
                sc=F.neg[A[i][c]]
                A[i]=[F.add[x][F.mul[sc][y]] for x,y in zip(A[i],A[r])]
        piv.append(c); r+=1
        if r==len(A): break
    return A,piv

def nullspace(A,F,ncols=None):
    if not A:
        return [[int(i==j) for i in range(ncols)] for j in range(ncols)]
    R,piv=rref(A,F)
    n=len(A[0]); out=[]
    for c in range(n):
        if c not in piv:
            v=[0]*n; v[c]=1
            for i,p in enumerate(piv):
                v[p]=F.neg[R[i][c]]
            out.append(v)
    return out

def span(rows,F):
    B={}
    for row in rows:
        v=row[:]
        for p,w in sorted(B.items()):
            if v[p]:
                z=F.neg[v[p]]
                v=[F.add[x][F.mul[z][y]] for x,y in zip(v,w)]
        p=next((i for i,x in enumerate(v) if x),None)
        if p is not None:
            z=F.inv[v[p]]
            B[p]=[F.mul[z][x] for x in v]
    return [v for _,v in sorted(B.items())]

def reshape(v,c): return [v[i:i+c] for i in range(0,len(v),c)]
def lincomb(rows,c,F):
    return [F.sum(F.mul[a][row[i]] for a,row in zip(c,rows))
            for i in range(len(rows[0]))]
def alphas(R):
    return [a for a in product(range(R+1),repeat=R) if sum(a)<=R]

def spec(N,R,F,gamma=None):
    assert F.q>2*N*R
    gamma=F.choose_generator(N) if gamma is None else gamma
    assert F.order(gamma)>N
    aa=alphas(R)
    ts=list(range(2*N*R+1))
    coeff=[[[F.pow(F.mul[F.pow(gamma,j)][t],i)
              for i in range(N+1)]
             for j in range(R)]
            for t in ts]
    return {'N':N,'R':R,'F':F,'gamma':gamma,'aa':aa,'ts':ts,'coeff':coeff}

def encode(w,S):
    F=S['F']; v=[1]+list(w); out=[]
    for cf in S['coeff']:
        ell=[F.sum(F.mul[a][b] for a,b in zip(row,v)) for row in cf]
        for alpha in S['aa']:
            h=1
            for x,p in zip(ell,alpha):
                h=F.mul[h][F.pow(x,p)]
            for vi in v:
                for vj in v:
                    out.append(F.mul[h][F.mul[vi][vj]])
    return out

def table_space(S,eqs):
    N=S['N']; F=S['F']
    words=list(product((0,1),repeat=N))
    enc=[encode(w,S) for w in words]
    stride=(N+1)**2
    equations=[]
    for eq in eqs:
        for hidx in range(len(S['ts'])*len(S['aa'])):
            equations.append([
                F.mul[ev[hidx*stride]][eq(w,F)]
                for ev,w in zip(enc,words)
            ])
    coeffs=nullspace(equations,F,len(words))
    basis=span([lincomb(enc,c,F) for c in coeffs],F)
    return words,enc,basis

def descend(mat,F):
    h=F.q.bit_length()-1
    return [[(entry>>bit)&1 for entry in row]
            for row in mat for bit in range(h)]

def canonical_span(vecs):
    """Unique reduced binary basis for bit-packed ambient vectors."""
    basis={}
    for x in vecs:
        v=x
        for p in sorted(basis, reverse=True):
            if (v>>p)&1:
                v ^= basis[p]
        if v:
            p=v.bit_length()-1
            for q in list(basis):
                if (basis[q]>>p)&1:
                    basis[q] ^= v
            basis[p]=v
    ps=sorted(basis, reverse=True)
    for p in ps:
        for q in ps:
            if q!=p and ((basis[q]>>p)&1):
                basis[q]^=basis[p]
    return tuple(basis[p] for p in sorted(basis, reverse=True))

def cols_from_binary_matrix(mat):
    cols=[]
    for c in range(len(mat[0])):
        v=0
        for i,row in enumerate(mat):
            if row[c]:
                v |= 1<<i
        cols.append(v)
    return cols

def xor_cols(A,B): return [a^b for a,b in zip(A,B)]

def source_cols(binary_mats,g):
    out=[0,0,0,0]
    x=g
    while x:
        lsb=x & -x
        i=lsb.bit_length()-1
        out=xor_cols(out,binary_mats[i])
        x ^= lsb
    return out

def all_hyperplanes(kdim):
    subs=set()
    for f in range(1,1<<kdim):
        xs=[x for x in range(1,1<<kdim)
            if ((x&f).bit_count()&1)==0]
        B=canonical_span(xs)
        if len(B)==kdim-1:
            subs.add(B)
    return sorted(subs)

def all_2spaces_F2_4():
    subs=set()
    for a in range(1,16):
        for b in range(a+1,16):
            B=canonical_span([a,b])
            if len(B)==2:
                subs.add(B)
    return sorted(subs)

def map_coord_subspace(U, sub_basis):
    vecs=[]
    for c in sub_basis:
        v=0
        for i,b in enumerate(U):
            if (c>>i)&1:
                v ^= b
        vecs.append(v)
    return canonical_span(vecs)

def reduce_mod(v,U):
    x=v
    for b in U:
        p=b.bit_length()-1
        if (x>>p)&1:
            x ^= b
    return x

def subcode_dim_supported_in(U,binary_mats):
    images=[]
    for M in binary_mats:
        pack=0
        for c,v in enumerate(M):
            pack |= reduce_mod(v,U) << (224*c)
        images.append(pack)
    return 16-len(canonical_span(images))

def sigma(t,j):
    z=1
    for i in range(j):
        z *= 2**t - 2**i
    return z

def log2_sum_terms(terms):
    logs=[log2(A)+log2(sigma(t,j))-r*c for A,j,c,r,t in terms]
    m=max(logs)
    return m+log2(sum(2**(x-m) for x in logs))

def main():
    # Exact current compiler fixture: N=3,R=1, GF(16), impossible label 8.
    F=Field(16,0b10011)
    N=3; R=1
    S=spec(N,R,F)
    eqs=[lambda w,F,N=N:
         F.add[F.sum(F.mul[1<<i][w[i]] for i in range(N))][1<<N]]
    words,enc,BB=table_space(S,eqs)
    check(len(BB)==4)
    check(not any(all(eq(w,F)==0 for eq in eqs) for w in words))
    check(len(BB[0])==224)

    # Restrict scalars exactly as the published source checker.
    binary_mats=[]
    for row in BB:
        for j in range(4):
            scalar=1<<j
            scaled=[F.mul[scalar][x] for x in row]
            bm=descend(reshape(scaled,N+1),F)  # 224 x 4
            binary_mats.append(cols_from_binary_matrix(bm))
    check(len(binary_mats)==16)

    # Check coefficient-basis independence as matrices.
    packed=[sum(v << (224*c) for c,v in enumerate(M))
            for M in binary_mats]
    check(len(canonical_span(packed))==16)

    # Enumerate every nonzero binary source word by Gray code.
    rank_hist=Counter()
    spaces={}
    rank3=[]
    rank4=[]
    cur=[0,0,0,0]
    prevg=0
    global_cols=[]
    for k in range(1,1<<16):
        g=k^(k>>1)
        diff=g^prevg
        idx=(diff & -diff).bit_length()-1
        cur=xor_cols(cur,binary_mats[idx])
        prevg=g
        U=canonical_span(cur)
        rank_hist[len(U)] += 1
        spaces[g]=U
        global_cols.extend(cur)
        (rank3 if len(U)==3 else rank4).append((g,U))
    check(rank_hist==Counter({3:225,4:65310}))
    check(len(set(spaces.values()))==65535,
          "distinct source words unexpectedly share a column space")
    global_support=canonical_span(global_cols)
    check(len(global_support)==24)

    # The rank-3 words are exactly 15 GF(16)-projective lines.
    def coeff_tuple(g):
        return tuple((g>>(4*i))&0xF for i in range(4))
    def normalize_field_line(c):
        for x in c:
            if x:
                inv=F.inv[x]
                return tuple(F.mul[inv][z] for z in c)
        raise AssertionError
    line_counts=Counter(normalize_field_line(coeff_tuple(g)) for g,_ in rank3)
    check(len(line_counts)==15)
    check(set(line_counts.values())=={15})

    # Exact rank3-rank3 pair support.
    pair33=Counter()
    min_2spaces=set()
    min_word_pair_inc=Counter()
    for i in range(len(rank3)):
        g1,U1=rank3[i]
        for j in range(i+1,len(rank3)):
            g2,U2=rank3[j]
            c=len(canonical_span(U1+U2))
            pair33[c]+=1
            if c==5:
                W=canonical_span([g1,g2])
                min_2spaces.add(W)
                min_word_pair_inc[g1]+=1
                min_word_pair_inc[g2]+=1
    check(pair33==Counter({5:1260,6:23940}))
    check(len(min_2spaces)==420)
    check(Counter(min_word_pair_inc.values())==Counter({12:210}))
    check(len(rank3)-len(min_word_pair_inc)==15)

    # Incidence controls needed to count all 2D subcodes without 2^31 pair loop.
    sub2_in3=all_hyperplanes(3)   # 7
    sub2_in4=all_2spaces_F2_4()   # 35
    sub3_in4=all_hyperplanes(4)   # 15
    check((len(sub2_in3),len(sub2_in4),len(sub3_in4))==(7,35,15))

    # No rank3 space is contained in a rank4 space; no rank3/rank4 pair
    # has intersection dimension >=2.
    rank3_spaces={U for _,U in rank3}
    rank3_2inc=Counter()
    rank3_1inc=Counter()
    for _,U in rank3:
        for sb in sub2_in3:
            rank3_2inc[map_coord_subspace(U,sb)] += 1
        for c in range(1,8):
            v=0
            for i,b in enumerate(U):
                if (c>>i)&1: v^=b
            rank3_1inc[v]+=1
    check(sum(rank3_2inc.values())==225*7)
    check(max(rank3_2inc.values())==1)

    cross_intersection2plus=0
    cross_intersection1=0
    for _,U in rank4:
        for sb in sub2_in4:
            cross_intersection2plus += rank3_2inc.get(
                map_coord_subspace(U,sb),0)
        for c in range(1,16):
            v=0
            for i,b in enumerate(U):
                if (c>>i)&1: v^=b
            cross_intersection1 += rank3_1inc.get(v,0)
    check(cross_intersection2plus==0)
    check(cross_intersection1==62370)

    # Rank4/rank4: no 3D intersection; count exact 2D intersections via
    # the 35 two-subspaces per rank4 word. Pack two 224-bit basis vectors.
    hyper3_seen=Counter()
    sub2_seen=Counter()
    vector_inc4=Counter()
    shift=224
    for _,U in rank4:
        for sb in sub3_in4:
            H=map_coord_subspace(U,sb)
            key=H[0] | (H[1]<<shift) | (H[2]<<(2*shift))
            hyper3_seen[key]+=1
        for sb in sub2_in4:
            H=map_coord_subspace(U,sb)
            key=H[0] | (H[1]<<shift)
            sub2_seen[key]+=1
        for c in range(1,16):
            v=0
            for i,b in enumerate(U):
                if (c>>i)&1: v^=b
            vector_inc4[v]+=1
    check(max(hyper3_seen.values())==1)
    check(sum(m*(m-1)//2 for m in sub2_seen.values())==8820)
    check(max(sub2_seen.values())==2)
    one_dim_pair_inc=sum(m*(m-1)//2 for m in vector_inc4.values())
    check(one_dim_pair_inc==7642845)
    pair44_int2=8820
    pair44_int1=one_dim_pair_inc-3*pair44_int2
    check(pair44_int1==7616385)

    # Complete pair-support histogram, hence complete j=2 support enumerator.
    pair_hist=Counter()
    pair_hist[5]+=1260
    pair_hist[6]+=23940
    pair_hist[6]+=cross_intersection1
    pair_hist[7]+=225*65310-cross_intersection1
    pair_hist[6]+=pair44_int2
    pair_hist[7]+=pair44_int1
    total44=comb(65310,2)
    pair_hist[8]+=total44-pair44_int2-pair44_int1
    check(sum(pair_hist.values())==comb(65535,2))
    check(pair_hist==Counter({
        5:1260,
        6:95130,
        7:22248765,
        8:2125040190,
    }))
    A2={c:n//3 for c,n in sorted(pair_hist.items())}
    check(A2=={
        5:420,
        6:31710,
        7:7416255,
        8:708346730,
    })
    check(sum(A2.values())==715795115)

    # Generalized support weights d1=3, d2=5.
    d1=min(rank_hist)
    d2=min(A2)
    check((d1,d2)==(3,5))

    # Exact d3=6:
    # every support-5 2D subcode has no extra source word inside the same
    # support, so no 3D subcode has support 5; one explicit extension has 6.
    support5_subcode_dims=Counter()
    example_W3=None
    for W in min_2spaces:
        g1,g2=W
        U=canonical_span(source_cols(binary_mats,g1)+
                         source_cols(binary_mats,g2))
        check(len(U)==5)
        subdim=subcode_dim_supported_in(U,binary_mats)
        support5_subcode_dims[subdim]+=1
        if example_W3 is None:
            Wspan={0,g1,g2,g1^g2}
            for g in range(1,1<<16):
                if g in Wspan: continue
                U3=canonical_span(U+tuple(source_cols(binary_mats,g)))
                if len(U3)==6:
                    example_W3=canonical_span([g1,g2,g])
                    break
    check(support5_subcode_dims==Counter({2:420}))
    check(example_W3 is not None and len(example_W3)==3)
    U3=canonical_span(sum(
        (source_cols(binary_mats,g) for g in example_W3), []))
    check(len(U3)==6)
    d3=6

    # Known j=1 and exact j=2 contributions to the Run-213 support-sum bound.
    A1={3:225,4:65310}
    def partial_log2(r,t):
        terms=[]
        for c,A in A1.items():
            terms.append((A,1,c,r,t))
        for c,A in A2.items():
            terms.append((A,2,c,r,t))
        return log2_sum_terms(terms)
    p74=partial_log2(74,86)
    p78=partial_log2(78,90)
    check(abs(p74-(-128.18621880878297))<1e-12)
    check(abs(p78-(-136.18621880878297))<1e-12)
    first=None
    for r in range(1,200):
        t=r+12
        if partial_log2(r,t)<-136:
            first=(r,t,partial_log2(r,t))
            break
    check(first[0:2]==(78,90))

    # Literature terminology sanity: these are matrix-code support weights,
    # not a claim that classical generic-group security becomes QPT security.
    out={
        "run":214,
        "python":sys.version.split()[0],
        "assertions":ASSERTIONS,
        "exact_fixture":{
            "N":3,
            "R":1,
            "field":"GF(16), x^4+x+1",
            "gamma":S["gamma"],
            "gamma_order":F.order(S["gamma"]),
            "field_source_dimension":len(BB),
            "binary_source_dimension":16,
            "binary_matrix_shape":[224,4],
            "global_column_support_dimension":24,
            "nonzero_rank_histogram":dict(sorted(rank_hist.items())),
            "distinct_nonzero_column_spaces":len(set(spaces.values())),
            "rank3_GF16_projective_lines":len(line_counts),
        },
        "generalized_column_support":{
            "d1":d1,
            "d2":d2,
            "d3":d3,
            "A1":A1,
            "A2":A2,
            "rank3_pair_support_histogram":dict(sorted(pair33.items())),
            "support5_2D_subspaces":len(min_2spaces),
            "support5_2D_subcode_dimensions":
                dict(sorted(support5_subcode_dims.items())),
            "example_support6_3D_basis_coefficients":
                list(example_W3),
        },
        "incidence_counts":{
            "rank3_rank4_pairs_intersection_dim1":cross_intersection1,
            "rank3_rank4_pairs_intersection_dim_ge2":cross_intersection2plus,
            "rank4_rank4_pairs_intersection_dim2":pair44_int2,
            "rank4_rank4_pairs_intersection_dim1":pair44_int1,
            "rank4_rank4_pairs_intersection_dim3":0,
        },
        "support_sum_known_terms":{
            "r74_t86_log2_j1_plus_j2":p74,
            "r78_t90_log2_j1_plus_j2":p78,
            "first_r_with_t_eq_r_plus_12_below_2^-136":
                {"r":first[0],"t":first[1],"log2":first[2]},
            "qualification":
                "This is only the exact j=1 and j=2 contribution; j>=3 spectrum remains unenumerated.",
        },
        "status":"PASS",
    }
    out["assertions"]=ASSERTIONS
    print(json.dumps(out,indent=2,sort_keys=True))

if __name__=="__main__":
    main()
