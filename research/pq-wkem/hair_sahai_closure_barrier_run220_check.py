#!/usr/bin/env python3
"""Run 219 exact adjoint-dual checkpoint for the current Hair--Sahai
N=3,R=1 GF(16) false source.

The checker is deterministic.  It reconstructs the exact weighted-table source,
compresses its global column support to dimension 24, constructs the adjoint
24-dimensional operator code D <= Mat_{4 x 16}(F_2), proves/validates the
primal-capacity/adjoint-row-support identity on deterministic fixtures, and
invokes the companion C++ engine for exhaustive 2^24 and GF(16)-projective
censuses.  No network, production code, or secrets are used.
"""
from __future__ import annotations

from collections import Counter
from itertools import product
import json
from pathlib import Path
import subprocess
import sys
import tempfile

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
    def sum(self,xs):
        z=0
        for x in xs: z=self.add[z][x]
        return z
    def order(self,a):
        z=1
        for i in range(1,self.q):
            z=self.mul[z][a]
            if z==1: return i
        raise AssertionError("not a field element")
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

def span_field(rows,F):
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

def reshape(v,c):
    return [v[i:i+c] for i in range(0,len(v),c)]

def lincomb(rows,c,F):
    return [F.sum(F.mul[a][row[i]] for a,row in zip(c,rows))
            for i in range(len(rows[0]))]

def alphas(R):
    return [a for a in product(range(R+1),repeat=R) if sum(a)<=R]

def spec(N,R,F):
    check(F.q>2*N*R)
    gamma=F.choose_generator(N)
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
    basis=span_field([lincomb(enc,c,F) for c in coeffs],F)
    return words,enc,basis

def descend(mat,F):
    h=F.q.bit_length()-1
    return [[(entry>>bit)&1 for entry in row]
            for row in mat for bit in range(h)]

def cols_from_binary_matrix(mat):
    cols=[]
    for c in range(len(mat[0])):
        v=0
        for i,row in enumerate(mat):
            if row[c]: v |= 1<<i
        cols.append(v)
    return cols

def canonical_span(vecs):
    basis={}
    for x in vecs:
        v=x
        for p,w in sorted(basis.items(), reverse=True):
            if (v>>p)&1: v ^= w
        if v:
            p=v.bit_length()-1
            for q in list(basis):
                if (basis[q]>>p)&1: basis[q]^=v
            basis[p]=v
    ps=sorted(basis,reverse=True)
    for p in ps:
        for q in ps:
            if q!=p and ((basis[q]>>p)&1):
                basis[q]^=basis[p]
    return tuple(basis[p] for p in sorted(basis,reverse=True))

def reduce_by_basis(v,B):
    x=v
    for b in B:
        p=b.bit_length()-1
        if (x>>p)&1: x ^= b
    return x

def coords_in_basis(v,B):
    x=v; coeff=0
    for i,b in enumerate(B):
        p=b.bit_length()-1
        if (x>>p)&1:
            x ^= b
            coeff |= 1<<i
    check(x==0,"vector not in declared basis span")
    return coeff

def gf2_nullspace_rows(rows,nvars):
    A=list(rows)
    piv=[]; r=0
    for col in range(nvars):
        p=next((i for i in range(r,len(A)) if (A[i]>>col)&1),None)
        if p is None: continue
        A[r],A[p]=A[p],A[r]
        for i in range(len(A)):
            if i!=r and ((A[i]>>col)&1): A[i]^=A[r]
        piv.append(col); r+=1
    free=[c for c in range(nvars) if c not in piv]
    out=[]
    for f in free:
        v=1<<f
        for i,p in enumerate(piv):
            if (A[i]>>f)&1: v |= 1<<p
        out.append(v)
    return canonical_span(out)

def source_capacity(U,cmats):
    packed=[]
    for M in cmats:
        z=0
        for j,col in enumerate(M):
            z |= reduce_by_basis(col,U) << (24*j)
        packed.append(z)
    return 16-len(canonical_span(packed))

def dual_rows(y,cmats):
    rows=[]
    for j in range(4):
        r=0
        for i in range(16):
            if ((cmats[i][j]&y).bit_count()&1):
                r |= 1<<i
        rows.append(r)
    return rows

def dual_row_support(L,cmats):
    return canonical_span([row for y in L for row in dual_rows(y,cmats)])

def mul_ambient(v,lam,F):
    out=0
    for block in range(56):
        a=(v>>(4*block))&0xF
        out |= F.mul[lam][a] << (4*block)
    return out

def main():
    root=Path(__file__).resolve().parent
    engine=root/"hair_sahai_fieldspan2_run220_engine.cpp"
    check(engine.exists(),"missing companion C++ engine")

    # Exact branch-published Run-214 source fixture.
    F=Field(16,0b10011)
    N=3; R=1
    S=spec(N,R,F)
    eqs=[lambda w,F,N=N:
         F.add[F.sum(F.mul[1<<i][w[i]] for i in range(N))][1<<N]]
    words,enc,BB=table_space(S,eqs)
    check(len(BB)==4)
    check(not any(all(eq(w,F)==0 for eq in eqs) for w in words))
    check(len(BB[0])==224)

    binary_mats=[]
    for row in BB:
        for j in range(4):
            scalar=1<<j
            scaled=[F.mul[scalar][x] for x in row]
            bm=descend(reshape(scaled,N+1),F)
            binary_mats.append(cols_from_binary_matrix(bm))
    check(len(binary_mats)==16)

    packed=[sum(v<<(224*c) for c,v in enumerate(M)) for M in binary_mats]
    check(len(canonical_span(packed))==16)
    global_support=canonical_span([col for M in binary_mats for col in M])
    check(len(global_support)==24)
    cmats=[[coords_in_basis(col,global_support) for col in M]
           for M in binary_mats]
    check(len(canonical_span([v for M in cmats for v in M]))==24)

    # Exact rank census to pin the same literal source as Run 214.
    rank_hist={3:0,4:0}
    cur=[0,0,0,0]; prev=0
    for k in range(1,1<<16):
        g=k^(k>>1); diff=g^prev; idx=(diff&-diff).bit_length()-1
        cur=[a^b for a,b in zip(cur,cmats[idx])]; prev=g
        rr=len(canonical_span(cur))
        check(rr in (3,4))
        rank_hist[rr]+=1
    check(rank_hist=={3:225,4:65310})

    # Feed only exact compressed current-source columns to the generic engine.
    engine_input="\n".join(" ".join(str(x) for x in M) for M in cmats)+"\n"
    import tempfile, subprocess
    with tempfile.TemporaryDirectory(prefix="run220-") as td:
        exe=Path(td)/"engine"
        subprocess.run(["g++","-O3","-std=c++17",str(engine),"-o",str(exe)],
                       check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        cp=subprocess.run([str(exe)],input=engine_input,check=True,
                          stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    census=json.loads(cp.stdout)

    check(census["field_planes_total"]==70161)
    check(census["field_plane_support_histogram"]=={"20":529,"24":69632})
    check(census["support20_planes"]==529)
    check(census["binary_5_subspaces_per_plane"]==97155)
    check(census["support20_binary_5_checked"]==51394995)
    check(census["support20_min_exact_support"]==13)
    check(census["support20_le11_count"]==0)
    check(census["support20_subspace_histogram"]=={
        "13":8820,
        "14":168315,
        "15":785445,
        "16":1652610,
        "17":3159180,
        "18":13674885,
        "19":23815680,
        "20":8130060,
    })
    check(sum(census["support20_subspace_histogram"].values())==51394995)

    # General codimension bound: adding one source dimension adds at most four
    # column vectors.  Therefore if H is a binary 8D GF(16)-plane and K is a
    # binary 5D subspace, c(K) >= c(H)-4*(8-5).  For support-24 field planes
    # this is >=12.  The exhaustive support-20 family is even stronger: >=13.
    support24_codim3_lower=24-4*3
    check(support24_codim3_lower==12)
    field_span2_global_lower=min(support24_codim3_lower,
                                 census["support20_min_exact_support"])
    check(field_span2_global_lower==12)

    # Verify the engine's support-13 example is genuinely binary dimension 5,
    # has GF(16) span dimension exactly 2, and exact column support 13.
    example=tuple(census["support13_example_basis"])
    check(len(canonical_span(example))==5)
    def cols_for_coeff(g):
        out=[0,0,0,0]
        for i,M in enumerate(cmats):
            if (g>>i)&1:
                out=[a^b for a,b in zip(out,M)]
        return out
    Uex=canonical_span([col for g in example for col in cols_for_coeff(g)])
    check(len(Uex)==13)
    field_rows=[[(g>>(4*i))&15 for i in range(4)] for g in example]
    _,field_piv=rref(field_rows,F)
    check(len(field_piv)==2)

    # Independently reverify the conversation-handoff explicit support-10 W5.
    # It is not used to prove the field-span-2 exclusion; it only records that
    # the global d5 upper bound 10 has an exact witness in this same fixture.
    explicit_W5=(39234,970,32,6,1)
    check(len(canonical_span(explicit_W5))==5)
    U5=canonical_span([col for g in explicit_W5 for col in cols_for_coeff(g)])
    check(len(U5)==10)
    frows5=[[(g>>(4*i))&15 for i in range(4)] for g in explicit_W5]
    _,piv5=rref(frows5,F)
    check(len(piv5)==4)
    check(source_capacity(U5,cmats)==5)

    # Build the exact adjoint operator code D <= Mat_(4 x 16)(F2).
    # Map each four-bit coefficient functional to its trace-dual GF(16)
    # coefficient so the transported field structure is explicit rather than
    # assumed.
    tr=[]
    for a in range(16):
        z=0; x=a
        for _ in range(4):
            z ^= x
            x=F.mul[x][x]
        tr.append(z&1)
    functional_to_field={}
    for rr in range(16):
        for a in range(16):
            if all((((rr&w).bit_count()&1)==tr[F.mul[a][w]]) for w in range(16)):
                functional_to_field[rr]=a
                break
    check(len(functional_to_field)==16)

    def row_to_field(row16):
        return [functional_to_field[(row16>>(4*i))&15] for i in range(4)]

    # Six GF(16)-basis generators of the adjoint 4x4 field matrix code E.
    E=[]
    for block in range(6):
        rows=dual_rows(1<<(4*block),cmats)
        E.append([row_to_field(r) for r in rows])

    def rank_field(A):
        if not A: return 0
        Rr,piv=rref(A,F)
        return len(piv)

    def dotF(a,b):
        return F.sum(F.mul[x][y] for x,y in zip(a,b))

    # Enumerate all 4369 GF(16)-hyperplanes of the four-dimensional row
    # ambient.  For each hyperplane R_F, compute the GF(16)-dimension of the
    # adjoint-domain preimage {y: Row(E(y)) <= R_F}.
    preimage_hist={}
    for pos in range(4):
        tail_len=3-pos
        from itertools import product
        for tail in product(range(16), repeat=tail_len):
            h=[0]*pos+[1]+list(tail)
            A=[]
            for outrow in range(4):
                A.append([dotF(h,E[k][outrow]) for k in range(6)])
            pre=6-rank_field(A)
            preimage_hist[pre]=preimage_hist.get(pre,0)+1
    check(preimage_hist=={2:4352,3:17})

    # Consequence: no GF(16)-4D domain subspace can have field row support <=3,
    # because it would be contained in one of the preimages above, all of which
    # have field dimension <=3.  Hence every field-4D H has full field row
    # support 4 (binary support 16).  A binary 15D L with field span H is a
    # hyperplane of H; adding its one missing binary vector contributes <=4
    # rows, so RowSupp(D(L)) >= 16-4 = 12.
    adjoint_fieldspan4_lower=12
    check(adjoint_fieldspan4_lower==12)

    # Reverify the explicit e15 <= 12 witness from the support-9 capacity-4 W4.
    explicit_W4=(39234,1002,6,1)
    check(len(canonical_span(explicit_W4))==4)
    U4=canonical_span([col for g in explicit_W4 for col in cols_for_coeff(g)])
    check(len(U4)==9)
    check(source_capacity(U4,cmats)==4)
    L4=gf2_nullspace_rows(U4,24)
    check(len(L4)==15)
    rowsupp4=dual_row_support(L4,cmats)
    check(len(rowsupp4)==12)

    # Derive the transported GF(16) action on the compressed adjoint domain and
    # verify this explicit 15D witness has full field closure dimension 6.  Thus
    # the known e15<=12 witness is not in the field-span-4 case excluded above.
    Qcols={}
    for lam in range(16):
        if lam==0:
            Qcols[lam]=[0]*24
        else:
            Qcols[lam]=[
                coords_in_basis(mul_ambient(b,lam,F),global_support)
                for b in global_support
            ]
    def dual_field_scale(y,lam):
        if lam==0: return 0
        yp=0
        for i,col in enumerate(Qcols[lam]):
            if ((col&y).bit_count()&1): yp |= 1<<i
        return yp
    closure=canonical_span([
        dual_field_scale(y,lam)
        for y in L4 for lam in (1,2,4,8)
    ])
    check(len(closure)==24)

    out={
        "run":220,
        "python":sys.version.split()[0],
        "assertions":ASSERTIONS,
        "fixture":{
            "N":3,
            "R":1,
            "field":"GF(16), x^4+x+1",
            "source_dimension_binary":16,
            "compressed_column_ambient_dimension":24,
            "rank_histogram":rank_hist,
        },
        "field_span_2_primal_search":{
            **census,
            "support24_plane_codim3_lower_bound":support24_codim3_lower,
            "all_field_span_2_W5_support_lower_bound":field_span2_global_lower,
            "conclusion":"No binary 5D source subcode with GF(16)-span 2 can have column support <=11; support <=9 is therefore impossible in this closure class.",
        },
        "independent_global_upper_witness":{
            "basis":list(explicit_W5),
            "column_support":len(U5),
            "GF16_span_dimension":len(piv5),
            "ambient_source_capacity":source_capacity(U5,cmats),
        },
        "adjoint_scalar_closure":{
            "field_row_hyperplane_preimage_dimension_histogram":preimage_hist,
            "binary_15D_L_with_GF16_span_4_row_support_lower_bound":adjoint_fieldspan4_lower,
            "explicit_e15_upper_witness":{
                "primal_W4_basis":list(explicit_W4),
                "primal_support":len(U4),
                "primal_ambient_capacity":source_capacity(U4,cmats),
                "adjoint_L_dimension":len(L4),
                "adjoint_row_support":len(rowsupp4),
                "adjoint_GF16_closure_dimension":len(closure)//4,
            },
            "conclusion":"e15(D)<=12 is independently reverified; any hypothetical e15(D)<=11 witness must have adjoint GF(16)-span 5 or 6, not 4.",
        },
        "combined_narrowing":{
            "hypothetical_primal_support_le9_W5_requires_GF16_span_at_least":3,
            "hypothetical_adjoint_e15_le11_L_requires_GF16_span_at_least":5,
            "remaining_question":"Does e15(D)=11 or 12 in the GF(16)-span-5/6 cases?",
        },
        "scope":{
            "proved":"Exact finite closure-class exclusions and exhaustive 51,394,995-subspace field-span-2 census for the literal current false-source fixture.",
            "not_proved":"e15(D)=12 globally, d5(C)=10 globally, full false-instance hiding, arbitrary-QPT ORIGINAL-witness extraction, or malicious distributed setup.",
        },
        "status":"PASS",
    }
    out["assertions"]=ASSERTIONS
    print(json.dumps(out,indent=2,sort_keys=True))

if __name__=="__main__":
    main()
