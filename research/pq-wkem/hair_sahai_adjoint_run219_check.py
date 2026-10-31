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
    engine=root/"hair_sahai_adjoint_run219_engine.cpp"
    check(engine.exists(),"missing companion C++ engine")

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

    packed=[sum(v<<(224*c) for c,v in enumerate(M))
            for M in binary_mats]
    check(len(canonical_span(packed))==16)

    global_support=canonical_span(
        [col for M in binary_mats for col in M])
    check(len(global_support)==24)

    cmats=[[coords_in_basis(col,global_support) for col in M]
           for M in binary_mats]
    check(len(canonical_span([v for M in cmats for v in M]))==24)

    # Construct the adjoint D(y): four 16-bit source-functional rows for each
    # of the 24 ambient-dual basis functionals.
    dual_basis=[]
    for p in range(24):
        dual_basis.append(dual_rows(1<<p,cmats))
    packed_dual=[
        sum(row<<(16*j) for j,row in enumerate(Rs))
        for Rs in dual_basis
    ]
    check(len(canonical_span(packed_dual))==24,
          "adjoint map unexpectedly has a kernel")

    # Exact primal-capacity / adjoint-row-support identity:
    # m_C(U) = 16 - rowsupp_D(U^perp).
    identity_fixtures=[]

    def test_U(name,U):
        U=canonical_span(U)
        L=gf2_nullspace_rows(U,24)
        cap=source_capacity(U,cmats)
        rs=len(dual_row_support(L,cmats))
        check(cap==16-rs,
              f"capacity/adjoint identity failed for {name}")
        identity_fixtures.append({
            "name":name,
            "ambient_support_dimension":len(U),
            "orthogonal_dimension":len(L),
            "source_capacity":cap,
            "adjoint_row_support":rs,
        })

    test_U("zero",())
    test_U("full",tuple(1<<i for i in range(24)))

    # Deterministic source-derived supports.
    M0=cmats[0]
    test_U("basis_word_0_columns",M0)
    test_U("basis_words_0_1_columns",cmats[0]+cmats[1])
    test_U("basis_words_0_1_2_columns",cmats[0]+cmats[1]+cmats[2])

    # Explicit support-nine four-dimensional source subcode.  This is a
    # self-contained adjoint witness e_15(D) <= 12: its support U has dim 9,
    # source capacity 4, hence U^perp has dim 15 and adjoint row support 12.
    def cols_for_coeff(g):
        out=[0,0,0,0]
        for i,M in enumerate(cmats):
            if (g>>i)&1:
                out=[a^b for a,b in zip(out,M)]
        return out

    explicit_W4=(39234,1002,6,1)
    check(len(canonical_span(explicit_W4))==4)
    U4=canonical_span([
        col
        for g in explicit_W4
        for col in cols_for_coeff(g)
    ])
    check(len(U4)==9)
    check(source_capacity(U4,cmats)==4)
    test_U("explicit_support9_W4_capacity4",U4)

    # Deterministic coordinate-space fixtures.
    for c in (3,5,8,9,12,17,21):
        test_U(f"coordinate_prefix_{c}",tuple(1<<i for i in range(c)))

    # Derive the transported GF(16)-module action on A^*.
    # If Q_lam is multiplication-by-lam on the compressed primal ambient,
    # the natural dual field action is Q_lam^T.
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

    # Verify module laws exhaustively on coordinate basis and field scalars.
    for p in range(24):
        y=1<<p
        check(dual_field_scale(y,1)==y)
        for a in range(16):
            for b in range(16):
                check(
                    dual_field_scale(y,F.add[a][b]) ==
                    (dual_field_scale(y,a)^dual_field_scale(y,b)),
                    "dual field additivity failed")
                check(
                    dual_field_scale(dual_field_scale(y,a),b) ==
                    dual_field_scale(y,F.mul[a][b]),
                    "dual field multiplication failed")

    # The chosen compressed basis splits into six identical transported
    # four-bit field coordinates.  Verify rather than assume it.
    def nibble_action(x,lam):
        return dual_field_scale(x,lam)&0xF

    for p in range(24):
        y=1<<p
        for lam in range(16):
            expected=0
            for block in range(6):
                x=(y>>(4*block))&0xF
                expected |= nibble_action(x,lam)<<(4*block)
            check(dual_field_scale(y,lam)==expected,
                  "dual field action is not chunkwise in derived basis")

    scalar_basis=(1,2,4,8)
    lookup=[[nibble_action(x,lam) for x in range(16)]
            for lam in scalar_basis]
    for a,row in zip(scalar_basis,lookup):
        check(len(set(row))==16 if a else True)

    # Run exact 2^24 and projective-line census in the companion engine.
    inp=[]
    for Rs in dual_basis:
        inp.append(" ".join(str(x) for x in Rs))
    for row in lookup:
        inp.append(" ".join(str(x) for x in row))
    input_text="\n".join(inp)+"\n"

    with tempfile.TemporaryDirectory(prefix="run219-") as td:
        exe=Path(td)/"engine"
        subprocess.run(
            ["g++","-O3","-std=c++17",str(engine),"-o",str(exe)],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        raw=subprocess.run(
            [str(exe)],
            input=input_text,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        ).stdout
    census=json.loads(raw)

    expected_rank={"0":0,"1":0,"2":525,"3":59850,"4":16716840}
    check(census["rank_histogram"]==expected_rank)
    check(sum(census["rank_histogram"].values())==(1<<24)-1)
    check(census["projective_line_total"]==(16**6-1)//15)

    expected_lines=[
        {"representative_rank":2,"row_support":8,"count":35},
        {"representative_rank":3,"row_support":8,"count":406},
        {"representative_rank":3,"row_support":12,"count":3584},
        {"representative_rank":4,"row_support":8,"count":88},
        {"representative_rank":4,"row_support":12,"count":66048},
        {"representative_rank":4,"row_support":16,"count":1048320},
    ]
    check(census["field_line_histogram"]==expected_lines)

    # Each transported field line has 15 nonzero words and constant matrix rank.
    by_rank=Counter()
    by_support=Counter()
    for row in expected_lines:
        by_rank[row["representative_rank"]] += 15*row["count"]
        by_support[row["row_support"]] += row["count"]
    check(dict(sorted(by_rank.items()))=={2:525,3:59850,4:16716840})
    check(dict(sorted(by_support.items()))=={
        8:529,
        12:69632,
        16:1048320,
    })

    # Consequences of the exact branch-published d1=3,d2=5,d3=6 via
    # d_j(C)=24-max{s:e_s(D)<=16-j}.  These are algebraic translations,
    # not additional assumptions.
    dual_tail={
        "e19":14,
        "e20":15,
        "e21":15,
        "e22":16,
        "e23":16,
        "e24":16,
        "e18_upper_bound":13,
    }

    out={
        "run":219,
        "python":sys.version.split()[0],
        "compiler_fixture":{
            "N":3,
            "R":1,
            "field":"GF(16), x^4+x+1",
            "gamma":S["gamma"],
            "gamma_order":F.order(S["gamma"]),
            "source_dimension_binary":16,
            "matrix_shape_after_descent":[224,4],
            "global_column_support_dimension":24,
        },
        "adjoint_code":{
            "binary_dimension":24,
            "matrix_shape":[4,16],
            "rank_histogram":census["rank_histogram"],
            "minimum_nonzero_rank":2,
            "transported_GF16_module_dimension":6,
            "projective_line_total":census["projective_line_total"],
            "field_line_histogram":census["field_line_histogram"],
            "field_line_support_totals":dict(sorted(by_support.items())),
        },
        "capacity_adjoint_identity":{
            "formula":"m_C(U)=16-dim(RowSupp(D(U^perp)))",
            "fixtures":identity_fixtures,
            "generalized_profile_formula":
                "d_j(C)=24-max{s : e_s(D)<=16-j}",
            "d5_target":
                "explicit support-9 W4 gives e15(D)<=12; d5(C)<=9 iff e15(D)<=11, so the unresolved drop is exactly 12 -> 11",
            "branch_published_d1_d2_d3_implied_dual_tail":dual_tail,
        },
        "scope":{
            "proved":
                "exact finite adjoint construction, dual identity, exhaustive rank census, and complete transported-GF16 projective-line row-support spectrum for this literal false-source fixture",
            "not_proved":
                "e15(D), d5(C), the full generalized-support tail, generic-NP false hiding, arbitrary-QPT ORIGINAL-witness extraction, or malicious distributed setup",
        },
        "status":"PASS",
        "assertions":ASSERTIONS,
    }
    out["assertions"]=ASSERTIONS
    print(json.dumps(out,indent=2,sort_keys=True))

if __name__=="__main__":
    main()
