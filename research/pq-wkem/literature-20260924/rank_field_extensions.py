#!/usr/bin/env python3
"""New finite checks of order-parameterized weighted-table compilers.
Not the failed-upload checker from the preceding literature assessment.
Standard library only. Small exhaustive encodings are validation oracles,
not a claim that enumerating assignments is the polynomial general compiler.
"""
from itertools import product, combinations
from fractions import Fraction
from math import comb
import json, random

class Field:
    def __init__(self, q, poly=None):
        self.q=q; self.poly=poly
        self.char=2 if poly else q
        self.add=[[self._add(a,b) for b in range(q)] for a in range(q)]
        self.mul=[[self._mul(a,b) for b in range(q)] for a in range(q)]
        self.neg=[0 if a==0 else next(b for b in range(q) if self.add[a][b]==0) for a in range(q)]
        self.inv=[0]+[next(b for b in range(1,q) if self.mul[a][b]==1) for a in range(1,q)]
    def _add(self,a,b): return a^b if self.poly else (a+b)%self.q
    def _mul(self,a,b):
        if not self.poly: return a*b%self.q
        z=0
        while b:
            if b&1:z^=a
            b>>=1; a<<=1
            if a&self.q:a^=self.poly
        return z
    def pow(self,a,k):
        z=1
        while k:
            if k&1:z=self.mul[z][a]
            k>>=1;a=self.mul[a][a]
        return z
    def integer(self,n):return n%self.char
    def sub(self,a,b):return self.add[a][self.neg[b]]
    def sum(self,xs):
        z=0
        for x in xs:z=self.add[z][x]
        return z
    def order(self,a):
        z=1
        for i in range(1,self.q):
            z=self.mul[z][a]
            if z==1:return i
        raise AssertionError('not field')
    def choose_generator(self,N):return next(a for a in range(1,self.q) if self.order(a)>N)

def rref(rows,F):
    A=[r[:] for r in rows]
    if not A:return [],[]
    r=0; piv=[]; mul,add=F.mul,F.add
    for c in range(len(A[0])):
        j=next((i for i in range(r,len(A)) if A[i][c]),None)
        if j is None:continue
        A[r],A[j]=A[j],A[r]
        sc=F.inv[A[r][c]];A[r]=[mul[sc][x] for x in A[r]]
        for i in range(len(A)):
            if i!=r and A[i][c]:
                sc=F.neg[A[i][c]]
                A[i]=[add[x][mul[sc][y]] for x,y in zip(A[i],A[r])]
        piv.append(c);r+=1
        if r==len(A):break
    return A,piv

def rank(A,F):return len(rref(A,F)[1])
def nullspace(A,F,ncols=None):
    if not A:
        return [[int(i==j) for i in range(ncols)] for j in range(ncols)]
    R,piv=rref(A,F);n=len(A[0]);out=[]
    for c in range(n):
        if c not in piv:
            v=[0]*n;v[c]=1
            for i,p in enumerate(piv):v[p]=F.neg[R[i][c]]
            out.append(v)
    return out

def span(rows,F):
    # Incremental echelon basis with normalized pivots, not full rref.
    B={}
    for row in rows:
        v=row[:]
        for p,w in sorted(B.items()):
            if v[p]:
                z=F.neg[v[p]]
                v=[F.add[x][F.mul[z][y]] for x,y in zip(v,w)]
        p=next((i for i,x in enumerate(v) if x),None)
        if p is not None:
            z=F.inv[v[p]];B[p]=[F.mul[z][x] for x in v]
    return [v for _,v in sorted(B.items())]

def flatten(A):return [x for row in A for x in row]
def reshape(v,c):return [v[i:i+c] for i in range(0,len(v),c)]
def lincomb(rows,c,F):return [F.sum(F.mul[a][row[i]] for a,row in zip(c,rows)) for i in range(len(rows[0]))]

def alphas(R):return [a for a in product(range(R+1),repeat=R) if sum(a)<=R]

def spec(N,R,F,gamma=None):
    assert F.q>2*N*R
    gamma=F.choose_generator(N) if gamma is None else gamma
    assert F.order(gamma)>N
    aa=alphas(R); ts=list(range(2*N*R+1))
    coeff=[[[F.pow(F.mul[F.pow(gamma,j)][t],i) for i in range(N+1)] for j in range(R)] for t in ts]
    return {'N':N,'R':R,'F':F,'gamma':gamma,'aa':aa,'ts':ts,'coeff':coeff}

def encode(w,S):
    F=S['F'];v=[1]+list(w);out=[]
    for cf in S['coeff']:
        ell=[F.sum(F.mul[a][b] for a,b in zip(row,v)) for row in cf]
        for alpha in S['aa']:
            h=1
            for x,p in zip(ell,alpha):h=F.mul[h][F.pow(x,p)]
            for vi in v:
                for vj in v:out.append(F.mul[h][F.mul[vi][vj]])
    return out

def advance(v,i,S):
    # Assumes bit i (matrix coordinate i) was previously zero.
    F=S['F']; n=S['N']+1; aa=S['aa']; n2=n*n;out=[]
    aidx={a:j for j,a in enumerate(aa)}
    for t_idx,cf in enumerate(S['coeff']):
        delta=[row[i] for row in cf];offset=t_idx*len(aa)*n2
        for a in aa:
            terms=[]
            for b in product(*(range(x+1) for x in a)):
                fac=1
                for aj,bj,dj in zip(a,b,delta):
                    fac=F.mul[fac][F.mul[F.integer(comb(aj,bj))][F.pow(dj,aj-bj)]]
                if fac:terms.append((offset+aidx[b]*n2,fac))
            for r in range(n):
                for c in range(n):
                    rr=0 if r==i else r;cc=0 if c==i else c
                    out.append(F.sum(F.mul[fac][v[base+rr*n+cc]] for base,fac in terms))
    return out

def table_space(S,eqs):
    N=S['N'];F=S['F'];nw=2**N
    words=list(product((0,1),repeat=N))
    enc=[encode(w,S) for w in words]
    # Recover h from top-left coefficient of each n*n block.
    stride=(N+1)**2; equations=[]
    for eq in eqs:
        for hidx in range(len(S['ts'])*len(S['aa'])):
            equations.append([F.mul[ev[hidx*stride]][eq(w,F)] for ev,w in zip(enc,words)])
    coeffs=nullspace(equations,F,nw)
    basis=span([lincomb(enc,c,F) for c in coeffs],F)
    return words,enc,basis

def column_candidates(mat,S,eqs):
    F=S['F'];cols=[list(c) for c in zip(*mat)]
    # Column-coordinate matrix from Gaussian pivot rows/columns.
    RR,piv=rref(mat,F);rho=len(piv)
    if rho==0:return None,0
    # Pivot rows of original matrix chosen by rank test on selected columns.
    cs=[];ids=[]
    for i,row in enumerate(mat):
        cand=[row[j] for j in piv]
        if rank(cs+[cand],F)>len(cs):cs.append(cand);ids.append(i)
        if len(cs)==rho:break
    # solve square cs for coefficients of every column
    aug=[cs[i]+[int(i==j) for j in range(rho)] for i in range(rho)]
    inv=rref(aug,F)[0];inv=[row[rho:] for row in inv]
    gam=[]
    for j in range(S['N']+1):
        b=[mat[i][j] for i in ids]
        gam.append([F.sum(F.mul[a][bb] for a,bb in zip(row,b)) for row in inv])
    for e in product((0,1),repeat=rho):
        x=[F.sum(F.mul[a][b] for a,b in zip(row,e)) for row in gam]
        w=x[1:]
        if all(v in (0,1) for v in w) and all(eq(w,F)==0 for eq in eqs):return w,rho
    return None,rho

def main():
    rng=random.Random(202609241701)
    out={'scope':'new algebraic extensions/controls only; no QPT or concrete WE security test','seed':202609241701}
    # Exhaustive rank condenser check on ALL rank-two 2x4 matrices over F7.
    F=Field(7);N=3;R=2;gamma=F.choose_generator(N)
    # 2NR+1 sampling is not available at F7; this tests determinant root count over all field points,
    # independently of the full compiler's larger sample-set precondition.
    cnt=0;maxzeros=0
    for vals in product(range(7),repeat=8):
        # Too large for whole census; deterministic exhaustive RREF subspaces instead below.
        break
    seen=set()
    for piv in combinations(range(N+1),2):
        free=[(r,c) for r in range(2) for c in range(N+1) if c not in piv and c>piv[r]]
        for vals in product(range(7),repeat=len(free)):
            A=[[0]*(N+1) for _ in range(2)]
            for i,c in enumerate(piv):A[i][c]=1
            for (i,c),v in zip(free,vals):A[i][c]=v
            zero=0
            for t in range(7):
                D=[[F.sum(F.mul[A[i][c]][F.pow(F.mul[F.pow(gamma,j)][t],c)] for c in range(N+1)) for j in range(2)] for i in range(2)]
                zero+=rank(D,F)<2
            assert zero<=N*2
            cnt+=1;maxzeros=max(maxzeros,zero)
    out['all_F7_two_subspaces_F7_4']={'count':cnt,'gamma':gamma,'order':F.order(gamma),'max_rank_drop_sample_points':maxzeros,'root_bound':N*2}
    # Base-2 aliasing negative control, same smaller prime supports repair.
    F=Field(31);N=5
    def zeros(g):
        return sum(rank([[1,1],[F.pow(t,N),F.pow(F.mul[g][t],N)]],F)<2 for t in range(21))
    g=F.choose_generator(N)
    assert F.order(2)==5 and zeros(2)==21 and zeros(g)==1
    out['base2_alias_control']={'p':31,'N':5,'bad_order':5,'bad_samples':21,'good_gamma':g,'good_order':F.order(g),'good_rank_drops':zeros(g)}
    # Direct tables + independently implemented partial-assignment linear updates.
    transition_count=0; compiler_reports=[]
    for N,R,F in [(3,1,Field(7)),(5,2,Field(23)),(5,2,Field(32,0b100101))]:
        S=spec(N,R,F);B=[encode((0,)*N,S)];dims=[1]
        for i in range(1,N+1):
            images=[advance(v,i,S) for v in B]
            B=span(B+images,F)
            direct=span([encode(w+(0,)*(N-i),S) for w in product((0,1),repeat=i)],F)
            assert len(B)==len(direct)==len(span(B+direct,F))
            dims.append(len(B))
            for _ in range(4):
                w=tuple(rng.randrange(2) for _ in range(i-1))+(0,)*(N-i+1)
                ww=list(w);ww[i-1]=1
                assert advance(encode(w,S),i,S)==encode(ww,S)
                transition_count+=1
        eqs=[lambda w,F:F.sub(F.add[w[0]][w[1]],1)]
        words,enc,basis=table_space(S,eqs)
        true_words=[w for w in words if all(eq(w,F)==0 for eq in eqs)]
        extracts=0
        for _ in range(30):
            subset=rng.sample(true_words,min(R,len(true_words)))
            E=[encode(w,S) for w in subset]
            co=[rng.randrange(1,F.q) for w in subset]
            a=lincomb(E,co,F)
            mat=reshape(a,N+1)
            if rank(mat,F)==0:continue
            w,rho=column_candidates(mat,S,eqs)
            assert rho<=R and w is not None
            extracts+=1
        compiler_reports.append({'N':N,'R':R,'field':F.q,'characteristic':F.char,'gamma':S['gamma'],'order':F.order(S['gamma']),'samples':len(S['ts']),'rows':(N+1)*len(S['ts'])*len(S['aa']),'columns':N+1,'stage_dimensions':dims,'constrained_dimension':len(basis),'low_rank_extractions':extracts,'old_p_2N_condition_met':F.q>2**N})
    out['compilers']=compiler_reports;out['transition_identities']=transition_count
    # Restrict scalars by expanding each extension-field entry vertically.
    # It is F2-linear; it preserves honest Boolean right factors as rank ONE,
    # and cannot reduce rank relative to the original extension-field matrix.
    def descend(mat,F):
        h=F.q.bit_length()-1
        return [[(entry>>bit)&1 for entry in row] for row in mat for bit in range(h)]
    F2=Field(2); descent_reports=[]
    for N,R,F in [(2,1,Field(8,0b1011)),(3,1,Field(16,0b10011)),(5,2,Field(32,0b100101))]:
        S=spec(N,R,F)
        if N<=3:
            # weights 1,2,...,2^(N-1) span only labels <2^N; target 2^N lies outside.
            eqs=[lambda w,F,N=N:F.add[F.sum(F.mul[1<<i][w[i]] for i in range(N))][1<<N]]
        else:
            eqs=[lambda w,F:F.sub(F.add[w[0]][w[1]],1)]
        words,enc,BB=table_space(S,eqs)
        has_witness=any(all(eq(w,F)==0 for eq in eqs) for w in words)
        binary_generators=[]
        for row in BB:
            for j in range(F.q.bit_length()-1):
                scalar=1<<j
                scaled=[F.mul[scalar][x] for x in row]
                binary_generators.append(flatten(descend(reshape(scaled,N+1),F)))
        binary_basis=span(binary_generators,F2)
        assert len(binary_basis)==len(BB)*(F.q.bit_length()-1)
        count=0; minF=999; min2=999
        coefflist=list(product(range(F.q),repeat=len(BB))) if N==2 else [[rng.randrange(F.q) for _ in BB] for _ in range(128)]
        for coeff in coefflist:
            if not any(coeff):continue
            mat=reshape(lincomb(BB,coeff,F),N+1)
            rf=rank(mat,F); rb=rank(descend(mat,F),F2)
            assert rf<=rb
            if not has_witness: assert rf>R and rb>R
            minF=min(minF,rf);min2=min(min2,rb);count+=1
        honest=0; extracted=0
        for w in words:
            if all(eq(w,F)==0 for eq in eqs):
                mat=reshape(encode(w,S),N+1)
                assert rank(mat,F)==rank(descend(mat,F),F2)==1
                got,rho=column_candidates(mat,S,eqs)
                assert got is not None;honest+=1;extracted+=1
        descent_reports.append({'field':F.q,'N':N,'R':R,'source_has_witness':has_witness,'field_space_dimension':len(BB),'binary_space_dimension':len(binary_basis),'tested_nonzero_matrices':count,'minimum_tested_field_rank':minF,'minimum_tested_binary_rank':min2,'all_nonzero_enumerated':N==2,'honest_binary_rank1_encodings':honest,'source_extractions':extracted})
    out['binary_scalar_descent']=descent_reports
    # Complete small false-space rank census over F7, N3,R1, Boolean sum=4.
    F=Field(7);S=spec(3,1,F)
    eqs=[lambda w,F:F.sub(F.sum(w),4)]
    words,enc,B=table_space(S,eqs)
    hist={};count=0
    for cc in product(range(7),repeat=len(B)):
        if not any(cc):continue
        mat=reshape(lincomb(B,cc,F),4);rr=rank(mat,F)
        assert rr>1
        hist[rr]=hist.get(rr,0)+1;count+=1
    out['exhaustive_false_space']={'N':3,'R':1,'p':7,'dimension':len(B),'nonzero_matrices':count,'ranks':hist}
    # Exact per-collision bound, using nontrivial false-space matrices and independent grid r.
    checks=0
    for _ in range(100):
        cc=[rng.randrange(7) for _ in B]
        if not any(cc):cc[0]=1
        mat=reshape(lincomb(B,cc,F),4);rr=rank(mat,F)
        alpha=[rng.randrange(7) for _ in mat]
        zeros=0;grid=2
        for r in product(range(grid),repeat=4):
            zeros+=all(F.add[F.sum(F.mul[a][b] for a,b in zip(row,r))][off]==0 for row,off in zip(mat,alpha))
        prob=Fraction(zeros,grid**4)+(1-Fraction(zeros,grid**4))/7
        assert prob<=Fraction(1,grid**rr)+Fraction(1,7);checks+=1
    out['exact_collision_bound_checks']=checks
    out['status']='PASS'
    print(json.dumps(out,indent=2,sort_keys=True))

if __name__=='__main__':main()
