#!/usr/bin/env python3
"""Bounded synthetic algebraic validation of the pivot-Schur joint view.

Standard library only. No network, file-input attack mode, wallet, signature,
or external credential support. All fields, SOURCEs and secrets are synthetic.
The finite checker is not a cryptographic-size execution or a QPT proof.
"""
import hashlib
import json
import random

POLY=0x13

def gf16mul(a,b):
    v=0
    for _ in range(4):
        if b&1:v^=a
        a<<=1
        if a&16:a^=POLY
        b>>=1
    return v
F=[[gf16mul(a,b) for b in range(16)] for a in range(16)]
def fpow(a,n):
    v=1
    while n:
        if n&1:v=F[v][a]
        a=F[a][a];n>>=1
    return v

def ftrace(a):
    t=0
    for _ in range(4):t^=a;a=F[a][a]
    assert t in (0,1)
    return t
KAPPA=next(a for a in range(1,16) if ftrace(a))

def gf256mul(a,b):
    a0,a1=a&15,a>>4
    b0,b1=b&15,b>>4
    t=F[a1][b1]
    return (F[a0][b0]^F[t][KAPPA]) | ((F[a0][b1]^F[a1][b0]^t)<<4)
E=[[gf256mul(a,b) for b in range(256)] for a in range(256)]
def epow(a,n):
    v=1
    while n:
        if n&1:v=E[v][a]
        a=E[a][a];n>>=1
    return v
INV=[0]+[epow(a,254) for a in range(1,256)]
INVF=[0]+[fpow(a,14) for a in range(1,16)]
THETA=16
COUNT=0

def check(x,why):
    global COUNT
    COUNT+=1
    if not x:raise AssertionError(f'assertion {COUNT}: {why}')

def zeros(rows,cols):return [[0]*cols for _ in range(rows)]
def ident(n):return [[int(i==j) for j in range(n)] for i in range(n)]
def mm(A,B):
    rows=len(A); mid=len(B); cols=len(B[0]); C=zeros(rows,cols)
    for i in range(rows):
        for t in range(mid):
            a=A[i][t]
            if a:
                for j in range(cols):C[i][j]^=E[a][B[t][j]]
    return C

def madd(A,B):return [[x^y for x,y in zip(a,b)] for a,b in zip(A,B)]
def mscale(s,M):return [[E[s][a] for a in row] for row in M]
def submatrix(M,rows,cols):return [[M[i][j] for j in cols] for i in rows]

def rref_with_pivots(M):
    A=[a[:] for a in M]; m=len(A);n=len(A[0]);row=0;pc=[];pr=[]
    for j in range(n):
        z=next((i for i in range(row,m) if A[i][j]),None)
        if z is None:continue
        A[row],A[z]=A[z],A[row]
        pr.append(z)  # only columns used elsewhere; row permutation isn't needed
        inv=INV[A[row][j]]
        for col in range(j,n):A[row][col]=E[inv][A[row][col]]
        for i in range(m):
            if i!=row and A[i][j]:
                f=A[i][j]
                for col in range(j,n):A[i][col]^=E[f][A[row][col]]
        pc.append(j);row+=1
        if row==m:break
    return A,pc

def invmat(M):
    n=len(M); W=[a[:]+b for a,b in zip(M,ident(n))]
    for j in range(n):
        k=next((t for t in range(j,n) if W[t][j]),None)
        check(k is not None,'pivot inverse exists')
        W[j],W[k]=W[k],W[j]
        v=INV[W[j][j]]
        for t in range(2*n):W[j][t]=E[v][W[j][t]]
        for i in range(n):
            if i!=j and W[i][j]:
                v=W[i][j]
                for t in range(2*n):W[i][t]^=E[v][W[j][t]]
    return [r[n:] for r in W]

def rank(M):return len(rref_with_pivots(M)[1])

def rank_factor(M):
    """Public canonical rank factorization M=A B with left/right inverses.

    Full column/row bases are chosen solely from public M, not hidden factors.
    """
    N=len(M);_,pivotcols=rref_with_pivots(M);R=len(pivotcols)
    A=[[M[i][j] for j in pivotcols] for i in range(N)]
    # Deterministic independent pivot rows of A.
    _,pivotrows=rref_with_pivots([[A[i][j] for i in range(N)] for j in range(R)])
    check(len(pivotrows)==R,'A has full column rank')
    Ainv=invmat(submatrix(A,pivotrows,list(range(R))))
    B=mm(Ainv,[M[i][:] for i in pivotrows]);check(mm(A,B)==M,'AB=public Q0')
    # B[:,pivotcolumnsB] is invertible, giving a public right inverse.
    _,bp=rref_with_pivots(B);check(len(bp)==R,'B full row rank')
    Binv=invmat(submatrix(B,list(range(R)),bp))
    # L_A=Ainv * row_selector; R_B=column_selector * Binv.
    left=zeros(R,N);right=zeros(N,R)
    for i in range(R):
        for j in range(R):
            left[i][pivotrows[j]]=Ainv[i][j]
            right[bp[i]][j]=Binv[i][j]
    check(mm(left,A)==ident(R),'left inverse')
    check(mm(B,right)==ident(R),'right inverse')
    return A,B,left,right


import sys
f=sys.modules[__name__]
def tr(a):return [list(r) for r in zip(*a)]
def kernel(A):
    R,p=f.rref_with_pivots(A); nc=len(A[0]); frees=[i for i in range(nc) if i not in p]
    out=[]
    for c in frees:
        v=[0]*nc;v[c]=1
        for i,j in enumerate(p):v[j]=R[i][c]
        out.append(v)
    return out

def rowbasis(A):
    R,p=f.rref_with_pivots(A)
    return R[:len(p)]
def intersect_rows(A,B):
    A=rowbasis(A);B=rowbasis(B)
    rel=kernel(tr(A+B))
    return rowbasis(f.mm([r[:len(A)] for r in rel],A)) if rel else []

def pv(c,e):
    z=0
    for x in reversed(c):z=f.F[z][e]^x
    return z

def pm(a,b):
    c=[0]*(len(a)+len(b)-1)
    for i,x in enumerate(a):
        for j,y in enumerate(b):c[i+j]^=f.F[x][y]
    return c

def compiler(false_source=True):
    n=4;m=7;base=n+1
    A=[];B=[];C=[]
    def row(*ind):
        v=[0]*base
        for i in ind:v[i]^=1
        return v
    for i in range(1,5):A.append(row(i));B.append(row(i));C.append(row(i))
    # a=u*v; a=1+b; a=b. Unsatisfiable; every wire participates.
    A += [row(1),row(3),row(3,4) if false_source else row(4)]
    B += [row(2),row(0),row(0)]
    C += [row(3),row(0,4),row() if false_source else row(0)]
    ts=list(range(m));es=list(range(m,15));Ls=[];Z=[1]
    for x in ts:Z=pm(Z,[x,1])
    for x in ts:
        l=[1];d=1
        for y in ts:
            if y!=x:l=pm(l,[y,1]);d=f.F[d][x^y]
        Ls.append([f.F[f.INVF[d]][a] for a in l])
    forms=[]
    for e in es:
        abc=[]
        for M in (A,B,C):
            a=[0]*base
            for i in range(m):
                l=pv(Ls[i],e)
                for j in range(base):a[j]^=f.F[l][M[i][j]]
            abc.append(a)
        forms.append((e,f.fpow(pv(Z,e),8),abc))
    return n,m,forms,(A,B,C)

def sl2(rng):
    while True:
        p,q=rng.randrange(16),rng.randrange(16)
        if p or q:break
    free=rng.randrange(16)
    if p:r=free;t=F[INVF[p]][1^F[q][r]]
    else:t=free;r=INVF[q]
    check(F[p][t]^F[q][r]==1,'SL2 determinant')
    return p,q,r,t

def setup(seed,h=5,false_source=True,two_sided=False):
    rng=random.Random(seed);n,m,forms,src=compiler(false_source);L=len(forms);N=2*L+h;k=n+m
    Cs=[f.zeros(N,N) for _ in range(k)];Bs=[];nodes=[]
    key=rng.randrange(256)
    for e,ze,(a,b,c) in forms:
        p,q,r,t=f.sl2(rng)
        aa=[f.F[p][x]^f.F[q][y] for x,y in zip(a,b)]
        bb=[f.F[r][x]^f.F[t][y] for x,y in zip(a,b)]
        cc=[x ^ f.F[f.F[p][r]][f.F[y][y]] ^ f.F[f.F[q][t]][f.F[z][z]] for x,y,z in zip(c,a,b)]
        alphas=[]
        for i in range(n):
            beta=rng.randrange(16)^f.E[f.THETA][f.fpow(e,i)]
            alphas.append(f.epow(beta,128));cc[i+1]^=beta
        mu=rng.randrange(16,256);o=rng.randrange(2)
        U=[[rng.randrange(256) for j in range(3)] for i in range(N)]
        V=[[rng.randrange(256) for j in range(N)] for i in range(3)]
        J=[[0,0,1],[0,0,0],[1,0,0]]
        Bs.append(f.mscale(ze,f.mm(f.mm(U,J),V)))
        nu=rng.randrange(16,256) if two_sided else 0
        nodes.append((o,mu,U,V,(p,q,r,t)))
        for j in range(k):
            z=int(j==0)
            if j<=n:av,bv,cv=aa[j],bb[j],cc[j];sv=0 if j==0 else alphas[j-1]
            else:av=bv=cv=0;sv=f.F[ze][f.fpow(f.fpow(e,8),j-n-1)]
            if two_sided:
                pi=z^f.E[mu][av]^f.E[nu][bv]^f.E[f.E[mu][nu]][cv]
                av^=f.E[nu][cv];bv^=f.E[mu][cv]
            else:
                pi=z^f.E[mu][av if o==0 else bv]
                if o==0:bv^=f.E[mu][cv]
                else:av^=f.E[mu][cv]
            G=[[cv,av,sv],[bv,pi,0],[sv,0,pi]]
            Cs[j]=f.madd(Cs[j],f.mm(f.mm(U,G),V))
    Cs[0]=f.madd(Cs[0],f.mscale(key,f.ident(N)))
    return Cs,[x[0] for x in forms],nodes,key,src

def public_probe(Cs,es,n,metric=None,two_sided=False):
    N=len(Cs[0]);L=len(es)
    A,B,li,ri=f.rank_factor(Cs[n+1]);T=f.mm(f.mm(li,Cs[n+2]),ri)
    projs=public_projectors(T,[f.fpow(e,8) for e in es])
    marks=[f.mm(f.mm(A,P),B) for P in projs]
    left=kernel(tr(Cs[n+1]));right=tr(kernel(Cs[n+1]))
    SR=rowbasis([r for M in Cs[1:n+1] for r in f.mm(left,M)])
    SL=rowbasis([r for M in Cs[1:n+1] for r in tr(f.mm(M,right))])
    if len(SL)+len(SR)!=(4 if two_sided else 3)*L:
        return {'status':'support_certificate_failed','SL':len(SL),'SR':len(SR)}
    H=kernel(SL);Z=tr(kernel(SR))
    terms=[];classif=[]
    for mark in marks:
        ac,bc,_,_=f.rank_factor(mark)
        ir=intersect_rows(bc,SR);ic=intersect_rows(tr(ac),SL)
        classif.append((len(ir),len(ic)))
        # Construct a rank-one supplementary term using only public bases.
        if (len(ir),len(ic))==(1,0) or (two_sided and (len(ir),len(ic))==(1,1)):
            v1=ir[0];v3=next(v for v in bc if f.rank([v,v1])==2)
            vv=[v3,v1]
            _,idx=f.rref_with_pivots(vv)
            Vi=f.invmat(f.submatrix(vv,[0,1],idx))
            uu=f.mm(f.submatrix(mark,list(range(N)),idx),Vi)
            u3=[[row[1]] for row in uu]
            extra=f.mm(u3,[v3])
        elif (len(ir),len(ic))==(0,1):
            u1=ic[0];u3=next(u for u in tr(ac) if f.rank([u1,u])==2)
            uu=tr([u1,u3]);_,idx=f.rref_with_pivots(tr(uu))
            Ui=f.invmat(f.submatrix(uu,idx,[0,1]))
            vv=f.mm(Ui,f.submatrix(mark,idx,list(range(N))))
            extra=f.mm(tr([u3]),[vv[0]])
        else:return {'status':'nongeneric_intersection','classes':classif,'SL':len(SL),'SR':len(SR)}
        terms += [f.mm(f.mm(H,mark),Z), f.mm(f.mm(H,extra),Z)]
    vec=lambda M:sum(M,[])
    space=rowbasis([vec(M) for M in terms]);metric=vec(f.mm(f.mm(H, metric or f.ident(N)),Z))
    obs=vec(f.mm(f.mm(H,Cs[0]),Z))
    # Reduce metric and observation modulo the publicly constructed subspace.
    red,piv=f.rref_with_pivots(space)
    for row,p in zip(red,piv):
        if metric[p]:metric=[a^f.E[metric[p]][b] for a,b in zip(metric,row)]
        if obs[p]:obs=[a^f.E[obs[p]][b] for a,b in zip(obs,row)]
    j=next((i for i,x in enumerate(metric) if x),None)
    if j is None:return {'status':'metric_in_span','classes':classif,'SL':len(SL),'SR':len(SR)}
    khat=f.E[obs[j]][f.INV[metric[j]]]
    consistency=all(a==f.E[khat][b] for a,b in zip(obs,metric))
    return {'status':'candidate','Khat':khat,'consistent':consistency,'classes':classif,'SL':len(SL),'SR':len(SR),'projected_shape':[len(H),len(Z[0])],'span_rank':len(space)}


def public_projectors(T,roots):
    R=len(T);I=ident(R);out=[]
    for e,root in enumerate(roots):
        acc=I;den=1
        for j,other in enumerate(roots):
            if j!=e:
                acc=mm(acc,madd(T,mscale(other,I)));den=E[den][root^other]
        check(den!=0,'distinct node spectrum')
        P=mscale(INV[den],acc)
        check(rank(P)==2,'rank-two node marker')
        check(mm(P,P)==P,'idempotent')
        out.append(P)
    return out

def original_valid(w,false_source=True):
    _,_,_,(A,B,C)=compiler(false_source)
    z=[1]+list(w)
    dot=lambda a,b: __import__('functools').reduce(int.__xor__,(F[x][y] for x,y in zip(a,b)),0)
    return all(F[dot(a,z)][dot(b,z)]==dot(c,z) for a,b,c in zip(A,B,C))

def encode_true(w):
    n,m,_,(A,B,C)=compiler(False);z=[1]+list(w)
    dot=lambda a,b: __import__('functools').reduce(int.__xor__,(F[x][y] for x,y in zip(a,b)),0)
    ts=list(range(m));Ls=[];Z=[1]
    for x in ts:Z=pm(Z,[x,1])
    for x in ts:
        poly=[1];d=1
        for y in ts:
            if y!=x:poly=pm(poly,[y,1]);d=F[d][x^y]
        Ls.append([F[INVF[d]][c] for c in poly])
    pols=[]
    for M in (A,B,C):
        v=[0]*m
        for i,row in enumerate(M):
            s=dot(row,z)
            for j,c in enumerate(Ls[i]):v[j]^=F[s][c]
        pols.append(v)
    num=pm(pols[0],pols[1])
    for j,c in enumerate(pols[2]):num[j]^=c
    quo=[0]*(m-1)
    for k in range(len(num)-1,m-1,-1):
        quo[k-m]=num[k]
        for j,c in enumerate(Z):num[k-m+j]^=F[quo[k-m]][c]
    check(not any(num),'true-source exact quotient')
    return z+[fpow(x,8) for x in quo]

def eval_public(Cs,y):
    out=zeros(len(Cs[0]),len(Cs[0]))
    for x,C in zip(y,Cs):out=madd(out,mscale(x,C))
    return out

def invertible(rng,n):
    while True:
        M=[[rng.randrange(256) for _ in range(n)] for _ in range(n)]
        if rank(M)==n:return M

def main():
    import itertools
    witnesses=[w for w in itertools.product((0,1),repeat=4) if original_valid(w,False)]
    check(len(witnesses)==3,'three true ORIGINAL witnesses')
    check(not any(original_valid(w,True) for w in itertools.product((0,1),repeat=4)), 'false ORIGINAL has no Boolean witness')
    cases=[];counts={}
    for seed in range(1000,1128):
        Cs,es,nodes,key,_=setup(seed)
        out=public_probe(Cs,es,4)
        counts[out['status']]=counts.get(out['status'],0)+1
        if out['status']=='candidate':
            check(out['consistent'],'entire projected quotient agrees')
            check(out['Khat']==key,'exact capability from PUBLIC input only')
            check(out['classes']==[(1,0) if node[0]==0 else (0,1) for node in nodes], 'public orientation certificate')
        cases.append(dict(seed=seed,**out,actual_key=key))
        if seed==1000:
            check(all(node[4][0]!=0 for node in nodes),'nonzero-p rational SL2 chart witness')
            generic_chart={'seed':seed,'SL2':[list(node[4]) for node in nodes],
                           'orientations':[node[0] for node in nodes],
                           'certificate_passed':out['status']=='candidate'}
    true=[]
    for seed in range(2000,2012):
        Cs,es,nodes,key,_=setup(seed,false_source=False)
        for w in witnesses:
            y=encode_true(w)
            M=eval_public(Cs,y)
            check(rank(madd(M,mscale(key,ident(len(M)))))<=2*len(es),'all-witness common-K correctness')
        out=public_probe(Cs,es,4)
        if out['status']=='candidate':check(out['Khat']==key and out['consistent'],'true source public-view check')
        true.append(dict(seed=seed,status=out['status'],correct=out.get('Khat')==key))
    transforms=[]
    for seed in range(3000,3004):
        Cs,es,nodes,key,_=setup(seed)
        rng=random.Random(seed^0x123456);N=len(Cs[0]);P=invertible(rng,N);Q=invertible(rng,N)
        W=mm(P,Q);view=[mm(mm(P,M),Q) for M in Cs]
        out=public_probe(view,es,4,metric=W)
        if out['status']=='candidate':check(out['Khat']==key and out['consistent'],'public metric transported exactly')
        transforms.append(dict(seed=seed,status=out['status'],correct=out.get('Khat')==key))
    repair=[]
    for seed in range(4000,4012):
        Cs,es,nodes,key,_=setup(seed,two_sided=True)
        out=public_probe(Cs,es,4,two_sided=True)
        if out['status']=='candidate':check(out['Khat']==key and out['consistent'],'two-sided pivot fails to repair full view')
        repair.append(dict(seed=seed,status=out['status'],correct=out.get('Khat')==key))
    result={'checkpoint':'joint_view_reduction_20261024','classification':'SECURITY_CORRECTION_NOT_POSITIVE_CONSTRUCTION',
       'model':'Synthetic GF(16) subset GF(256), classical public-input algebra, no key search',
       'fixture':{'original_variables':4,'R1CS_rows':7,'release_nodes':8,'padding':5,'matrix_dimension':21,'quotient_coordinates':6},
       'false_seed_range':[1000,1127],'false_examples':cases[:5],
       'all_false_cases_sha256':hashlib.sha256(json.dumps(cases,sort_keys=True).encode()).hexdigest(),
       'generic_chart_witness':generic_chart,'false_case_counts':counts,'true_source_checks':true,
       'valid_witness_recoveries':36,'transported_metric_checks':transforms,'failed_two_sided_repair_checks':repair,
       'explicit_assertions':COUNT,'checker_sha256':hashlib.sha256(open(__file__,'rb').read()).hexdigest(),
       'not_claimed':['asymptotic saturation bound for all relations','cryptographic-size execution','secure replacement','QPT secrecy','native Bitcoin validation']}
    print(json.dumps(result,sort_keys=True,indent=2))

if __name__=='__main__':main()
