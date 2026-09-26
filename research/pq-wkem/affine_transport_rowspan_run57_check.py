#!/usr/bin/env python3
import json, random, math
from fractions import Fraction as F
R=random.Random(570057)

def I(d): return [[int(i==j) for j in range(d)] for i in range(d)]
def mm(A,B,p=None):
    C=[[sum(A[i][k]*B[k][j] for k in range(len(B))) for j in range(len(B[0]))] for i in range(len(A))]
    return [[x%p for x in r] for r in C] if p else C
def sub(A,B,p=None):
    C=[[a-b for a,b in zip(x,y)] for x,y in zip(A,B)]
    return [[z%p for z in r] for r in C] if p else C
def add(A,B,p): return [[(a+b)%p for a,b in zip(x,y)] for x,y in zip(A,B)]
def tr(A): return list(map(list,zip(*A)))
def rank(A,p=None):
    A=[[F(x) if p is None else x%p for x in r] for r in A]; m=len(A); n=len(A[0]); rr=0
    for c in range(n):
        k=next((i for i in range(rr,m) if A[i][c]),None)
        if k is None: continue
        A[rr],A[k]=A[k],A[rr]; inv=(1/A[rr][c]) if p is None else pow(A[rr][c],-1,p)
        A[rr]=[(x*inv)%p if p else x*inv for x in A[rr]]
        for i in range(m):
            if i!=rr and A[i][c]:
                f=A[i][c]; A[i]=[(A[i][j]-f*A[rr][j])%p if p else A[i][j]-f*A[rr][j] for j in range(n)]
        rr+=1
    return rr

def solve_mod(A,b,p):
    A=[[x%p for x in r]+[b[i]%p] for i,r in enumerate(A)]; m=len(A); n=len(A[0])-1; rr=0; piv=[]
    for c in range(n):
        k=next((i for i in range(rr,m) if A[i][c]),None)
        if k is None: continue
        A[rr],A[k]=A[k],A[rr]; inv=pow(A[rr][c],-1,p); A[rr]=[(x*inv)%p for x in A[rr]]
        for i in range(m):
            if i!=rr and A[i][c]:
                f=A[i][c]; A[i]=[(A[i][j]-f*A[rr][j])%p for j in range(n+1)]
        piv.append(c); rr+=1
    if any(all(A[i][j]==0 for j in range(n)) and A[i][n] for i in range(rr,m)): return None
    x=[0]*n
    for i,c in enumerate(piv): x[c]=A[i][n]
    return x

def Mbuild(A):
    L=len(A); d=len(A[0][0]); M=[]
    for i in range(L):
      for b in (0,1):
       for j in range(d):
        r=[0]*((L+1)*d)
        for k in range(d): r[i*d+k]=-A[i][b][k][j]
        r[(i+1)*d+j]=1; M.append(r)
    return M

def Lrows(T,L):
    d=len(T); O=[]
    for j in range(d):
        r=[0]*((L+1)*d)
        for k in range(d): r[k]=-T[k][j]
        r[L*d+j]=1; O.append(r)
    return O

def prod(A,w,p=None):
    P=I(len(A[0][0]))
    for i,b in enumerate(w): P=mm(P,A[i][b],p)
    return P

def qsolve(M,Ls,p):
    MT=tr(M); Q=[]
    for l in Ls:
        q=solve_mod(MT,l,p)
        if q is None:return None
        Q.append(q)
    return Q

def mv(A,x,p=None):
    y=[sum(a*b for a,b in zip(r,x)) for r in A]
    return [z%p for z in y] if p else y

def qv(Q,c,p): return [sum(a*b for a,b in zip(r,c))%p for r in Q]

def minnorm(A,b):
    # minimum ||q|| s.t. A q=b over Q; keep independent constraints, q=A^T(AA^T)^-1b
    keep=[]; rhs=[]; r0=0
    for row,bb in zip(A,b):
        nr=rank(keep+[row])
        if nr>r0: keep.append(list(map(F,row))); rhs.append(F(bb)); r0=nr
    G=[[sum(keep[i][t]*keep[j][t] for t in range(len(keep[0]))) for j in range(len(keep))] for i in range(len(keep))]
    aug=[G[i]+[rhs[i]] for i in range(len(G))]
    n=len(G)
    for c in range(n):
        k=next(i for i in range(c,n) if aug[i][c]); aug[c],aug[k]=aug[k],aug[c]; z=aug[c][c]; aug[c]=[x/z for x in aug[c]]
        for i in range(n):
            if i!=c and aug[i][c]:
                z=aug[i][c]; aug[i]=[aug[i][j]-z*aug[c][j] for j in range(n+1)]
    lam=[aug[i][-1] for i in range(n)]
    return [sum(keep[i][t]*lam[i] for i in range(n)) for t in range(len(keep[0]))]

def pathQ(A,w):
    L=len(A); d=len(A[0][0]); Q=[[F(0)]*(2*L*d) for _ in range(d)]; U=I(d); suff=[None]*L
    for i in range(L-1,-1,-1): suff[i]=U; U=mm(A[i][w[i]],U)
    for i,b in enumerate(w):
        off=(2*i+b)*d
        for j in range(d):
            for k in range(d): Q[j][off+k]=F(suff[i][k][j])
    return Q

def ff():
    p=101;d=3;L=6; good=sing=qs=falseok=0
    for _ in range(500):
        A=[]
        for _ in range(L):
            A0=[[R.randrange(p) for _ in range(d)] for _ in range(d)]
            while True:
                u=[R.randrange(p) for _ in range(d)];v=[R.randrange(p) for _ in range(d)]
                if any(u) and any(v):break
            D=[[u[i]*v[j]%p for j in range(d)] for i in range(d)]; A.append([A0,add(A0,D,p)])
        assert all(rank(sub(x[0],x[1],p),p)==1 for x in A); sing+=1
        w=[R.randrange(2) for _ in range(L)]; T=prod(A,w,p); M=Mbuild(A); M=[[z%p for z in r] for r in M]; Ls=[[z%p for z in r] for r in Lrows(T,L)]
        Q=qsolve(M,Ls,p); assert Q is not None and mm(Q,M,p)==Ls; qs+=d*len(M[0])
        x=[R.randrange(p) for _ in range((L+1)*d)]; assert qv(Q,mv(M,x,p),p)==mv(Ls,x,p); good+=1
        paths={tuple(sum(prod(A,[(m>>i)&1 for i in range(L)],p),[])) for m in range(1<<L)}
        while True:
            Tf=[[R.randrange(p) for _ in range(d)] for _ in range(d)]
            if tuple(sum(Tf,[])) not in paths:break
        falseok+=qsolve(M,[[z%p for z in r] for r in Lrows(Tf,L)],p) is not None
    return {'field':p,'d':d,'L':L,'fixtures':500,'true_public_evaluator_recoveries':good,'all_branch_differences_singular':sing,'max_branch_difference_rank':1,'qm_scalar_checks':qs,'false_control_targets':500,'false_controls_with_public_evaluator':falseok}

def rat():
    d=3;L=8; J=I(d);P=I(d);P[0][0]=P[1][1]=0;P[0][1]=P[1][0]=1; A=[[J,P] for _ in range(L)]; w=[1,0,1,0,0,0,0,0]; T=prod(A,w); M=Mbuild(A); Ls=Lrows(T,L); Ae=tr(M); Qw=pathQ(A,w); Q=[]; ratios=[]; den=1
    for j,l in enumerate(Ls):
        q=minnorm(Ae,l); Q.append(q); assert all(sum(F(Ae[r][t])*q[t] for t in range(len(q)))==F(l[r]) for r in range(len(Ae)))
        for z in q:den=math.lcm(den,z.denominator)
        ratios.append(float(sum(z*z for z in q)/sum(z*z for z in Qw[j])))
    for _ in range(300):
        x=[R.randint(-20,20) for _ in range((L+1)*d)]; c=mv(M,x); s=mv(Ls,x); assert [sum(a*F(b) for a,b in zip(q,c)) for q in Q]==list(map(F,s))
    trials=30000; q0=list(map(float,Q[0])); h0=list(map(float,Qw[0])); a2=h2=0.0
    for _ in range(trials):
        e=[R.gauss(0,1) for _ in q0]; a=sum(x*y for x,y in zip(q0,e)); h=sum(x*y for x,y in zip(h0,e)); a2+=a*a;h2+=h*h
    return {'d':d,'L':L,'branch_difference_rank':rank(sub(J,P)),'minimum_norm_over_honest_norm2_ratios':ratios,'max_minimum_evaluator_denominator':den,'exact_constraint_checks':len(Ae)*d,'noiseless_rational_public_recoveries':300,'gaussian_trials_diagnostic':trials,'output0_theoretical_std_public':math.sqrt(float(sum(z*z for z in Q[0]))),'output0_theoretical_std_honest':math.sqrt(float(sum(z*z for z in Qw[0]))),'output0_empirical_rmse_public':math.sqrt(a2/trials),'output0_empirical_rmse_honest':math.sqrt(h2/trials)}

print(json.dumps({'run':57,'seed':570057,'finite_field_exact':ff(),'rational_minimum_energy':rat(),'claims_scope':{'proved_by_algebra':'true instance => endpoint functional lies in public row span of the noiseless affine transport operator; singular branch differences do not prevent exact public synthesis','noise_theorem':'over real iid Gaussian transcript noise, the publicly computable minimum-Euclidean-norm evaluator has per-output standard deviation no larger than any witness-path evaluator','not_claimed':'no universal attack on modular LWE-style noise; rational minimum-norm coefficients can have denominators that do not preserve centered smallness modulo q; tests are not security evidence'}},sort_keys=True,indent=2))
