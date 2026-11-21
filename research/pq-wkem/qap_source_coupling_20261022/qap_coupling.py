"""Normalized off-domain QAP source compiler and spectral correctness reference.
Research fixture only: global prime-field modulus and deterministic RNG for tests.
No public-output hiding, key-recovery hardness, or production-security claim.
"""
from __future__ import annotations
import numpy as np
import itertools, json
P=65537

def trim(a):
    a=list(map(int,a))
    while len(a)>1 and a[-1]%P==0:a.pop()
    return [x%P for x in a]
def add(a,b):
    c=[0]*max(len(a),len(b))
    for i,x in enumerate(a):c[i]+=int(x)
    for i,x in enumerate(b):c[i]+=int(x)
    return trim(c)
def scale(a,k):return trim([int(x)*int(k)%P for x in a])
def mul(a,b):
    c=[0]*(len(a)+len(b)-1)
    for i,x in enumerate(a):
        for j,y in enumerate(b):c[i+j]=(c[i+j]+int(x)*int(y))%P
    return trim(c)
def divrem(a,b):
    a=trim(a);b=trim(b);q=[0]*max(1,len(a)-len(b)+1)
    while a!=[0] and len(a)>=len(b):
        d=len(a)-len(b);v=a[-1]*pow(b[-1],-1,P)%P;q[d]=v
        a=add(a,scale([0]*d+b,-v))
    return trim(q),a
def ev(p,x):
    z=0
    for a in reversed(p):z=(z*x+int(a))%P
    return z
def lagrange(nodes):
    out=[]
    for i,x in enumerate(nodes):
        a=[1];den=1
        for j,y in enumerate(nodes):
            if i!=j:a=mul(a,[-y,1]);den=den*(x-y)%P
        out.append(scale(a,pow(den,-1,P)))
    return out
def mm(a,b):return a@b%P

def rref(a):
    a=np.asarray(a,dtype=np.int64).copy()%P;r=0;piv=[]
    for c in range(a.shape[1]):
        ids=np.flatnonzero(a[r:,c])
        if len(ids)==0:continue
        i=r+int(ids[0]);a[[r,i]]=a[[i,r]]
        a[r]=a[r]*pow(int(a[r,c]),-1,P)%P
        vec=a[:,c].copy();vec[r]=0
        a=(a-vec[:,None]*a[r][None,:])%P
        piv.append(c);r+=1
        if r==a.shape[0]:break
    return a,piv

def rank(a):return len(rref(a)[1])
def inv(a):
    n=len(a);rr,piv=rref(np.concatenate([a,np.eye(n,dtype=np.int64)],axis=1))
    if piv[:n]!=list(range(n)):raise ValueError('singular')
    return rr[:,n:]
def comm(a,b):return (mm(a,b)-mm(b,a))%P

def family(n,target):
    m=n+1;A=np.zeros((m,n+1),dtype=np.int64);B=A.copy();C=A.copy()
    for j in range(n):A[j,j+1]=B[j,j+1]=C[j,j+1]=1
    A[-1,1:]=1;B[-1,0]=1;C[-1,0]=target
    return A,B,C

def compile_qap(A,B,C,length=None):
    if A.shape != B.shape or A.shape != C.shape or A.ndim != 2:
        raise ValueError('A, B, C must have the same matrix shape')
    m,base=A.shape;length=length or 2*m-1
    if m < 2 or length < 2*m-1 or m+length >= P:
        raise ValueError('Need m>=2, L>=2m-1, and enough distinct nonzero field nodes')
    nodes=list(range(1,m+1));ts=list(range(m+1,m+1+length))
    ls=lagrange(nodes);Z=[1]
    for x in nodes:Z=mul(Z,[-x,1])
    polys=[]
    for mat in (A,B,C):
        cols=[]
        for j in range(base):
            col=[0]
            for i in range(m):col=add(col,scale(ls[i],int(mat[i,j])))
            cols.append(col)
        polys.append(cols)
    variables=base+m-1
    forms=np.zeros((length,variables,4),dtype=np.int64)
    for i,t in enumerate(ts):
        for j in range(base):
            for slot in range(3):forms[i,j,slot]=ev(polys[slot][j],t)
        for h in range(m-1):forms[i,base+h,2]=ev(Z,t)*pow(t,h,P)%P
        forms[i,0,3]=1
    return dict(forms=forms, polynomials=polys, Z=Z,base=base,m=m,nodes=nodes,points=ts)
def original_forms(A,B,C):
    m,base=A.shape;forms=np.zeros((m,base,4),dtype=np.int64)
    forms[:,:,0]=A;forms[:,:,1]=B;forms[:,:,2]=C;forms[:,0,3]=1
    return forms

def encode(comp,assignment):
    y=[1]+list(assignment);values=[]
    for cols in comp['polynomials']:
        a=[0]
        for c,v in zip(cols,y):a=add(a,scale(c,v))
        values.append(a)
    quotient,remainder=divrem(add(mul(values[0],values[1]),scale(values[2],-1)),comp['Z'])
    if remainder!=[0]:raise ValueError('invalid source')
    return np.array(y+quotient+[0]*(comp['m']-1-len(quotient)),dtype=np.int64)

def gate(a,b,c,d,X):
    k=len(X);I=np.eye(k,dtype=np.int64);Z=np.zeros((k,k),dtype=np.int64)
    return np.block([[a*I,c*I,-X,Z],[d*I,b*I,Z,X],[Z,Z,b*I,c*I],[Z,Z,d*I,a*I]])%P

def setup(forms,block=2,seed=1,key=12345):
    gates,variables,_=forms.shape;N=2*block*gates+1
    if block < 1 or max(N,variables,4*block)*(P-1)**2 >= 2**63:
        raise ValueError('Invalid block size or int64 arithmetic capacity exceeded')
    rng=np.random.default_rng(seed)
    mats=np.zeros((variables,N,N),dtype=np.int64);sources=np.zeros_like(mats)
    for i in range(gates):
        L=rng.integers(0,P,(N,4*block),dtype=np.int64)
        R=rng.integers(0,P,(4*block,N),dtype=np.int64)
        for j in range(variables):
            X=rng.integers(0,P,(block,block),dtype=np.int64)
            a,b,c,d=map(int,forms[i,j]);src=gate(a,b,c,d,np.zeros_like(X));G=gate(a,b,c,d,X)
            mats[j]=(mats[j]+mm(mm(L,G),R))%P
            sources[j]=(sources[j]+mm(mm(L,src),R))%P
    public=mats.copy();public[0]=(public[0]+key*np.eye(N,dtype=np.int64))%P
    return public,sources

def attack_diagnostic(public,block,key,indices=(1,2,3)):
    a,c,d=indices;N=public.shape[1]
    try:Q=inv(public[a])
    except ValueError:return dict(status='pivot_singular',N=N,indices=list(indices))
    A=mm(Q,public[c]);B=mm(Q,public[d]);T=mm(Q,public[0]);
    if block==1:F0=comm(T,A);F1=comm(Q,A)
    else:
        H=mm(comm(A,B),comm(A,B));F0=comm(H,T);F1=comm(H,Q)
    return dict(status='measured',N=N,indices=list(indices),denominator_rank=rank(F1),
        key_pencil_rank=rank((F0-key*F1)%P))

