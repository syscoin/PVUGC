"""Bounded independent rerun of the already-committed minimal-margin attack.
Synthetic finite-field instances only. The attacker gets public slices, b, q.
"""
import json
from pathlib import Path
import numpy as np
from sympy.polys.domains import ZZ
from sympy.polys.galoistools import gf_factor

ROOT=Path(__file__).resolve().parent

def mul(A,B,q): return (A@B)%q

def comm(A,B,q): return (mul(A,B,q)-mul(B,A,q))%q

def inv(A,q):
    n=len(A); B=np.concatenate([A.copy()%q,np.eye(n,dtype=np.int64)],axis=1)
    for j in range(n):
        indices=np.flatnonzero(B[j:,j])
        if not len(indices): raise ValueError('public matrix is singular')
        k=j+int(indices[0]);B[[j,k]]=B[[k,j]]
        B[j]=B[j]*pow(int(B[j,j]),-1,q)%q
        c=B[:,j].copy();c[j]=0;B=(B-c[:,None]*B[j])%q
    return B[:,n:]

def generate(m,b,q,seed,key):
    assert m>=7 and b in (1,2)
    N=2*b*m+1;v=m-3;assert q>v+1 and 4*max(N,4*b)*q*q<2**63
    rng=np.random.default_rng(seed);indices=[0,3,4,5]
    slices=[np.zeros((N,N),dtype=np.int64) for _ in indices]
    Ib=np.eye(b,dtype=np.int64)
    for gate in range(m):
        L=rng.integers(0,q,(N,4*b),dtype=np.int64)
        R=rng.integers(0,q,(4*b,N),dtype=np.int64)
        for k,j in enumerate(indices):
            if gate==0: coeff=(int(j==1),int(j==1),int(j==0),int(j==0))
            elif gate==1: coeff=(int(j==1),int(j==0),int(j==0),int(j==0))
            elif gate<m-1: coeff=(int(j==gate),int(j==gate),int(j==1),int(j==gate))
            else: coeff=(int(j>=2),int(j==1),(v+1)*int(j==1),int(j==1))
            a,bb,c,d=coeff;X=rng.integers(0,q,(b,b),dtype=np.int64)
            G=np.zeros((4*b,4*b),dtype=np.int64)
            G[:b,:b]=a*Ib;G[:b,b:2*b]=c*Ib;G[:b,2*b:3*b]=-X
            G[b:2*b,:b]=d*Ib;G[b:2*b,b:2*b]=bb*Ib;G[b:2*b,3*b:]=X
            G[2*b:3*b,2*b:3*b]=bb*Ib;G[2*b:3*b,3*b:]=c*Ib
            G[3*b:,2*b:3*b]=d*Ib;G[3*b:,3*b:]=a*Ib
            slices[k]=(slices[k]+mul(mul(L,G%q,q),R,q))%q
    slices[0]=(slices[0]+key*np.eye(N,dtype=np.int64))%q
    return slices

def recurrence(seq,q):
    C=[1];B=[1];L=0;s=1;last=1
    for n,value in enumerate(seq):
        delta=(value+sum(C[i]*seq[n-i] for i in range(1,L+1)))%q
        if delta==0:s+=1;continue
        old=C[:];a=delta*pow(last,-1,q)%q
        C += [0]*max(0,len(B)+s-len(C))
        for j,z in enumerate(B):C[j+s]=(C[j+s]-a*z)%q
        if 2*L<=n:L=n+1-L;B=old;last=delta;s=1
        else:s+=1
    return C[:L+1]

def recover(public_slices,b,q):
    C=public_slices;N=len(C[0]);Q=inv(C[1],q);A=mul(Q,C[2],q)
    if b==1:F0=comm(mul(Q,C[0],q),A,q);F1=comm(Q,A,q)
    else:
        B=mul(Q,C[3],q);S=comm(A,B,q);H=mul(S,S,q)
        F0=comm(H,mul(Q,C[0],q),q);F1=comm(H,Q,q)
    Z=mul(inv(F1,q),F0,q)
    rng=np.random.default_rng(93);u=rng.integers(0,q,N,dtype=np.int64);v=rng.integers(0,q,N,dtype=np.int64)
    seq=[]
    for _ in range(2*N):seq.append(int(u@v%q));v=Z@v%q
    polynomial=recurrence(seq,q)
    _,factors=gf_factor(polynomial,q,ZZ)
    candidates=sorted({(-int(f[1])*pow(int(f[0]),-1,q))%q for f,e in factors if len(f)==2})
    return {'N':N,'polynomial_degree':len(polynomial)-1,'candidates':candidates,'polynomial':polynomial}

if __name__=='__main__':
    result=[]
    for b in (1,2):
        key=50027;q=65537;m=32
        public=generate(m,b,q,7060+b,key)
        out=recover(public,b,q) # key, setup seed, and private factors are not arguments.
        assert key in out['candidates']
        out.update({'q':q,'m':m,'block_size':b,'margin':1,'residual_masks':False,
                    'reference_key':key,'reference_key_in_candidates':True,
                    'source_family':'complete connected false SOURCE from pinned unmasked audit',
                    'attack_uses_field_or_witness_enumeration':False})
        out.pop('polynomial')
        result.append(out)
    print(json.dumps(result,indent=2,sort_keys=True))
