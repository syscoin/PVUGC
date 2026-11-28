"""Unmasked minimal-margin spectral candidate: exact small-field reproduction.

Uses NumPy int64 only within an explicitly checked non-overflow bound.
Deterministic coins are for reproducibility, not production key generation.
The attack function receives only public coefficient matrices.
"""
import numpy as np
from time import perf_counter

def rank(A,p):
 A=A.copy()%p;n,m=A.shape;r=0
 for j in range(m):
  ids=np.flatnonzero(A[r:,j]);
  if not len(ids):continue
  k=r+int(ids[0]);A[[r,k]]=A[[k,r]]
  A[r]=A[r]*pow(int(A[r,j]),-1,p)%p
  if r+1<n:A[r+1:]=(A[r+1:]-A[r+1:,j,None]*A[r])%p
  r+=1
  if r==n:break
 return r

def inv(A,p):
 n=A.shape[0];B=np.concatenate([A.copy()%p,np.eye(n,dtype=np.int64)],axis=1)
 for j in range(n):
  ids=np.flatnonzero(B[j:,j]);
  if not len(ids):raise ValueError('singular')
  k=j+int(ids[0]);B[[j,k]]=B[[k,j]]
  B[j]=B[j]*pow(int(B[j,j]),-1,p)%p
  vals=B[:,j].copy();vals[j]=0
  B=(B-vals[:,None]*B[j])%p
 return B[:,n:]

def mm(A,B,p):return (A@B)%p

def comm(A,B,p):return (mm(A,B,p)-mm(B,A,p))%p

def generate(m,b,seed=5,p=65537,K=31415):
 # variables z0, u, x1, ..., x_(m-3).
 # g0 u*u=z0*z0; g1 u*z0=z0*z0; bits xi*xi=u*xi;
 # last (sum_i xi)*u=(v+1)*u*u. Every bit enters the accepting constraint.
 # False for p>v+1, and projectively safe.
 if m < 7 or b not in (1,2): raise ValueError("need m>=7 and block size 1 or 2")
 rng=np.random.default_rng(seed);n=2*b*m+1;v=m-3
 if 4*max(n,4*b)*p*p >= 2**63: raise ValueError("field/dimension exceed int64 arithmetic bound")
 inds=[0,3,4,5] # constant, x2(ref), x3(A), x4(B)
 C=[np.zeros((n,n),dtype=np.int64) for _ in inds]
 for g in range(m):
  L=rng.integers(0,p,(n,4*b),dtype=np.int64)
  R=rng.integers(0,p,(4*b,n),dtype=np.int64)
  for k,j in enumerate(inds):
   if g==0:tup=(int(j==1),int(j==1),int(j==0),int(j==0))
   elif g==1:tup=(int(j==1),int(j==0),int(j==0),int(j==0))
   elif g<m-1:
    xidx=g # g2->x1 index2
    tup=(int(j==xidx),int(j==xidx),int(j==1),int(j==xidx))
   else:tup=(int(j>=2),int(j==1),(v+1)*int(j==1),int(j==1))
   a,bb,c,d=tup;I=np.eye(b,dtype=np.int64)
   X=rng.integers(0,p,(b,b),dtype=np.int64)
   G=np.zeros((4*b,4*b),dtype=np.int64)
   G[:b,:b]=a*I;G[:b,b:2*b]=c*I;G[:b,2*b:3*b]=-X
   G[b:2*b,:b]=d*I;G[b:2*b,b:2*b]=bb*I;G[b:2*b,3*b:]=X
   G[2*b:3*b,2*b:3*b]=bb*I;G[2*b:3*b,3*b:]=c*I
   G[3*b:,2*b:3*b]=d*I;G[3*b:,3*b:]=a*I
   C[k]=(C[k]+mm(mm(L,G%p,p),R,p))%p
 C[0]=(C[0]+K*np.eye(n,dtype=np.int64))%p
 return C

def probe(m,b,seed=5,p=65537):
 K=31415;C=generate(m,b,seed,p,K);n=C[0].shape[0];I=np.eye(n,dtype=np.int64)
 Q=inv(C[1],p);T0=mm(Q,(C[0]-K*I)%p,p);TA=mm(Q,C[2],p);TB=mm(Q,C[3],p)
 if b==1:
  F0=comm(mm(Q,C[0],p),TA,p);F1=comm(Q,TA,p)
 elif b==2:
  H=mm(comm(TA,TB,p),comm(TA,TB,p),p)
  F0=comm(H,mm(Q,C[0],p),p);F1=comm(H,Q,p)
 else:return
 out={'m':m,'b':b,'N':n,'rank_at_K':rank((F0-K*F1)%p,p),'rank_F1':rank(F1,p),'rank_at_K_plus1':rank((F0-(K+1)*F1)%p,p)}
 print(out,flush=True)
 return C,F0,F1

if __name__=='__main__':
 for b in [1,2]:
  for m in [12,20,32,48]:
   st=perf_counter();probe(m,b);print('seconds',perf_counter()-st,flush=True)

def bm(seq,p):
 C=[1];B=[1];L=0;shift=1;last=1
 for n,s in enumerate(seq):
  delta=(int(s)+sum(C[i]*int(seq[n-i]) for i in range(1,L+1)))%p
  if delta==0:shift+=1;continue
  T=C[:];a=delta*pow(last,-1,p)%p
  need=len(B)+shift
  if len(C)<need:C += [0]*(need-len(C))
  for j,z in enumerate(B):C[j+shift]=(C[j+shift]-a*z)%p
  if 2*L<=n:
   L=n+1-L;B=T;last=delta;shift=1
  else:shift+=1
 return list(reversed(C[:L+1]))

def minimal_poly(A,p,seed=17):
 rng=np.random.default_rng(seed);n=A.shape[0]
 u=rng.integers(0,p,n,dtype=np.int64);v=rng.integers(0,p,n,dtype=np.int64)
 seq=[]
 for _ in range(2*n):
  seq.append(int(u@v%p));v=A@v%p
 return bm(seq,p)

def roots(poly,p):
 from sympy.polys.galoistools import gf_factor
 from sympy.polys.domains import ZZ
 _,fac=gf_factor(list(reversed(poly)),p,ZZ)
 return sorted({(-int(f[1])*pow(int(f[0]),-1,p))%p for f,e in fac if len(f)==2})

def recover(C,b,p):
 n=C[0].shape[0];Q=inv(C[1],p);TA=mm(Q,C[2],p)
 if b==1:
  F0=comm(mm(Q,C[0],p),TA,p);F1=comm(Q,TA,p)
 else:
  TB=mm(Q,C[3],p);S=comm(TA,TB,p);H=mm(S,S,p)
  F0=comm(H,mm(Q,C[0],p),p);F1=comm(H,Q,p)
 A=mm(inv(F1,p),F0,p)
 mp=minimal_poly(A,p)
 return {'polynomial_degree':len(mp)-1,'candidates':roots(mp,p),'poly':mp}
