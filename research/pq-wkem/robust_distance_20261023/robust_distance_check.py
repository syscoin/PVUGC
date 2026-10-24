"""Honest-setup robust sampled-QAP/rank-gate certificate; no QPT key-security claim."""
import json, math, random
import numpy as np
Q=16
M=np.zeros((Q,Q),dtype=np.uint8)
for a in range(Q):
 for b in range(Q):
  x,y,z=a,b,0
  while y:
   if y&1:z^=x
   y>>=1;x<<=1
   if x&Q:x^=0x13
  M[a,b]=z
I=[0]+[next(b for b in range(1,Q) if M[a,b]==1) for a in range(1,Q)]
def mm(A,B):
 O=np.zeros((A.shape[0],B.shape[1]),dtype=np.uint8)
 for j in range(A.shape[1]):O^=M[A[:,j,None],B[j,None,:]]
 return O
def rank(A):
 A=A.copy();r=0
 for j in range(A.shape[1]):
  p=next((i for i in range(r,A.shape[0]) if A[i,j]),None)
  if p is None:continue
  if p!=r:A[[p,r]]=A[[r,p]]
  A[r]=M[A[r],I[A[r,j]]]
  for i in range(r+1,A.shape[0]):
   if A[i,j]:A[i]^=M[A[r],A[i,j]]
  r+=1
  if r==A.shape[0]:break
 return r
def gate(v,t):
 a,b,c,d,s=map(int,v)
 P=np.array([[0,a,d,s],[a,0,s,c],[d,s,0,b],[s,c,b,0]],dtype=np.uint8)
 S=np.array([[0,b,c,s],[b,0,s,d],[c,s,0,a],[s,d,a,0]],dtype=np.uint8)
 G=np.zeros((8,8),dtype=np.uint8);G[:4,:4]=P;G[4:,4:]=S
 G[:4,4:]=t*np.eye(4,dtype=np.uint8)
 return G
F=[np.array([[0,1,0,1,0],[1,1,0,0,0],[0,0,a,0,0]],dtype=np.uint8) for a in (1,2,4)]
K=9;N=16;D=12
def build(seed):
 rng=random.Random(seed);C=np.zeros((3,N,N),dtype=np.uint8)
 for f in F:
  U=np.array([[rng.randrange(Q) for _ in range(8)] for _ in range(N)],dtype=np.uint8)
  V=np.array([[rng.randrange(Q) for _ in range(N)] for _ in range(8)],dtype=np.uint8)
  eta=[rng.randrange(Q) for _ in range(3)]
  for j in range(3):C[j]^=mm(mm(U,gate(f[j],eta[j])),V)
 C[0]^=M[K,np.eye(N,dtype=np.uint8)]
 return C
def cert():
 n,m,r,T,h=11000,16000,11726,83,165
 q=1<<256;k=n+m;L=m-1+r;N=4*L+h;A=m+T-2
 assert 4*T>=2*h and h*h>k
 assert q>=2*r*(2*m-2+r)
 top=2*math.comb(m-1+r,T-1)*A**r
 bottom=q**(r-n-T+1)
 assert top*(1<<212)<bottom
 assert 16*(h+1)*(1<<130)<q**(h*h-k+1)
 assert 4*(1<<130)<q**(h*h-k)
 rp=r-1
 assert 2*math.comb(m-1+rp,T-1)*A**rp*(1<<129)>=q**(rp-n-T+1)
 oldN=117292
 return dict(n=n,m=m,k=k,field_bits=256,r=r,T=T,h=h,L=L,N=N,
  distance_less_than_2minus212=True,correct_rank_less_than_2minus130=True,
  wrong_scalar_less_than_2minus130=True,old_bytes=k*oldN**2*32,
  new_bytes=k*N*N*32,saved_bytes=k*(oldN**2-N**2)*32)
def run():
 count=0;hist={};results=[]
 for w in range(Q):
  for rho in range(Q):
   z=[int(M[w,w^1])^int(M[a,rho]) for a in (1,2,4)]
   v=sum(bool(t) for t in z)
   good=(w in (0,1) and rho==0)
   assert (v==0)==good;count+=1
   if not good:assert v>=2;count+=1
   hist[v]=hist.get(v,0)+1
 for seed in (47,79):
  C=build(seed);goodcount=badcount=0;honest=[]
  for w in range(Q):
   for rho in range(Q):
    y=(1,w,rho);X=np.zeros((N,N),dtype=np.uint8)
    for j in range(3):X^=M[y[j],C[j]]
    accepted=[lam for lam in range(Q) if rank(X^M[lam,np.eye(N,dtype=np.uint8)])<=D]
    count+=Q+1
    good=(w in (0,1) and rho==0)
    assert accepted==([K] if good else [])
    if good:goodcount+=1;honest.append(X)
    else:badcount+=len(accepted)
  assert len(honest)==2 and not np.array_equal(honest[0],honest[1]);count+=1
  results.append(dict(seed=seed,accepted_valid_pairs=goodcount,accepted_invalid_or_wrong_pairs=badcount,
                      field_key_source_pair_checks=Q**3))
 return dict(checkpoint='robust-distance-rank-selection-20261023',assertions=count,
  synthetic_Gf16_distance_histogram=hist,experiments=results,
  exact_256bit_certificate=cert(),key_only_secrecy_proved=False,
  status='SUPPLIED_PAIR_SOURCE_EXTRACTION_ONLY')
if __name__=='__main__':print(json.dumps(run(),indent=2,sort_keys=True))
