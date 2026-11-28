#!/usr/bin/env python3
"""Finite algebra checks only; not QPT, SLH, or generic NP security."""
import itertools, json, math, random, hashlib
from math import comb
rng=random.Random(20261028)
checks=0
def ck(v):
    global checks
    checks+=1
    assert v

def xor(*bs): return bytes(__import__('functools').reduce(lambda a,b:a^b,col,0) for col in zip(*bs))
def digs(x,T,L):
    a=int.from_bytes(x,'big'); out=[]
    for _ in range(L):out.append(a%T); a//=T
    ck(a==0)
    return out

def source(A,q,d):
    m=len(A);n=len(A[0]);S=[[rng.randrange(q) for _ in range(d)] for _ in range(n)]
    E=[[rng.choice((-1,0,1)) for _ in range(d)] for _ in range(m)]
    B=[[(sum(A[i][v]*S[v][j] for v in range(n))+E[i][j])%q for j in range(d)] for i in range(m)]
    return B,S,E

def encdec(A,B,S,E,a,r,q,h):
    m=len(A);n=len(A[0]);d=len(B[0]);g=2*h+1;T=q//g
    c=[sum(A[i][v]*r[i] for i in range(m))%q for v in range(n)]
    y=[(sum(B[i][j]*r[i] for i in range(m))+g*a[j])%q for j in range(d)]
    ck(all((sum(A[i][v]*S[v][j] for v in range(n))+E[i][j]-B[i][j])%q==0 for i in range(m) for j in range(d)))
    out=[]
    for j in range(d):
        z=(y[j]-sum(S[v][j]*c[v] for v in range(n)))%q
        a2=min(range(T),key=lambda b:min((z-g*b)%q,(g*b-z)%q))
        ck(min((z-g*a2)%q,(g*a2-z)%q)<=h)
        out.append(a2)
    return out

q=257;m=9;n=2;d=3;h=2;t=3;g=5;T=q//g
A=[[rng.randrange(q) for _ in range(n)] for _ in range(m)]
B1,S1,E1=source(A,q,d);B2,S2,E2=source(A,q,d)
ck(B1!=B2)
for B,S,E in ((B1,S1,E1),(B2,S2,E2)):
    K=rng.randbytes(32);U=rng.randbytes(32);Z=[rng.randbytes(32) for _ in range(t)]
    D=xor(U,*Z);V=xor(K,U);recovered=[]
    L=0;p=1
    while p<2**256:p*=T;L+=1
    for share in Z:
        a=digs(share,T,L);dec=[]
        for off in range(0,L,d):
            vec=a[off:off+d]+[0]*max(0,d-len(a[off:off+d]))
            r=[0]*m;r[0]=1;r[1]=-1
            dec+=encdec(A,B,S,E,vec,r,q,h)
        got=sum(x*T**i for i,x in enumerate(dec[:L])).to_bytes(32,'big')
        ck(got==share);recovered.append(got)
    ck(xor(V,D,*recovered)==K)
    ck(hashlib.sha256(xor(V,D,*recovered)).digest()==hashlib.sha256(K).digest())
# Reusing complete B under another label does not revoke witness access:
ck(encdec(A,B1,S1,E1,[11,13,17],[1,-1]+[0]*(m-2),q,h)==[11,13,17])
# Exhaust all uniform H=[A|B] and all distinct signed-sphere pairs.
q0=5;R=[(1,0),(-1,0),(0,1),(0,-1)];pairs=list(itertools.combinations(range(4),2))
hits=[0]*len(pairs);total=0
for H in itertools.product(range(q0),repeat=4):
    imgs=[((H[0]*r[0]+H[2]*r[1])%q0,(H[1]*r[0]+H[3]*r[1])%q0) for r in R]
    for k,(i,j) in enumerate(pairs):hits[k]+=imgs[i]==imgs[j]
    total+=1
for h0 in hits:ck(h0*q0**2==total)
# Exact high-parameter integer comparisons, not a QPT parameter certification.
q=65537;m=1600;n=128;d=14;h=800;t=3;L=4
N=sum(2**k*comb(m,k)*comb(h-1,k-1) for k in range(1,h+1))
ck((t*L)**2*(q**(n+d)-1)*2**256<=4*N)
A=m*n;per=m*d+t*L*(n+d)
rows={}
for M in (1,2,10,100):
    old=M*(A+per);new=A+M*per
    ck(old-new==(M-1)*A)
    rows[M]={'repeated':old,'shared':new,'percent_saved':round(100*(1-new/old),5)}
print(json.dumps({'status':'PASS','checks':checks,'whole_H_cases':total,'collisions_by_pair':hits,'mock_capability_bits':256,'sources':2,'shares_per_source':3,'shared_A_elements':A,'per_source_B_and_ciphertexts':per,'field_elements':rows,'qpt_test':False,'generic_NP':False},sort_keys=True,indent=2))
