#!/usr/bin/env python3
"""Synthetic clause-state consistency and matrix-projector screen. No real FE/source."""
from hashlib import sha256
from itertools import product
import json
P=(1<<127)-1; N=4; F=3
def ch(x,y,z): return (x&y)|((1-x)&z)
def clauses(v,true):
    x,y,z,t=v
    return (int(t!=ch(x,y,z)),int(t!=ch(x,z,y)),int((y!=z) if true else (y==z)))
def penalty(path,true):
    q=sum(clauses(path[j],true)[j] for j in range(F))
    ks=[sum(path[j][v] for j in range(F)) for v in range(N)]
    bad=sum(k*(F-k) for k in ks)
    return q+bad,q,bad
D=2+2*N
def transition(bits,j,true):
    m=[[int(i==k) for k in range(D)] for i in range(D)]
    for i,b in enumerate(bits):
        m[1+i][0]=b; m[1+N+i][0]=b; m[1+N+i][1+i]=2*b
    m[-1][0]=clauses(bits,true)[j]
    return m
def mv(m,x): return [sum(a*b for a,b in zip(row,x)) for row in m]
def matrix_penalty(path,true):
    x=[1]+[0]*N+[0]*N+[0]
    for j,b in enumerate(path): x=mv(transition(b,j,true),x)
    assert all(x[1+N+i]==x[1+i]**2 for i in range(N))
    return x[-1]+sum(F*x[1+i]-x[1+N+i] for i in range(N))
bits=list(product((0,1),repeat=4))
false_zero=true_zero=false_splice=0
for path in product(bits,repeat=F):
    v,q,bad=penalty(path,False)
    assert matrix_penalty(path,False)==v
    false_zero+=(v==0); false_splice+=(q==0 and bad>0)
    t,_,_=penalty(path,True)
    assert matrix_penalty(path,True)==t
    true_zero+=(t==0)
assert false_zero==0 and false_splice>0 and true_zero>0
def mul(a,b):return [[sum(a[i][k]*b[k][j] for k in range(2))%P for j in range(2)] for i in range(2)]
def inverse(a):
    invdet=pow((a[0][0]*a[1][1]-a[0][1]*a[1][0])%P,-1,P)
    return [[a[1][1]*invdet%P,-a[0][1]*invdet%P],[-a[1][0]*invdet%P,a[0][0]*invdet%P]]
def power(a,n):
    v=[[1,0],[0,1]]
    while n:
        if n&1:v=mul(v,a)
        a=mul(a,a);n>>=1
    return v
R=[[11,43],[17,71]];RI=inverse(R);gamma=0x4a12f47c9d5842ba33b1e
def mval(v):return mul(mul(R,[[gamma*v%P,0],[0,1]]),RI)
projector=mval(0);I=[[1,0],[0,1]]
assert power(projector,P-1)==projector
for w in bits:
    v,_,_=penalty((w,w,w),True)
    assert power(mval(v),P-1)==(projector if v==0 else I)
v,_,_=penalty((bits[0],bits[1],bits[-1]),False)
assert v>0
M=mval(v);g=(M[0][0]+M[1][1]-1)%P
assert g not in (0,1) and power(M,P-1)==I
ig=pow((1-g)%P,-1,P)
recovered=[[(M[i][j]-(g if i==j else 0))*ig%P for j in range(2)] for i in range(2)]
assert recovered==projector
def key(m):return sha256(b'SAI117-test-key'+b''.join(n.to_bytes(16,'big') for row in m for n in row)).digest()
S=sha256(b'SAI117 synthetic fixed safe signature stand-in').digest()
cipher=bytes(a^b for a,b in zip(S,key(projector)))
assert bytes(a^b for a,b in zip(cipher,key(recovered)))==S
print(json.dumps(dict(scope='synthetic arithmetic; NO original evidence, FE or native signing',
false_global_satisfying_paths=false_zero,false_locally_accepted_inconsistent_paths=false_splice,
true_global_satisfying_paths=true_zero,field_bits=P.bit_length(),path_violation=v,
invalid_power_identity=power(M,P-1)==I,one_invalid_pre_power_sample_recovers_secret_projector=True,
frozen_synthetic_payload_recovered_without_original_witness=True),sort_keys=True,indent=2))
