#!/usr/bin/env python3
"""R85 exact toy identities; no QPT/128-bit security claim."""
import hashlib,json
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.exceptions import InvalidSignature
N,M,L,T=2,6,8,2
K=N*L+M*T;D=M*L-K;Q=1<<L; checks=0;decodes=0;collisions=0
assert (K,D)==(28,20)
def ck(x):
 global checks
 checks+=1
 assert x,checks
def H(x):return hashlib.sha256(x).digest()
A=[[H(bytes([i,j]))[0] for j in range(N)] for i in range(M)]
def G(x):
 s=[(x>>(M*T+(N-1-i)*L))&(Q-1) for i in range(N)]
 e=[((x>>((M-1-i)*T))&((1<<T)-1))-(1<<(T-1)) for i in range(M)]
 out=0
 for a,v in zip(A,e):out=(out<<L)|((sum(a[j]*s[j] for j in range(N))+v)%Q)
 return out
def expand(x,size):
 out=[]
 while len(out)<size:
  y=G(x);x=y>>D
  out.extend((y>>i)&1 for i in range(D-1,-1,-1))
 return bytes(int(''.join(map(str,out[i:i+8])),2) for i in range(0,size,8))
def ciphertext(x,tag):
 out=[]
 for j in range(K):
  b=(x>>(K-1-j))&1
  r=[H(tag+bytes([j,i]))[0]&1 for i in range(4)]
  u=sum(r);out.append((u,(u+128*b)%257))
 return out
def open_seed(C,s):
 global decodes
 res=0
 for u,v in C:
  d=(v-s*u)%257
  d0=min(d,257-d);d1=min((d-128)%257,(128-d)%257)
  ck(d0!=d1);res=(res<<1)|int(d1<d0);decodes+=1
 return res
for i in range(24):
 tag=H(b'R85'+bytes([i]));seed=int.from_bytes(tag,'big')&((1<<K)-1)
 C=ciphertext(seed,tag);out=expand(seed,640);P,B=out[:64],out[64:]
 sk=Ed25519PrivateKey.from_private_bytes(H(tag+b'key'))
 m=H(tag+b'authorized-challenge');sig=sk.sign(m)
 masked=bytes(a^b for a,b in zip(sig,P))
 check=H(B+masked+str(C).encode()+m)
 for s in (0,1,2):
  seed2=open_seed(C,s);ck(seed2==seed)
  P2,B2=expand(seed2,640)[:64],expand(seed2,640)[64:]
  sig2=bytes(a^b for a,b in zip(masked,P2))
  ck(H(B2+masked+str(C).encode()+m)==check)
  sk.public_key().verify(sig2,m);ck(sig2==sig)
 other=expand(seed^1,640);P3,B3=other[:64],other[64:]
 if H(B3+masked+str(C).encode()+m)==check:collisions+=1
 wrong=bytes(a^b for a,b in zip(masked,P3))
 try:sk.public_key().verify(wrong,m);ck(False)
 except InvalidSignature:ck(True)
ck(decodes==24*3*K)
print(json.dumps({'run':'R85-LWE-EXACT-PRG-20261105','assertions':checks,
 'source_bit_decodes':decodes,'same_capability_openings':72,
 'wrong_seed_checking_seed_collisions':collisions,'seed_bits':K,'per_call_stretch_bits':D,
 'status':'RESTRICTED_CONDITIONAL_NOT_GENERIC_WKEM'},sort_keys=True))
