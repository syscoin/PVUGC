#!/usr/bin/env python3
"""Run 372 finite toy algebra, NOT an LWE/QPT security demonstration."""
import random,json
q,d,n,m=257,128,3,8
checks=0
def ck(x):
 global checks
 checks+=1
 assert x
rng=random.Random(372)
s=[rng.randrange(q) for _ in range(n)]
a=[[rng.randrange(q) for _ in range(n)] for _ in range(m)]
e=[rng.randrange(-1,2) for _ in range(m)]
b=[(sum(a[i][j]*s[j] for j in range(n))+e[i])%q for i in range(m)]
def coin(t): return [(t>>i)&1 for i in range(m)]
def enc(bit,r):
 return (tuple(sum(r[i]*a[i][j] for i in range(m))%q for j in range(n)),
         (sum(r[i]*b[i] for i in range(m))+d*bit)%q)
def dec(c):
 u,v=c
 z=(v-sum(u[j]*s[j] for j in range(n)))%q
 dist=lambda z,t:min((z-t)%q,(t-z)%q)
 return int(dist(z,d)<dist(z,0))
def bits(t,l):return [(t>>i)&1 for i in range(l)]
def inject(ct,w):
 return ct[:4]+[(ct[4+j][0],(ct[4+j][1]+d*w[j])%q) for j in range(6)]
for t in range(1<<m):
 r=coin(t)
 for v in (0,1):ck(dec(enc(v,r))==v)
 ck(enc(1,r)==(enc(0,r)[0],(enc(0,r)[1]+d)%q))
for key in range(16):
 k=bits(key,4)
 rs=[coin((17*j+13*key+97)%256) for j in range(10)]
 base=[enc(k[j] if j<4 else 0,rs[j]) for j in range(10)]
 for wnum in range(64):
  w=bits(wnum,6)
  x=inject(base,w)
  ck(x==[enc(v,r) for v,r in zip(k+w,rs)])
  ck([dec(c) for c in x]==k+w)
  ck(x[:4]==base[:4])
 valid=[bits(v,6) for v in range(64) if ((v&31)<17 and ((v&31)**2)%17==4)]
 ck(len(valid)==4)
 ck(all([dec(c) for c in inject(base,w)[:4]]==k for w in valid))
 ck([dec(c) for c in inject(base,bits(1,6))[4:]]==bits(1,6))
print(json.dumps({'run':372,'status':'PASS','assertions':checks,'q':q,'n':n,'m':m,'witness_bits':6,'key_bits':4,'scope':'toy finite algebra only; no QPT security'},sort_keys=True))
