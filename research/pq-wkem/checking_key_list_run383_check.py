#!/usr/bin/env python3
"""Run 383 finite toy check; NOT LWE security or a Bitcoin signature verifier."""
import hashlib,itertools,json,math,random
q,d=257,128
checks=0

def ck(ok):
 global checks
 checks+=1
 assert ok

def dist(x,y):
 a=(x-y)%q
 return min(a,q-a)

def near(y): return int(dist(y,d)<dist(y,0))
def options(y): return [b for b in (0,1) if dist(y,d*b)<=75]
def key(bits): return hashlib.sha256(b'Run383-test-key-v1:'+bytes(bits)).digest()

for h,k,e in itertools.product(range(q),(0,1),(-25,25)):
 D=(d*k-3*e)%q
 ck(near(D)!=k and options(D)==[0,1])
 for x in range(-2,3):
  for a,b in itertools.product((-1,0,1),repeat=2):
   if a+b==x:
    y=(d*k+h*x-(h+e)*a-h*b)%q
    ck(near(y)==k)

rng=random.Random(383639)
success=fail_nearest=maximum=0
for n in (16,64,256):
 for sample in range(60):
  K=[rng.randrange(2) for _ in range(n)]
  hs=[rng.randrange(q) for _ in range(n)]
  es=[(25 if rng.randrange(2) else -25) if rng.randrange(n)==0 else 0 for _ in range(n)]
  Y=[(d*k-3*e)%q for k,e in zip(K,es)]
  sets=[options(y) for y in Y]
  t=sum(len(s)==2 for s in sets)
  ck(t==sum(e!=0 for e in es))
  fail_nearest+=([near(y) for y in Y]!=K)
  ck(t<=math.ceil(2*math.log2(n)))
  found=False
  for candidate in itertools.product(*sets):
   if key(candidate)==key(K):
    ck(list(candidate)==K)
    found=True
    break
  ck(found)
  maximum=max(maximum,t)
  success+=1

for t in range(2,8):
 N=1<<t
 s=[1/math.sqrt(N)]*N
 rounds=round(math.pi/(4*math.asin(1/math.sqrt(N)))-.5)
 for _ in range(rounds):
  s[-1]=-s[-1]
  avg=sum(s)/N
  s=[2*avg-v for v in s]
 expected=math.sin((2*rounds+1)*math.asin(1/math.sqrt(N)))**2
 ck(abs(s[-1]**2-expected)<1e-12)

print(json.dumps({'run':383,'status':'PASS','assertions':checks,'independent_error_fixtures':success,'nearest_failure_fixtures':fail_nearest,'maximum_ambiguous_positions':maximum,'coherent_grover_widths':[2,3,4,5,6,7],'real_lwe':False,'qpt_security':False},sort_keys=True))
