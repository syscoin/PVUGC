import json,math,random
checks=0
def ok(x):
 global checks
 checks+=1
 assert x

def gate(v,op,w):
 if op==0:return v^(1<<w[0])
 if op==1:return v^((1<<w[1]) if v>>w[0]&1 else 0)
 if op==2:return v^((1<<w[2]) if (v>>w[0]&1) and (v>>w[1]&1) else 0)
 a,b=w
 return v^((1<<a)|(1<<b)) if (v>>a&1)!=(v>>b&1) else v

def circ(n,depth,seed):
 r=random.Random(seed)
 return [(op:=r.randrange(4),r.sample(range(n),(1,2,3,2)[op])) for _ in range(depth)]

def mix(x,gates):
 for op,w in gates:x=gate(x,op,w)
 return x

cases=0
for n,k in ((6,3),(8,4),(10,5)):
 for depth in (0,1,7,37,128):
  for seed in (2,17,101,690):
   f=circ(n,depth,seed+100*n)
   outputs=[mix(x,f) for x in range(1<<n)]
   ok(len(set(outputs))==1<<n)
   for key in range(1<<k):
    fiber=[v&((1<<(n-k))-1) for v in outputs if v>>(n-k)==key]
    ok(len(fiber)==1<<(n-k) and len(set(fiber))==len(fiber))
   cases+=1

qchecks=0
for n,k in ((6,3),(8,4)):
 for seed in (2,17,101):
  f=circ(n,37,seed+100*n)
  marked={x for x in range(1<<n) if mix(x,f)>>(n-k)==5}
  theta=math.asin(math.sqrt(len(marked)/(1<<n)))
  for t in range(5):
   amps=[1/math.sqrt(1<<n)]*(1<<n)
   for _ in range(t):
    amps=[-a if i in marked else a for i,a in enumerate(amps)]
    mean=sum(amps)/len(amps)
    amps=[2*mean-a for a in amps]
   p=sum(amps[i]**2 for i in marked)
   ok(abs(p-math.sin((2*t+1)*theta)**2)<1e-10)
   ok(abs(sum(v*v for v in amps)-1)<1e-10)
   qchecks+=1
for n,k in ((6,3),(8,4),(10,5)):
 for m in (1,2,3,2**(n-k)):
  ok(math.ceil(math.log2(m))<=n-k)
print(json.dumps({'run':690,'cases':cases,'grover_statevector_cases':qchecks,'checks_passed':checks,'scope':'total public permutation plus k-bit credential projection only','security_claim':False},sort_keys=True,separators=(',',':')))
