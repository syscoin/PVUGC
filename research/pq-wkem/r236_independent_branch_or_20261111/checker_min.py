"""R236 independent branch OR wrapper; NO ORIGINAL release gate."""
import hashlib,json,random

def H(tag,*v):
 d=tag.encode()+b'\0'+b''.join(len(x).to_bytes(4,'big')+x for x in v)
 return hashlib.sha256(d).digest()
def X(a,b):return bytes(i^j for i,j in zip(a,b))
def PAD(ctx,k,n):return b''.join(H('pad',ctx,k,i.to_bytes(4,'big')) for i in range((n+31)//32))[:n]
def low(k):return hashlib.sha256(b'toy'+bytes([k])).digest()[0]

r=random.Random(1631)
report={'common_signature':0,'joint_partial_leak_unique':0,'joint_trials':0}
for t in range(80):
 ctx=H('context',t.to_bytes(2,'big'))
 keys=[H('k',ctx,bytes([j])) for j in range(3)]
 s=H('s',ctx);sigma=H('sig',ctx)+H('sig2',ctx)
 E=[X(s,H('branch',ctx,bytes([j]),keys[j])) for j in range(3)]
 D=X(sigma,PAD(ctx,s,len(sigma)))
 for j in range(3):
  ss=X(E[j],H('branch',ctx,bytes([j]),keys[j]))
  assert X(D,PAD(ctx,ss,len(sigma)))==sigma
  report['common_signature']+=1
for t in range(100):
 keys=[r.randrange(256) for _ in range(3)];s=r.randrange(256)
 E=[s^low(k) for k in keys]
 cand=[{E[j]^low(v) for v in range(256) if v>>4==keys[j]>>4} for j in range(3)]
 intersection=set.intersection(*cand)
 assert s in intersection
 report['joint_trials']+=1
 report['joint_partial_leak_unique']+=(len(intersection)==1)
print(json.dumps(report,sort_keys=True,indent=2))
