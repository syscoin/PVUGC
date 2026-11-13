"""Exact executed finite functional checker; MOCK public key, NO native sign/verify or QPT proof."""
import hashlib,random,json,math
R=random.Random(20261030); checks=0
q=1009; m=4; ell=5; L=52; g=q//32; A=[7,7,17,19]; U=7
Z=[(1,0,0,0),(0,1,0,0)]
def ck(v):
 global checks
 assert v;checks+=1
def trip(scope,k):
 d=b'PVUGC/PQ-WKEM/native-master/v1\0'+len(scope).to_bytes(4,'big')+scope+k
 return hashlib.shake_256(d).digest(48)
def pk_of(y):
 return y[32:48]+hashlib.sha256(b'MOCK-PK-ROOT'+y[:16]+y[32:48]).digest()[:16]
def digits(k):return [(int.from_bytes(k,'little')>>(5*i))&31 for i in range(L)]
def capsule(ds):
 r=R.randrange(q); e=[R.randint(-1,1) for _ in A]
 c=[(a*r+x)%q for a,x in zip(A,e)]
 d=[(U*r+R.randint(-1,1)+g*x)%q for x in ds]
 return c,d
def release(scope,pk,z,ct):
 c,d=ct
 ck(sum(a*b for a,b in zip(A,z))%q==U and sum(abs(i) for i in z)==1)
 digs=[]
 for v in d:
  phase=(v-sum(a*b for a,b in zip(z,c)))%q
  dist=lambda i:min((phase-g*i)%q,(g*i-phase)%q)
  matches=[i for i in range(32) if dist(i)<=2]
  ck(len(matches)==1);digs.append(matches[0])
 k=sum(x<<(5*i) for i,x in enumerate(digs))
 ck(k<1<<256)
 seed=k.to_bytes(32,'little')
 ck(pk_of(trip(scope,seed))==pk)
 return seed
ck(2*(1+1)<g and q-31*g>2*(1+1));ck(len(Z)==2 and Z[0]!=Z[1])
for scope in (b'claim-A/utxo1',b'claim-B/utxo2'):
 k=R.randbytes(32); y=trip(scope,k); pk=pk_of(y)
 ck(len(y)==48 and len(pk)==32 and len(digits(k))==L)
 for _ in range(2):
  ct=capsule(digits(k))
  for z in Z:ck(release(scope,pk,z,ct)==k)
  try:release(scope,bytes([pk[0]^1])+pk[1:],Z[0],ct)
  except AssertionError:ck(True)
  else:ck(False)
N,C,J,n,m_real=4,100,2,256,4469
def size(l):return 3*(N*n*m_real+N*C*n*l+N*C*J*(m_real+l))
ck(size(77)==48293568);ck(size(52)==40553568)
ck(size(77)-size(52)==7740000)
print(json.dumps({'record':'native_master_seed_dual_lwe_20261030','checks':checks,'master_bits':256,'derived_native_seed_bits':384,'master_digit_columns':52,'raw_seed_digit_columns':77,'saved_bytes':size(77)-size(52),'classification':'restricted source seed-to-native composition; native public key mocked; not ORIGINAL witness-KEM'},sort_keys=True))
