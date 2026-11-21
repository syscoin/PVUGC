# ISOC finite-field + toy RSA checker. Toy native RSA is factorable, NOT PQ.
import random, hashlib, json, math
r=random.Random(20263218); q=257; g=64; d=4; n=6; checks=0
def ok(x):
 global checks
 checks+=1; assert x
def dot(a,b):return sum(x*y for x,y in zip(a,b))%q
def bits(k):return [(v>>j)&1 for v in k for j in range(7,-1,-1)]
def key(bs):return bytes(sum(bs[i+j]<<(7-j) for j in range(8)) for i in range(0,len(bs),8))
def enc(A,t,b):
 s=[r.randrange(q) for _ in A]; e=[r.randint(-1,1) for _ in A[0]]; z=r.randint(-1,1)
 c=[(sum(A[i][j]*s[i] for i in range(len(A)))+e[j])%q for j in range(len(A[0]))]
 return (c,(dot(t,s)+z+g*b)%q),(s,e,z)
def dec(w,C):
 out=[]
 for c,tau in C:
  z=(tau-dot(w,c)+q//2)%q-q//2
  out.append(0 if abs(z)<abs(z-g) else 1)
 return key(out)
def sig(sk,mod,msg):return pow(int.from_bytes(hashlib.sha256(msg).digest(),'big')%mod,int.from_bytes(sk[:8],'big'),mod)
def ver(vk,msg,s):
 mod,e=vk;return pow(s,e,mod)==int.from_bytes(hashlib.sha256(msg).digest(),'big')%mod
A=[[r.randrange(q) for _ in range(n)] for _ in range(d)]
for row in A:row[1]=row[0]
w1=[1,0,0,0,0,0]; w2=[0,1,0,0,0,0];t=[dot(a,w1) for a in A]
ok([dot(a,w2) for a in A]==t)
primes=[(65521,65519),(65447,65497),(65479,65449)]; data=[]
for p,h in primes:
 mod=p*h;e=65537;phi=(p-1)*(h-1);ok(math.gcd(e,phi)==1)
 sec=pow(e,-1,phi);sk=sec.to_bytes(8,'big')+bytes(r.randrange(256) for _ in range(56))
 caps=[];coins=[]
 for k in range(2):
  cc=[];rr=[]
  for bit in bits(sk):
   c,rho=enc(A,t,bit);cc.append(c);rr.append(rho)
  caps.append(cc);coins.append(rr)
 data.append((sk,(mod,e),caps,coins))
for sk,vk,caps,coins in data:
 for cc in caps:
  for w in [w1,w2]:ok(dec(w,cc)==sk)
ctx=b'claim:UTXO-21|branch:challenge|window:77..84|original:ISIS'
dig=hashlib.sha256(str([v[2] for v in data]).encode()).digest();hist=[]
for round in range(2):
 for i,(sk,vk,caps,coins) in enumerate(data):
  msg=b'P'+bytes([i,round])+ctx+dig+hashlib.sha256(str(hist[-1:]).encode()).digest()
  s=sig(sk,vk[0],msg);ok(ver(vk,msg,s));hist.append((i,msg,s))
target=int.from_bytes(dig[:2],'big')%len(data)
opened=0
for i,(sk,vk,caps,coins) in enumerate(data):
 if i==target:continue
 opened+=1
 for cap,rr in zip(caps,coins):
  for j,(ct,(s,e,z)) in enumerate(zip(cap,rr)):
   reconstructed=([(sum(A[k][l]*s[k] for k in range(d))+e[l])%q for l in range(n)],(dot(t,s)+z+g*bits(sk)[j])%q)
   ok(reconstructed==ct)
ok(opened==2)
msg=b'C'+bytes([target])+ctx+dig
sk,vk,caps,_=data[target]
for w in (w1,w2):
 secret=dec(w,caps[0]);ok(ver(vk,msg,sig(secret,vk[0],msg)))
 ok(not ver(vk,msg+b'changed',sig(secret,vk[0],msg)))
for i,(other,_,_,_) in enumerate(data):
 if i!=target:ok(not ver(vk,msg,sig(other,vk[0],msg)))
Af=[[1] for _ in range(d)];tf=[3]*d
ok(all([dot(row,[b]) for row in Af]!=tf for b in (0,1)))
false=[]
for bit in bits(sk):
 s=[r.randrange(q) for _ in Af];e=r.randint(-1,1);z=r.randint(-1,1)
 false.append(([(sum(s)+e)%q],(dot(tf,s)+z+g*bit)%q))
stolen=dec([3],false);ok(stolen==sk);ok(ver(vk,msg,sig(stolen,vk[0],msg)))
print(json.dumps({'checks':checks,'scope_keys':3,'bits_per_key':512,'legitimate_witnesses':2,'related_capsules_each':2,'opened_sibling_keys_and_coins':2,'fresh_native_challenge_verified':True,'chosen_false_nonwitness_bits_recovered':512,'signature':'toy factorable RSA, NOT post-quantum'},sort_keys=True))
