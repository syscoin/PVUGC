#!/usr/bin/env python3
# Deterministic bounded check. Python 3 standard library; no network.
import itertools, json, random
q,h,g=257,8,19
T=q//g
check_count=0
def ck(p):
 global check_count
 assert p
 check_count+=1
B=[sum(1<<i for i in S) for d in range(4) for S in itertools.combinations(range(3),d)]
def multiply(a,b):
 c={}
 for x,u in a.items():
  for y,v in b.items(): c[x|y]=c.get(x|y,0)+u*v
 return {k:v for k,v in c.items() if v}
def violated(lits):
 p={0:1}
 for i,positive in lits: p=multiply(p,{0:1,1<<i:-1} if positive else {1<<i:1})
 return p
def compiler(clauses):
 rows=[]
 for literals in clauses:
  p=violated(literals)
  deg=max(x.bit_count() for x in p)
  for u in B:
   if u.bit_count()+deg>3: continue
   f=multiply(p,{u:1})
   rows.append([f.get(m,0)%q for m in B])
 rows.append([int(m==0) for m in B])
 return rows,[0]*(len(rows)-1)+[1]
def vector(bits): return [int(all(bits[i] for i in range(3) if m>>i&1)) for m in B]
def apply(A,v): return [sum(x*y for x,y in zip(row,v))%q for row in A]
def source_coin(A,U,a,rng):
 s=[rng.randrange(q) for _ in A];e=[rng.choice((-1,0,1)) for _ in B];eps=rng.choice((-1,0,1))
 c=[(sum(A[j][i]*s[j] for j in range(len(A)))+e[i])%q for i in range(len(B))]
 d=(sum(U[j]*s[j] for j in range(len(A)))+eps+g*a)%q
 return (c,d),(s,e,eps)
def decode(ct,w):
 c,d=ct;v=(d-sum(x*y for x,y in zip(w,c)))%q
 opts=[a for a in range(T) if min((v-g*a)%q,(g*a-v)%q)<=h+1]
 ck(len(opts)==1)
 return opts[0]
def digits(x):
 out=[]
 while x:out.append(x%T);x//=T
 return out or [0]
def undigits(ds):
 x=0
 for d in ds[::-1]:x=x*T+d
 return x
true=[[(0,True),(1,True),(2,True)]]
false=[[(0,False)],[(0,True),(1,False)],[(1,True)]]
A,U=compiler(true);AF,UF=compiler(false)
valid=[]
for bits in itertools.product((0,1),repeat=3):
 w=vector(bits)
 ck((apply(A,w)==U)==bool(any(bits)))
 ck(apply(AF,w)!=UF)
 if any(bits):valid.append(w)
ck(len(valid)==7)
z=[0]*len(AF)
# For violated clauses x, (1-x)y, (1-y): y*x+(1-x)*y+(1-y)=1.
z[2]=z[7]=z[11]=q-1;z[-1]=1
ck(all(sum(z[j]*AF[j][i] for j in range(len(AF)))%q==0 for i in range(len(B))))
ck(sum(z[j]*UF[j] for j in range(len(AF)))%q==1)
rng=random.Random(20261029043952)
for trial in range(4):
 K=rng.getrandbits(256)
 Z=[rng.getrandbits(256) for _ in range(3)]
 M=K^Z[0]^Z[1]^Z[2]
 ct=[[source_coin(A,U,a,rng)[0] for a in digits(s)] for s in Z]
 for w in valid:
  recovered=M
  for entries in ct: recovered^=undigits([decode(entry,w) for entry in entries])
  ck(recovered==K)
for trial in range(4):
 a=rng.randrange(T)
 (c,d),(s,e,eps)=source_coin(AF,UF,a,rng)
 observed=set()
 for lam in range(q):
  ss=[(u+lam*v)%q for u,v in zip(s,z)]
  cc=[(sum(AF[j][i]*ss[j] for j in range(len(AF)))+e[i])%q for i in range(len(B))]
  dd=(sum(UF[j]*ss[j] for j in range(len(AF)))+eps+g*a)%q
  ck(cc==c);ck(dd==(d+lam)%q)
  observed.add(dd)
 ck(len(observed)==q)
print(json.dumps({'status':'PASS','assertions':check_count,'q':q,'degree':3,'matrix_true':[len(A),len(B)],'matrix_false':[len(AF),len(B)],'true_distinct_witnesses':7,'whole_key_trials':4,'false_exact_uniform_orbits':4,'false_kernel_certificate':z,'native_key':'mock integer, no SLH implementation','generic_NP_solution':False},sort_keys=True,indent=2))
