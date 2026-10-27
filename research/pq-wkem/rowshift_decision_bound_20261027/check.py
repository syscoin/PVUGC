#!/usr/bin/env python3
"""Offline finite-field row-shift experiment for degree-four parity moment source.
No third-party dependencies, no network, no QPT security assertion.
"""
import itertools,json,random

q=101
S=(7,25,42,52)
true_signs=(1,1,1,1)
false_signs=(1,1,1,-1)
masks=tuple(t for t in range(64) if t.bit_count()<=4)
index={v:i for i,v in enumerate(masks)}
checks=0

def check(cond,msg):
 global checks
 checks+=1
 if not cond: raise AssertionError(msg)

def build(signs):
 rows=[]; lookup={}
 for j,s in enumerate(S):
  for t in masks:
   p=s^t
   if p not in index: continue
   rr={index[p]:1,index[t]:-signs[j]}
   if index[p]==index[t]:
    rr={index[p]:1-signs[j]}
   lookup[j,t]=len(rows)
   rows.append([rr.get(i,0)%q for i in range(len(masks))])
 return rows,lookup

def rank_field(A):
 a=[r[:] for r in A];ncol=len(a[0]);rank=0
 for j in range(ncol):
  pivot=next((i for i in range(rank,len(a)) if a[i][j]),None)
  if pivot is None: continue
  a[rank],a[pivot]=a[pivot],a[rank]
  fac=pow(a[rank][j],-1,q)
  a[rank]=[(v*fac)%q for v in a[rank]]
  for i in range(rank+1,len(a)):
   if a[i][j]:
    fac=a[i][j]
    a[i]=[(x-fac*y)%q for x,y in zip(a[i],a[rank])]
  rank+=1
  if rank==len(a):break
 return rank

def matmulT(rows,coeff):
 z=[0]*len(masks)
 for c,r in zip(coeff,rows):
  for i,v in enumerate(r):z[i]=(z[i]+c*v)%q
 return z

Rtrue,_=build(true_signs)
Rfalse,lookup=build(false_signs)
check(len(masks)==57 and len(Rtrue)==len(Rfalse)==200,'moment dimensions')
anchor=[0]*len(masks);anchor[index[0]]=1
rtr=rank_field(Rtrue);rfa=rank_field(Rfalse)
check(rank_field(Rtrue+[anchor])==rtr+1,'true anchor outside row span')
check(rank_field(Rfalse+[anchor])==rfa,'false anchor inside row span')

# Explicit sparse row certificate 2e_anchor (over integers, verified mod q).
cert=[0]*len(Rfalse)
for (j,t,c) in ((0,S[1],-1),(1,0,-1),(2,S[3],1),(3,0,1)):
 cert[lookup[j,t]]=c
lift=matmulT(Rfalse,cert)
check(lift==[(2*x)%q for x in anchor],'sparse certificate 2e')

# Every ORIGINAL true witness yields an opening with normalized anchor.
def chi(w,mask):return -1 if (w&mask).bit_count()%2 else 1
valid=[w for w in range(64) if all(chi(w,s)==b for s,b in zip(S,true_signs))]
check(len(valid)==8,'8 true ORIGINAL witnesses')
for w in valid:
 z=[chi(w,t)%q for t in masks]
 check(z[0]==1,'true anchor one')
 for row in Rtrue:check(sum(a*b for a,b in zip(row,z))%q==0,'all true source equations')
check(not any(all(chi(w,s)==b for s,b in zip(S,false_signs)) for w in range(64)),'false original has no witness')
# Exhaust all parity-sign right-hand sides in this four-equation family.
family=[]
for bs in itertools.product((-1,1),repeat=4):
 M,_=build(bs)
 c=sum(all(chi(w,s)==b for s,b in zip(S,bs)) for w in range(64))
 in_span=rank_field(M+[anchor])==rank_field(M)
 check((c==0)==in_span,'public row-span decides XOR-SAT family')
 check((c==0) if (bs[0]*bs[1]*bs[2]*bs[3]<0) else (c==8),'parity consistency')
 family.append((bs,c,in_span))

# Finite-field exact full-ciphertext coupling. This is only a restricted false instance.
# Let p_t=M^T u+e+g*t*e_anchor. For any t, u' = u+t*g/2*cert
# gives M^T u'+e=p_t, so no observer can distinguish any t, even given pk(K).
rng=random.Random(0x20261027)
g=13
inv2=pow(2,-1,q)
for rep in range(120):
 u=[rng.randrange(q) for _ in Rfalse]
 err=[rng.randrange(-2,3)%q for _ in masks]
 t=rng.randrange(q)
 c=(g*t*inv2)%q
 shifted=[(ui+c*ci)%q for ui,ci in zip(u,cert)]
 real=[(a+b+g*t*an)%q for a,b,an in zip(matmulT(Rfalse,u),err,anchor)]
 null=[(a+b)%q for a,b in zip(matmulT(Rfalse,shifted),err)]
 check(real==null,'exact coupled public transcript')

# No simultaneous polynomial-size exact row-span/null-coupling compiler for *all* 3SAT
# unless SAT is in P. The assertion below tests only the example, not that theorem.
result={
 'status':'NECESSARY_CONDITION_NOT_WKEM_ADVANCE',
 'modulus':q,'moments':len(masks),'rows_per_source':len(Rtrue),
 'row_rank_true':rtr,'row_rank_false':rfa,
 'target_anchor_in_rowspan_true':False,'target_anchor_in_rowspan_false':True,
 'valid_original_true_witnesses':len(valid), 'valid_original_false_witnesses':0,
 'explicit_sparse_certificate':'M_false^T cert = 2 e_anchor',
 'exact_false_source_coupling_trials':120, 'exhausted_parity_sign_systems':len(family),
 'assertions':checks,
 'random_seed':0x20261027,
 'qpt_security':'NOT ESTABLISHED',
 'full_original_witness_recovery_reduction':'NOT ESTABLISHED',
 'standard_lwe_full_joint_simulator':'NOT ESTABLISHED',
 'proof_obligation':'Source-dependent full-public QPT security without efficiently decidable exact row-span condition'
}
print(json.dumps(result,sort_keys=True,indent=2))
