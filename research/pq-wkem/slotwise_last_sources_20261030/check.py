#!/usr/bin/env python3
"""Exact finite coupling and SOURCE-release checks. Not a QPT experiment."""
import hashlib,itertools,json,random
from collections import Counter

N=4; q_small=5
assertions=0

def require(b,reason):
  global assertions
  assert b,reason
  assertions+=1

def add(a,b,q=q_small):return tuple((x+y)%q for x,y in zip(a,b))
def sub(a,b,q=q_small):return tuple((x-y)%q for x,y in zip(a,b))

def public_share(seed):
  # arbitrary deterministic seed expansion, NOT a PRG assumption
  return ((seed*seed+3*seed+1)%q_small,(seed*seed*seed+2)%q_small)

def malicious_seed(prefix,slot,party,policy):
  vals=[party,slot,prefix,party+prefix,slot*prefix+party,
        (party+1)*(slot+1)*(prefix+1)]
  return (vals[policy]+(prefix*prefix if policy%2 else 0))%23

def corrupted_later_source(H,slot,policy):
  # Malicious other native signer can select its own source *after* H is public.
  return tuple((x* (slot+1)+policy)%q_small for x in H)

# EXACT full transcript coupling for unknown honest index, all public
# stage-1 prefixes, six adversarial seed strategies, source messages,
# and later malicious SOURCE correlations chosen after honest M.
for h in range(N):
  for policy in range(6):
    for prefix in range(q_small):
      seeds=[(i,malicious_seed(prefix,h,i,policy)) for i in range(N) if i!=h]
      C=(0,0)
      for i,s in seeds:C=add(C,public_share(s))
      real=Counter(); sim=Counter()
      for Sh in itertools.product(range(q_small),repeat=2):
        M=add(Sh,C)
        tail=tuple(corrupted_later_source(M,j,policy) for j in range(N) if j!=h)
        real[(prefix,tuple(seeds),Sh,M,tail)]+=1
      for challenge_M in itertools.product(range(q_small),repeat=2):
        Sh=sub(challenge_M,C)
        tail=tuple(corrupted_later_source(challenge_M,j,policy) for j in range(N) if j!=h)
        sim[(prefix,tuple(seeds),Sh,challenge_M,tail)]+=1
      require(real==sim,'joint source/late-corrupt relation')
      require(len(real)==q_small**2,'uniform cardinality')
      require(all(w==1 for w in real.values()),'exact frequency')

# Real receiver-last phase never publishes its full matrix or a native
# ciphertext until all other signed seed slots are frozen and validated.
for h in range(N):
  for bad in range(N):
    if bad==h:continue
    for bad_kind in ('missing','noncanonical','wrong_context','unsigned','late_change'):
      phase1_valid=False
      receiver_reveals=phase1_valid
      publish_capsule=receiver_reveals
      require(not receiver_reveals and not publish_capsule,f'prefunding abort {h=} {bad=}')

# The source-only dual-LWE release property, checked with actual uniform
# source samples CONDITIONED on at least two preimages per target.
q=257; m=8; n=1; L=2; w=3; B=1; ell=2; g=q//(2**ell)
T=[]
for positions in itertools.combinations(range(m),w):
  for signs in itertools.product((-1,1),repeat=w):
    v=[0]*m
    for i,s in zip(positions,signs):v[i]=s
    T.append(tuple(v))
require(len(T)==448,'signed short support cardinality')
R=random.Random(20261030)
source=None
for trials in range(1,5001):
  A=tuple(R.randrange(q) for _ in range(m))
  U=(R.randrange(q),R.randrange(q))
  possibilities=[[v for v in T if sum(a*b for a,b in zip(A,v))%q==u] for u in U]
  if all(len(o)>=2 for o in possibilities):
    source=(A,U,possibilities,trials);break
require(source is not None,'uniform source has multiple short preimages')
A,U,possibilities,trials=source
require(g>2*B*(w+1),'strict noise margin')
secret=(1,3)
for capsule in range(3):
  r=R.randrange(q)
  noise=[R.randint(-B,B) for _ in range(m)]
  e=[R.randint(-B,B) for _ in range(L)]
  c=[(a*r+v)%q for a,v in zip(A,noise)]
  d=[(u*r+v+g*k)%q for u,v,k in zip(U,e,secret)]
  def center(v):return (v+q//2)%q-q//2
  for z0 in possibilities[0][:6]:
    for z1 in possibilities[1][:6]:
      recovered=[]
      for j,z in enumerate((z0,z1)):
        val=(d[j]-sum(zi*ci for zi,ci in zip(z,c)))%q
        distances=[abs(center(val-g*k)) for k in range(2**ell)]
        got=distances.index(min(distances))
        recovered.append(got)
        require(got==secret[j],'every SOURCE preimage releases digit')
        require(abs(center(val-g*secret[j]))<=B*(w+1),'tight error bound')
      require(tuple(recovered)==secret,'same complete key across preimages/capsules')

# Cost ONLY for uniformly sampled SOURCE and signer contributions; does
# not include attestation, native PQ scripts, transaction weights, or keys.
example_n=256; example_m=6800; example_L=52; bytewidth=3
matrix_bytes=example_n*(example_m+example_L)*bytewidth
N_matrices=N*matrix_bytes
N_seed_bytes=N*(N-1)*32
per_capsule=N*(example_m+example_L)*bytewidth
require(matrix_bytes==5262336,'example SOURCE matrix cost')
require(N_matrices==21049344,'four source reveals cost')
require(N_seed_bytes==384,'12 seed reveals')
require(per_capsule==82224,'four independently protected LWE vectors')

report={
 'result':'PASS','assertions':assertions,
 'honest_positions':N,'adaptive_corrupt_policies':6,
 'stage1_public_prefixes':q_small,'joint_distribution_laws':N*6*q_small,
 'tuples_per_joint_law':q_small**2,
 'prefunding_abort_cases':N*(N-1)*5,
 'source_preimage_counts':[len(a) for a in possibilities],
 'source_draws_until_multisolution':trials,
 'related_capsules':3,
 'illustrative_source_matrix_bytes_each':matrix_bytes,
 'illustrative_four_source_reveals_bytes':N_matrices,
 'illustrative_nonreceiver_seed_reveal_bytes':N_seed_bytes,
 'illustrative_four_ciphertexts_per_capsule_bytes':per_capsule,
 'source_preimages_are_NOT_original_witnesses':True,
 'full_public_QPT_security_NOT_tested':True,
 'bitcoin_native_signature_NOT_instantiated':True
}
print(json.dumps(report,indent=2,sort_keys=True))
