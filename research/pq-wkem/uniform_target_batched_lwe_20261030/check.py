#!/usr/bin/env python3
"""Uniform-target batched dual-LWE SOURCE algebra and counting checker.
The exact exhaustive SOURCE-opening enumerator is TEST-ONLY, not real Setup.
No actual QPT/security/native PQ/Bitcoin testing is attempted.
"""
import itertools,math,random,hashlib,json
from collections import defaultdict
rng=random.Random(2026103009)
checks=0

def ck(cond,msg):
 global checks
 checks+=1
 if not cond:raise AssertionError(msg)

def signed_weight(m,w):
 for inds in itertools.combinations(range(m),w):
  for signs in itertools.product((-1,1),repeat=w):
   z=[0]*m
   for pos,val in zip(inds,signs):z[pos]=val
   yield tuple(z)

def sample_source(n,m,L,q):
 # Honest setup samples uniform A and uniform U, never samples or retains preimages.
 A=[[rng.randrange(q) for j in range(m)] for i in range(n)]
 U=[[rng.randrange(q) for j in range(L)] for i in range(n)]
 return A,U

def valid(A,U,z,l,q):
 return all(sum(A[i][j]*z[j] for j in range(len(z)))%q==U[i][l] for i in range(len(A)))

def encrypt(A,U,digits,q,B,ell):
 n=len(A);m=len(A[0]);L=len(digits)
 r=[rng.randrange(q) for i in range(n)]
 eta=[rng.randint(-B,B) for i in range(m+L)]
 c=[(sum(A[i][j]*r[i] for i in range(n))+eta[j])%q for j in range(m)]
 g=q//(1<<ell)
 d=[(sum(U[i][l]*r[i] for i in range(n))+eta[m+l]+g*digits[l])%q for l in range(L)]
 return (c,d),eta

def decrypt_one(ct,z,l,q,ell):
 c,d=ct;g=q//(1<<ell)
 residual=(d[l]-sum(a*b for a,b in zip(c,z)))%q
 dist=lambda t:min(t%q,(-t)%q)
 return min(range(1<<ell),key=lambda a:dist(residual-g*a))

def trial_division_prime(a):
 if a<2:return False
 for k in range(2,math.isqrt(a)+1):
  if a%k==0:return False
 return True

# Check exact first and second moment for every A,u in small field.
Q0,M0,W0=5,3,2
T=list(signed_weight(M0,W0)); X=[]
for avec in itertools.product(range(Q0),repeat=M0):
 for u in range(Q0):
  X.append(sum(sum(a*z for a,z in zip(avec,t))%Q0==u for t in T))
mu=len(T)/Q0
variance=sum((v-mu)**2 for v in X)/len(X)
ck(len(X)==625,'exhaustive 5^(3+1)')
ck(abs(sum(X)/len(X)-mu)<1e-12,'exact expectation')
ck(abs(variance-len(T)*(1/Q0)*(1-1/Q0))<1e-12,'exact pairwise variance')
ck(sum(v==0 for v in X)/len(X)<=Q0/len(T),'availability bound')

# Toy multi-target SOURCE: actual Setup samples only uniform A,U. Openings enumerated in test.
q,n,m,w,B,ell,L,J=127,2,14,6,1,3,86,2
ck(q//(1<<ell)>2*(w+1)*B,'strict any-opening correctness')
A,U=sample_source(n,m,L,q)
# Exhaustive test-only enumeration, not the setup distribution or a real release algorithm.
pre=defaultdict(list)
for z in signed_weight(m,w):
 target=tuple(sum(A[i][k]*z[k] for k in range(m))%q for i in range(n))
 pre[target].append(z)
by_digit=[pre[tuple(U[i][l] for i in range(n))] for l in range(L)]
ck(all(len(zs)>=2 for zs in by_digit),'fixed uniform source has >=2 distinct SOURCE preimages for each target')
ck(all(valid(A,U,by_digit[l][0],l,q) and valid(A,U,by_digit[l][1],l,q) for l in range(L)),'separate target openings valid')
secret=rng.getrandbits(256)
pk=hashlib.sha256(secret.to_bytes(32,'big')).hexdigest()
digits=[(secret>>(ell*l))&((1<<ell)-1) for l in range(L)]
for capsule in range(J):
 ct,eta=encrypt(A,U,digits,q,B,ell)
 ck(len(ct[0])+len(ct[1])==m+L,'one vector ciphertext, not L vectors')
 ck(all(-B<=x<=B for x in eta),'bounded errors')
 for variant in range(8):
  zs=[by_digit[l][variant%len(by_digit[l])] for l in range(L)]
  rec=[decrypt_one(ct,z,l,q,ell) for l,z in enumerate(zs)]
  key=sum(a<<(ell*l) for l,a in enumerate(rec))
  ck(key==secret,'all distinct witnesses get same precommitted key')
  ck(hashlib.sha256(key.to_bytes(32,'big')).hexdigest()==pk,'native key binding mock')
# Malicious contributor source b_i=0 and known opening 0 doesn't open honest random U.
ck(any(U[i][l]!=0 for i in range(n) for l in range(L)),'honest target not zero')
ck(not all(valid(A,U,(0,)*m,l,q) for l in range(L)),'known corrupt opening fails for honest source')

# Fixed FALSE uniform-source-theorem exclusion: A=I, U=0, weight=1 is FALSE,
# but d_j=e_j+g*a_j reveals the plaintext. No all-fixed-source hiding claim.
Af=[[1,0],[0,1]];Uf=[[0],[0]]
ck(not any(valid(Af,Uf,z,0,q) for z in signed_weight(2,1)),'fixed FALSE SOURCE')
for digit in range(8):
 ciph,_=encrypt(Af,Uf,[digit],q,B,ell)
 noisy=ciph[1][0]; g=q//(1<<ell)
 ck(min(range(8),key=lambda a:min((noisy-g*a)%q,(g*a-noisy)%q))==digit,'fixed FALSE last coordinate leaks')

# Exact illustrative arithmetic only (not QPT parameter certification).
Q,N,M,W,BIG_B,ELL,KEY_BITS=16777213,256,6800,2000,128,5,256
LL=(KEY_BITS+ELL-1)//ELL
logT=(math.lgamma(M+1)-math.lgamma(W+1)-math.lgamma(M-W+1))/math.log(2)+W
log_mu=logT-N*math.log2(Q)
ck(trial_division_prime(Q),'q prime by deterministic trial division')
ck(Q//(1<<ELL)>2*BIG_B*(W+1),'large deterministic noise margin')
ck(log_mu>1700,'large uniform target short-preimage availability')
old=LL*(M+1)*3;new=(M+LL)*3
ck(new<old,'strict public ciphertext reduction')
print(json.dumps(dict(status='PASS',assertions=checks,candidate='uniform-target batched dual LWE',toy_exhaustive_sources=len(X),toy_mean=mu,toy_variance=variance,toy_source_absence=sum(v==0 for v in X),toy_target_preimages_min=min(map(len,by_digit)),toy_target_preimages_max=max(map(len,by_digit)),toy_targets=L,toy_related_capsules=J,different_source_witness_vectors_per_capsule=8,toy_native_key_bits=256,malicious_known_opening_does_not_transfer=True,fixed_false_source_leak=True,large_log2_expected_preimages_per_target=round(log_mu,3),large_log2_all_targets_failure_upper_bound=round(math.log2(LL)-log_mu,3),single_target_ciphertext_bytes=old,batched_ciphertext_bytes=new,batched_source_bytes=N*(M+LL)*3,assurance='bounded algebra and moments only; QPT LWE and actual native signature security untested; ORIGINAL Lift absent'),sort_keys=True))
