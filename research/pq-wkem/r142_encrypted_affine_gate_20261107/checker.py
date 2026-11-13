#!/usr/bin/env python3
"""Exact finite experiment for R142: encrypted public-affine polynomial coefficients.
The experiment is a one-time-pad information-theoretic control, not a QPT-LWE test.
"""
import itertools, json, hashlib
q=5
mod=lambda x:x%q
C=(1,-1,-1,1)  # (1-z0)(1-z1)
def coeff(k,a):return tuple(mod((k if i==0 else 0)+a*C[i]) for i in range(4))
def ev(poly,w):return mod(sum(p*(((w[0] if (i&1) else 1)*(w[1] if (i&2) else 1))) for i,p in enumerate(poly)))
assertions=0
witnesses=((1,0),(0,1),(1,1))
for k in range(q):
 for a in range(q):
  P=coeff(k,a)
  for w in witnesses:
   assert ev(P,w)==k;assertions+=1
  assert ev(P,(0,0))==mod(k+a);assertions+=1
# Exhaustive joint coefficient-ciphertext histograms, conditioned on every k.
# Each k has q choices of a and q^4 independent one-time pads; each ciphertext occurs q times.
counts=[[0]*(q**4) for _ in range(q)]
evcounts=[[[0]*q for _ in range(q)] for w in witnesses]
for k in range(q):
 for a in range(q):
  p=coeff(k,a)
  for pads in itertools.product(range(q), repeat=4):
   ct=tuple(mod(p[i]+pads[i]) for i in range(4))
   idx=sum(ct[i]*(q**i) for i in range(4))
   counts[k][idx]+=1
   for j,w in enumerate(witnesses):
    evcounts[j][k][ev(ct,w)]+=1
for k in range(q):
 for ct in range(q**4):
  assert counts[k][ct]==q;assertions+=1
for j in range(len(witnesses)):
 for k in range(q):
  for v in range(q):
   assert evcounts[j][k][v]==q**4;assertions+=1
for k in range(1,q):
 assert counts[0]==counts[k];assertions+=1
# For a known witness, joint pads would have to reveal an additional key-dependent opening.
# Perfect correctness without opening is impossible since ciphertext views have identical laws for all k.
report={"run":"R142-ENCRYPTED-AFFINE-QUOTIENT-WRAPPER","status":"REJECTED_NO_FOUNDATIONAL_ADVANCE","q":q,"coefficient_count":4,"witnesses":list(witnesses),"total_assertions":assertions,"ciphertext_histogram_count_per_key_per_ciphertext":q,"evaluated_ciphertext_histogram_count_per_key_per_value":q**4,"complete_joint_view_OTP_identical_for_all_keys":True,"independent_QPT_PKE_extension":"conditional multi-message IND-CPA standard hybrid; not a generic witness-KEM proof"}
print(json.dumps(report,indent=2,sort_keys=True))
