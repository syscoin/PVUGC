#!/usr/bin/env python3
"""Toy private-generator global-BP gate: NOT an ORIGINAL witness-KEM."""
import random, json, hashlib
P=101
I=((1,0),(0,1))
def add(u,v): return (u+v)%P
def mul(A,B):
  return tuple(tuple(sum(A[i][k]*B[k][j] for k in range(2))%P for j in range(2)) for i in range(2))
def inv(A):
  a,b=A[0];c,d=A[1];det=(a*d-b*c)%P
  if not det: raise ValueError('singular')
  s=pow(det,-1,P)
  return ((d*s%P,-b*s%P),(-c*s%P,a*s%P))
def product(xs):
  r=I
  for x in xs:r=mul(r,x)
  return r
def sample(rng):
  while True:
    A=tuple(tuple(rng.randrange(P) for _ in range(2)) for _ in range(2))
    try: inv(A);return A
    except ValueError: pass
def ser(A):return bytes(x for row in A for x in row)
def xor(a,b):return bytes(x^y for x,y in zip(a,b))
def h(A):return hashlib.sha256(b'PRIVATE-GENERATOR-BP-TARGET-V1'+ser(A)).digest()
def one(seed):
  rng=random.Random(seed)
  a,b=sample(rng),sample(rng)
  ain,binv=inv(a),inv(b)
  comm=product([a,b,ain,binv]);assert comm!=I
  layers=((I,a),(b,I),(I,ain),(binv,I))
  # independently secret endpoint and intermediate gauges
  p=[sample(rng) for _ in range(5)]
  public=[]
  for i,(zero,one) in enumerate(layers):
    public.append((mul(mul(inv(p[i]),zero),p[i+1]),mul(mul(inv(p[i]),one),p[i+1])))
  target=mul(mul(inv(p[0]),comm),p[4]);s=bytes(rng.randrange(256) for _ in range(32));ct=xor(s,h(target))
  def eval_public(z):return product(public[i][v] for i,v in enumerate(z))
  legal0=eval_public((0,0,0,0)); legal1=eval_public((1,1,1,1))
  assert legal0==legal1==mul(inv(p[0]),p[4])
  forged=eval_public((1,0,1,0));assert forged==target
  recovered=xor(ct,h(forged));assert recovered==s
  # Plaintext baseline polynomial source relation is unsatisfiable, not a real source.
  assert all(eval_public((v,)*4)!=target for v in (0,1))
  # Two distinct private generators show the public clear-generator input was removed.
  return {'seed':seed,'private_a_trace':sum((a[0][0],a[1][1]))%P,'private_b_trace':sum((b[0][0],b[1][1]))%P,'commutator_trace':sum((comm[0][0],comm[1][1]))%P,'valid_words_hit_target':False,'invalid_word_1010_hits_target':True,'public_recovery_without_valid_witness':recovered==s,'unpublished_generator_sha256':hashlib.sha256(ser(a)+ser(b)).hexdigest(),'capsule_sha256':hashlib.sha256(b''.join(ser(x) for row in public for x in row)+ct).hexdigest()}
if __name__=='__main__':
 out={'scope':'two-generator private-global-BP FALSE fixture, not original authenticated source','field':P,'samples':[one(s) for s in (20261118,20261119,20261120)]}
 print(json.dumps(out,sort_keys=True,indent=2))
