#!/usr/bin/env python3
"""R31 bounded exact checker. Pure Python standard library; no network.
     This proves finite linear identities only, never QPT hardness.
"""
from itertools import product
import json
q=7
B=(1,1,0); e0=(1,0,0); ell=(1,-1,0)
H=((1,-1,0),(0,0,1)); Delta=3
checks=0

def assert_(flag,why):
    global checks
    checks+=1
    if not flag: raise AssertionError(why)

def dot(x,y):return sum(a*b for a,b in zip(x,y))%q

def add(*vs):return tuple(sum(v[i] for v in vs)%q for i in range(3))

def smul(a,v):return tuple((a*x)%q for x in v)

def project(v):return tuple(dot(h,v) for h in H)

assert_(dot(ell,B)==0,'original witness annihilator')
assert_(dot(ell,e0)==1,'correct signal evaluation')
assert_(project(e0)!=(0,0),'signal survives public quotient')

# Version 1: directly place a uniformly random LWE column into the source.
# For fixed s=1, epsilon=0, mu=1, a genuine witness decrypts exactly
# when ell*A=0, which holds with probability exactly 1/q.
A_space=list(product(range(q),repeat=3))
exact=0
for A in A_space:
    c=add(A,smul(Delta,e0))
    if dot(ell,c)==Delta:exact+=1
    assert_(dot(ell,c)==(dot(ell,A)+Delta)%q,'direct LWE witness equation')
assert_(exact==q*q,'uniform direct challenge succeeds with 1/q')

# Version 2: make every LWE challenge column lie in image(B).
A_supported=[A for A in A_space if project(A)==(0,0)]
assert_(len(A_supported)==q,'projected challenge column size')
assert_(set(A_supported)=={smul(u,B) for u in range(q)},'supported columns exactly span B')

# Actual affine public capsule with independent small coefficient noise.
# H strips every B*r and B*u*s term: the LWE contribution is EXACTLY absent
# from the public syndrome for every r,u,s,e,mu.
noise=list(product((-1,0,1),repeat=3))
for r,u,s,ep,mu in product(range(q),range(q),range(q),noise,(0,1)):
    c=add(smul(r,B),smul(u*s,B),ep,smul(Delta*mu,e0))
    expected=project(add(ep,smul(Delta*mu,e0)))
    assert_(project(c)==expected,'all LWE masks cancel from full public syndrome')
    assert_(dot(ell,c)==(Delta*mu+dot(ell,ep))%q,'witness exact evaluation')

# If all error lives in image(B), the syndrome is a directly readable key bit.
for u,s,r,mu in product(range(q),range(q),range(q),(0,1)):
    c=add(smul(r,B),smul(u*s,B),smul(1,B),smul(Delta*mu,e0))
    assert_(project(c)==smul(Delta*mu,project(e0))[:2], 'signal public without quotient noise')

# A constrained uniform challenge has TV 1-q^(-(m-r)*n) from standard uniform A.
# Here n=1, m=3, r=1; count the exact event H A=0.
assert_(len(A_supported)/len(A_space)==1/q**2,'density of supported columns')

out={
  'run':'R31-MINK-LWE-JOINT', 'q':q, 'm':3, 'rank_B':1,
  'uniform_A_total':len(A_space),'correct_exact':exact,
  'correct_fraction':f'{exact}/{len(A_space)}',
  'supported_A':len(A_supported),
  'statistical_distance_uniform_to_supported':f'{q*q-1}/{q*q}',
  'checks':checks,
  'status':'PASS algebra only; no generic PQ WKEM security proved'
}
print(json.dumps(out,sort_keys=True,indent=2))
