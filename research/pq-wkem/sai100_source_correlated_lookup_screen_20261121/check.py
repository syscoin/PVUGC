#!/usr/bin/env python3
"""Exact combinatorial check for explicitly restricted independent lookup-pad family.
This is NOT FE, not the ORIGINAL source predicate, and not a QPT proof.
"""
from fractions import Fraction
from math import comb
import json

def exact_nohit(N,B,q):
    # q distinct samples without replacement and B independently fixed hidden positions
    return Fraction(comb(N-B,q), comb(N,q))

rows=[]
for n,B,q in [(8,2,3),(10,8,4),(12,8,4),(14,16,8)]:
    N=1<<n
    direct=exact_nohit(N,B,q)
    union=Fraction(B*q,N)
    assert 1-direct<=union
    # exact census in a smaller domain for two independent sample points
    if n==8:
        hidden={0,37}
        count=0
        hit=0
        for a in range(N):
            for b in range(a+1,N):
                count+=1
                hit+=int(a in hidden or b in hidden)
        assert Fraction(hit,count)==1-exact_nohit(N,2,2)
    rows.append({'domain_bits':n,'hidden_points':B,'witness_queries':q,
        'exact_hit_probability':str(1-direct),'union_bound':str(union),
        'hit_decimal':round(float(1-direct),9)})
print(json.dumps({'model':'classical independent hidden-point lookup only; not universal hash-only WE',
  'checks':rows,'small_domain_census_pass':True},indent=2,sort_keys=True))
