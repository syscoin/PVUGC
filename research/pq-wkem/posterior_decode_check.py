#!/usr/bin/env python3
"""Exact small checks for POSTERIOR_CLEANUP_BOUNDARY.md.

NOT a KEM, NOT a generic compiler, NOT a scalable posterior sampler.
Standard library only. Finite probabilities and code bounds are exact fractions.
The full statevector suite and isolated consumer are in the conversation archive.
"""
from collections import defaultdict
from fractions import Fraction as F
from itertools import product
from math import comb
import json


def tail(n, start, p):
    return sum((F(comb(n,k))*p**k*(1-p)**(n-k)
                for k in range(start,n+1)), F(0))


def code_failure(p, repetitions):
    bit=tail(repetitions,(repetitions+1)//2,p)
    return tail(128,49,min(F(1),8*bit))


def character_norm_squared(probabilities):
    # Exact for the three cube roots of unity.
    assert sum(probabilities)==1
    return (3*sum(x*x for x in probabilities)-1)/2


def check():
    count={'posterior_law_coordinates':0,'preimage_signal_bounds':0,
           'code_bounds':0}
    single=(F(1,2),F(1,4),F(1,4))
    noise={e:single[e[0]]*single[e[1]] for e in product(range(3),repeat=2)}
    cosines=(F(1),F(-1,2),F(-1,2))
    nu=tuple((1+x)/3 for x in cosines)
    for V in ((1,2),(1,0),(0,0)):
        p=defaultdict(F)
        joint=defaultdict(F)
        for r in range(3):
            for e,pe in noise.items():
                c=tuple((V[j]*r+e[j])%3 for j in range(2))
                p[c]+=pe/3
                joint[(c,r)]+=pe/3
        assert sum(p.values())==1
        post={c:tuple(joint[(c,r)]/pc for r in range(3)) for c,pc in p.items()}
        for y in range(3):
            target={}
            for c,row in post.items():
                t=[F(0)]*3
                for r,pr in enumerate(row):t[y*r%3]+=pr
                target[c]=tuple(t)
            J=sum(p[c]*character_norm_squared(t) for c,t in target.items())
            assert 0<=J<=1
            diff=[F(0)]*3
            for c,row in target.items():
                for a,pa in enumerate(row):
                    for b,pb in enumerate(row):diff[(a-b)%3]+=p[c]*pa*pb
            assert sum(diff)==1
            for bit in (0,1):
                law=[F(0)]*3
                for h,ph in enumerate(diff):
                    for v,pv in enumerate(nu):law[(h+v+bit)%3]+=ph*pv
                for u,value in enumerate(law):
                    assert value==(1+J*cosines[(u-bit)%3])/3
                    count['posterior_law_coordinates']+=1
            for z in product(range(3),repeat=2):
                if sum(V[i]*z[i] for i in range(2))%3!=y:continue
                rho=F(1)
                for zi in z:rho*=1 if zi==0 else F(1,4)
                assert J>=rho*rho
                count['preimage_signal_bounds']+=1
    gamma=F(19,20)
    beta_lower=F(7,11)-F(11,7*31**2)
    crossover=(1-beta_lower*gamma**2)/2
    assert crossover<F(43,200)
    assert crossover+F(1,200)<F(11,50)
    for p,R,bits in ((F(43,200),17,122),(F(43,200),25,241),
                     (F(11,50),17,111),(F(11,50),25,225)):
        assert code_failure(p,R)<F(1,2**bits)
        count['code_bounds']+=1
    return {'status':'PASS: scoped identities only; no completed WKEM',
            'counts':count,
            'scope':'Exact enumeration at q=3; posterior method is exponential. '
                    'Whole-code bounds assume the hypothetical posterior sampler.'}


if __name__=='__main__':
    print(json.dumps(check(),indent=2))
