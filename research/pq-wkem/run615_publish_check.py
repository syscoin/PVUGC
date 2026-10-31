#!/usr/bin/env python3
"""Run 615: bounded metric-ball, branch-overlap and Grover oracle checks (NOT WKEM)."""
import hashlib, json, math
from itertools import combinations

def ball(d,c,t):
    return {x for x in range(1<<d) if (x^c).bit_count() <= t}

def grover(marked,d):
    n=1<<d; a=[1/math.sqrt(n)]*n
    theta=math.asin(math.sqrt(len(marked)/n))
    for j in range(8):
        success=sum(a[x]**2 for x in marked)
        assert abs(success-math.sin((2*j+1)*theta)**2)<2e-11
        for x in marked: a[x]=-a[x]
        mean=sum(a)/n; a=[2*mean-z for z in a]

fixtures=[(7,0,[0,127]),(8,1,[0,255]),(8,2,[0,255]),
          (8,2,[0,1]),(10,2,[0,1023,0b1111100000])]
checks=0; results=[]
key=b'A'*32; bad=b'B'*32
assert hashlib.sha256(key).digest()!=hashlib.sha256(bad).digest()
for d,t,centers in fixtures:
    balls=[ball(d,c,t) for c in centers]; u=set().union(*balls)
    v=sum(math.comb(d,j) for j in range(t+1))
    pack=max(len(s) for k in range(1,len(centers)+1)
             for s in combinations(centers,k)
             if all((a^b).bit_count()>2*t for a,b in combinations(s,2)))
    assert all(len(b)==v for b in balls)
    assert len(u)>=pack*v
    assert {x for x in range(1<<d)
            if hashlib.sha256(key if x in u else bad).digest()==hashlib.sha256(key).digest()}==u
    for b in balls: assert all(x in u for x in b)
    grover(u,d)
    checks+=len(u)+9
    results.append([d,t,len(centers),len(u),pack*v])
for t in (0,1,2):
    b=[ball(5,x,t) for x in range(32)]
    for a in range(32):
        for c in range(32):
            assert bool(b[a]&b[c])==((a^c).bit_count()<=2*t)
            checks+=1
assert len(ball(8,0,2)&ball(8,3,2))>0
assert len(ball(8,0,2)&ball(8,31,2))==0
print(json.dumps({'run':615,'checks':checks,'fixtures':results,
                  'branch_overlap_cases':3072,'pq_security':'NOT ESTABLISHED'},sort_keys=True))
