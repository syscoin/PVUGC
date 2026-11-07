#!/usr/bin/env python3
# Run 366, exact reproducible finite Simon-interference and classical-bound checks.
from itertools import combinations
from math import comb
import json

checks=0
for n in range(2,9):
    N=1<<n
    periods=range(1,N) if n<=4 else (1,N//3,N-1)
    for s in periods:
        roots={min(x,x^s) for x in range(N)}
        assert len(roots)==N//2
        for y in range(N):
            numerator=sum(((-1)**((x&y).bit_count()&1)+
                           (-1)**(((x^s)&y).bit_count()&1))**2 for x in roots)
            assert numerator==(2*N if ((s&y).bit_count()&1)==0 else 0)
            checks+=1
for n in (3,4):
    N=1<<n
    for q in range(1,5):
        for Q in combinations(range(N),q):
            D={a^b for a,b in combinations(Q,2)}
            assert len(D)<=comb(q,2)
            assert min(1,(len(D)+1)/(N-1))<=min(1,(comb(q,2)+1)/(N-1))
            checks+=1
print(json.dumps({'run':366,'status':'PASS','checks':checks,
                  'scope':'finite oracle identities, not a QPT security proof'},sort_keys=True))
