"""Run 652: bent seams, exact public-oracle law, related-view cancellation.
Finite algebra only; does not establish practical cryptographic security.
"""
from collections import Counter
from itertools import permutations
from math import factorial
import json

checks=0

def test(ok):
    global checks
    checks+=1
    assert ok

def g(v,b):
    m=b//2
    return ((v&((1<<m)-1))&(v>>m)).bit_count()%2

def q(v,k,b):
    p=(k&-k).bit_length()-1
    out=j=0
    for i in range(b):
        if i!=p:
            out|=(((v>>i)&1)^(((k>>i)&1)&((v>>p)&1)))<<j
            j+=1
    return out

def profile(b,fn,k):
    counts=Counter()
    for v in range(1<<b):
        a,z=fn(v),fn(v^k)
        counts[tuple(sorted((a,z)))]+=1
    test(all(c%2==0 for c in counts.values()))
    return tuple(sorted((t,c//2) for t,c in counts.items()))

def full(b,fn):
    n=1<<b; h={}
    for k in range(1,n):
        hist=Counter()
        for T in permutations(range(n)):
            lbl=tuple(fn(T[s]) for s in range(n))
            raw=[q(T[s],k,b) for s in range(n)]
            for P in permutations(range(n//2)):
                F=tuple(P[y] for y in raw)
                hist[(F,lbl)]+=1
        test(sum(hist.values())==factorial(n)*factorial(n//2))
        h[k]=hist
    return h

def main():
    profiles=[]
    for b in (2,4,6,8,10):
        n=1<<b
        for addbit in (0,1):
            fn=lambda v,b=b,addbit=addbit:g(v,b)^(addbit&(v&1))
            ps={profile(b,fn,k) for k in range(1,n)}
            test(len(ps)==1)
            for k in range(1,n):
                test(sum(fn(v)^fn(v^k) for v in range(n))==n//2)
        for k in range(1,n):
            for v in range(n):
                test((g(v,b)^(g(v,b)^(v&1)))==(v&1))
        profiles.append({'width':b,'pair_types':dict((str(t),c) for t,c in next(iter(ps)))})
    for fn in (lambda v:g(v,2),lambda v:g(v,2)^(v&1)):
        hh=full(2,fn)
        test(all(v==hh[1] for v in hh.values()))
    # Two correlated individually safe views expose a key coordinate per collision.
    for k in range(1,4):
        for T in permutations(range(4)):
            raw=[q(T[s],k,2) for s in range(4)]
            for P in permutations(range(2)):
                F=[P[y] for y in raw]
                pairs={}
                for s,y in enumerate(F):pairs.setdefault(y,[]).append(s)
                l0=[g(T[s],2) for s in range(4)]
                l1=[g(T[s],2)^(T[s]&1) for s in range(4)]
                for a,c in pairs.values():
                    test((l0[a]^l1[a]^l0[c]^l1[c])==(k&1))
    return {'run':652,'assertions':checks,'full_oracle_b2':'identical per-key','profile_widths':[2,4,6,8,10],'correlated_two_view_leak':'verified','cryptographic_security':'NOT_PROVED'}

if __name__=='__main__':
    print(json.dumps(main(),sort_keys=True,separators=(',',':')))
