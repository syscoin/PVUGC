#!/usr/bin/env python3
import itertools, json, random

def valid(enc,m):
    decrypt={}; counts={0:{},1:{}}
    for k in (0,1):
        for t in itertools.product((0,1),repeat=m):
            c=enc[(k,)+t]
            counts[k][c]=counts[k].get(c,0)+1
            for i,ti in enumerate(t):
                idx=(i,ti,c)
                if idx in decrypt and decrypt[idx]!=k:return False
                decrypt[idx]=k
    return counts[0]==counts[1]

census=[]
for m,b in ((1,1),(2,1),(2,2)):
    tuples=list(itertools.product((0,1),repeat=m+1))
    passing=0; checked=0
    for seq in itertools.product(range(1<<b),repeat=len(tuples)):
        passing+=int(valid(dict(zip(tuples,seq)),m))
        checked+=1
    census.append((m,b,checked,passing))
assert census==[(1,1,16,2),(2,1,256,0),(2,2,65536,24)]
rng=random.Random(6202026)
for _ in range(256):
    t0,t1,ka,kb=[rng.getrandbits(128) for j in range(4)]
    assert (kb^t1)^(ka^t1)^(ka^t0)^t0==kb
print(json.dumps({'run':620,'census':census,'reuse_checks':256,
 'model':'independent masks, perfect secrecy, no public native pk',
 'status':'scoped lower bound; NO PQ WKEM'},sort_keys=True,indent=2))
