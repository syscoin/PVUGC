#!/usr/bin/env python3
"""R213 source-digest interpolation toy; not ORIGINAL source or key release."""
import hashlib, json
q=257

def h(x):
    return hashlib.sha256(b'R213'+int(x).to_bytes(2,'big')).hexdigest()

def mul(a,b):
    r=[0]*(len(a)+len(b)-1)
    for i,x in enumerate(a):
        for j,y in enumerate(b):r[i+j]=(r[i+j]+x*y)%q
    return r

def ev(p,x):
    v=0
    for c in reversed(p):v=(v*x+c)%q
    return v

checks=0
for s in range(48):
    points=[(s+5+13*i)%q for i in range(4)]
    const=[s,0,0,0]
    assert len({h(ev(const,z)) for z in points})==1
    assert h(ev(const,0))==h(s)
    checks+=2
    vanish=[1]
    for z in points[:3]:vanish=mul(vanish,[(-z)%q,1])
    p=vanish[:]
    p[0]=(p[0]+s)%q
    assert all(ev(p,z)==s for z in points[:3])
    assert ev(p,points[3])!=s
    assert h(ev(p,points[3]))!=h(s)
    checks+=3
print(json.dumps({'run':'R213-AFPI','assertions':checks,'result':'public constant or omitted future source digest; no secure gate'},sort_keys=True))
