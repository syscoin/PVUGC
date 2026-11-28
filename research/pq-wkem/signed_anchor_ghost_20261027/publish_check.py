"""Bounded signed-ghost diagnostic; structured 3CNF source, NOT random-B LWE."""
from itertools import product
from random import Random
from fractions import Fraction
import json
Q=2**20;G=640;H=4;R=Q//G; rng=Random(202610271114)
C=[((0,0,0),(0,0,0)),((0,0,0),(1,1,1))]
cols=[('a',),('y',0,0),('y',0,1)]
for i,(_,f) in enumerate(C):
    cols += [('t',i,t) for t in product((0,1),repeat=3) if t!=f]
ix={x:i for i,x in enumerate(cols)}
rows=[]
def row(terms):
    a=[0]*len(cols)
    for k,v in terms:a[ix[k]]+=v
    rows.append(a)
row([(('y',0,0),1),(('y',0,1),1),(('a',),-1)])
for i,(vs,f) in enumerate(C):
    al=[t for t in product((0,1),repeat=3) if t!=f]
    row([(('t',i,t),1) for t in al]+[(('a',),-1)])
    for j in range(3):
        row([(('t',i,t),1) for t in al if t[j]]+[(('y',vs[j],1),-1)])
def local(f,s):
    if s!=f:return {s:1}
    a=(1-f[0],f[1],f[2]);b=(f[0],1-f[1],f[2]);c=(1-f[0],1-f[1],f[2])
    return {a:1,b:1,c:-1}
def ghost(bit):
    z=[0]*len(cols);z[ix[('a',)]]=1;z[ix[('y',0,bit)]]=1
    for i,(vs,f) in enumerate(C):
        for t,v in local(f,(bit,bit,bit)).items():z[ix[('t',i,t)]]=v
    return z
checks=0
for f in product((0,1),repeat=3):
    for s in product((0,1),repeat=3):
        v=local(f,s)
        assert all(t!=f for t in v) and sum(v.values())==1
        assert all(sum(c*t[j] for t,c in v.items())==s[j] for j in range(3))
        checks+=4
for bit in (0,1):
    z=ghost(bit)
    assert z[ix[('a',)]]==1 and sum(z)==H
    assert sum(abs(x) for x in z)==6
    assert all(sum(x*y for x,y in zip(z,r))==0 for r in rows)
    checks+=4
z=ghost(0)
for _ in range(1000):
    t=rng.randrange(R);u=[rng.randrange(Q) for _ in rows]
    e=[rng.randrange(-5,6) for _ in cols]
    p=[((G//H)*t+sum(row[j]*u[i] for i,row in enumerate(rows))+e[j])%Q for j in range(len(cols))]
    y=sum(x*v for x,v in zip(z,p))%Q
    E=sum(x*v for x,v in zip(z,e))
    assert y==(G*t+E)%Q and abs(E)<=30
    actual=min(range(R),key=lambda a:(min((y-G*a)%Q,(G*a-y)%Q),a))
    assert actual==t
    checks+=3
expo=Fraction(G*G,1)/(8*Fraction(256,25)*6)
assert expo==Fraction(2500,3) and expo>Fraction(1200*694,1000)
checks+=2
print(json.dumps(dict(checks=checks,rows=len(rows),columns=len(cols),ghost_anchor=1,ghost_l1=6,original_witnesses=0,trial_openings=1000,ideal_gaussian_tail_exponent=str(expo),qualified_positive_advance=False),sort_keys=True))
