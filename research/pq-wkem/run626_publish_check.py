"""Run 626 exact finite-group falsifier; standard library only, no crypto claims."""
import collections
import itertools
import json

E = tuple(range(4))
S4 = tuple(itertools.permutations(range(4)))
assert len(S4) == 24

def mul(a,b):
    return tuple(a[b[i]] for i in range(4))

def inv(a):
    z = [0]*4
    for i,j in enumerate(a): z[j]=i
    return tuple(z)

def ctype(a):
    seen=set(); cycles=[]
    for i in range(4):
        if i not in seen:
            j=i; n=0
            while j not in seen:
                seen.add(j); j=a[j]; n+=1
            if n>1: cycles.append(n)
    return tuple(sorted(cycles, reverse=True))

G = ((1,0,3,2),(1,2,0,3))
assert (ctype(G[0]),ctype(G[1])) == ((2,2),(3,))
laws=[]; marginals=[]; checks=0
for secret in G:
    joint=collections.Counter(); m0=collections.Counter(); m1=collections.Counter()
    for p in S4:
        for q in S4:
            u0=mul(p,inv(q)); u1=mul(mul(p,secret),inv(q))
            assert ctype(mul(u0,inv(u1)))==ctype(secret)
            joint[(u0,u1)]+=1; m0[u0]+=1; m1[u1]+=1
            checks+=2
    assert all(m0[x]==24 and m1[x]==24 for x in S4)
    laws.append(joint); marginals.append((m0,m1))
assert marginals[0]==marginals[1]
assert not (set(laws[0]) & set(laws[1]))
assert tuple(map(len,laws)) == (72,192)
tv=sum(abs(laws[0][v]-laws[1][v]) for v in set(laws[0])|set(laws[1]))/(2*576)
assert tv==1
# Aligned public adapters expose the exact same class for independent frames.
for secret in G:
    for p0,p1 in itertools.product(S4,S4):
        q0=inv(p0); q1=inv(p1)
        m0=mul(p0,inv(q0)); m1=mul(mul(p1,secret),inv(q1))
        left=mul(p0,inv(p1)); right=mul(q1,inv(q0))
        aligned=mul(mul(left,m1),right)
        assert ctype(mul(m0,inv(aligned)))==ctype(secret)
        checks+=1
print(json.dumps({"run":626,"result":"PASS","group":"S4","mask_pairs_per_world":576,"joint_supports":[72,192],"joint_overlap":0,"joint_tv":tv,"individual_path_marginals_uniform":True,"public_adapter_tests":1152,"counted_conditions":checks,"scope":"finite group falsifier, not QPT WKEM security"},sort_keys=True))
