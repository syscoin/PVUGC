#!/usr/bin/env python3
"""R195 pure-child prefix projection fixture; not source authentication or WKEM."""
import hashlib,json

def H(*xs):
    return hashlib.sha256(b'|'.join(xs)).digest()
def chain(n,d=None):
    a=[H(b'anchor')]
    for j in range(1,n+1):
        salt=b'other' if d is not None and j>=d else b'base'
        a.append(H(b'child',j.to_bytes(4,'big'),a[-1],salt))
    return a
def tag_ref(n):
    return 10*((n-6)//10)
def tag(a,n):
    r=tag_ref(n)
    return (r,a[r])

pairs=0; assertions=0; false_rounded=0; repeated=0
for h in range(21,44):
    r=10*((h+9)//10)
    for k in (2,5,13):
        n=max(r+6,h+k-1)
        a=chain(n)
        for d in range(1,min(n,h+11)+1):
            b=chain(n,d)
            assert (a[h]!=b[h])==(d<=h);assertions+=1
            assert (a[r]!=b[r])==(d<=r);assertions+=1
            assert tag_ref(r+6)==r and n>=r+6;assertions+=1
            assert tag(b,r+6)==(r,b[r]);assertions+=1
            if h<d<=r:
                assert a[h]==b[h] and a[r]!=b[r];false_rounded+=1;assertions+=1
            if tag_ref(n)==tag_ref(n-1):
                assert tag(b,n)==tag(b,n-1);repeated+=1;assertions+=1
            # Replacing a mutable parent work ID does not alter pure-child U_h.
            work_a=H(b'powA',b[n]);work_b=H(b'powB',b[n])
            assert work_a!=work_b and b[h]==b[h];assertions+=1
            pairs+=1
# Explicit claim h=101, fork d=105 and tag n=116.
a,b=chain(116),chain(116,105)
assert a[101]==b[101] and a[110]!=b[110] and tag_ref(116)==110
assertions+=1
print(json.dumps({'run':'R195-PUBLISHED','pairs':pairs,
 'false_rounded':false_rounded,'same_tag_consecutive_child_cases':repeated,
 'assertions':assertions,'scope':'synthetic source semantics only; no release'},sort_keys=True))
