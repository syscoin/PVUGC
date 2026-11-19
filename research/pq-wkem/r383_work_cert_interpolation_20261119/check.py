#!/usr/bin/env python3
"""Mathematical threshold-source attempt only. No real original certificates, FE or Bitcoin consensus."""
from itertools import combinations
import hashlib, json
q, d = 101, 3
K, coeff = 47, (12, 29)
xs = tuple(range(1, 7))
def f(x): return (K + coeff[0]*x + coeff[1]*x*x) % q
def at_zero(points):
    total=0
    for i, (xi,yi) in enumerate(points):
        li=1
        for j,(xj,_) in enumerate(points):
            if i!=j: li = li*(-xj)*pow((xi-xj)%q,-1,q)%q
        total=(total+yi*li)%q
    return total
all_reconstructed=[at_zero([(x,f(x)) for x in ix]) for ix in combinations(xs,d)]
assert len(all_reconstructed)==20 and set(all_reconstructed)=={K}
# Change a single value: no common release for all qualifying subsets.
def fp(x): return (f(x)+(1 if x==xs[0] else 0))%q
changed=[at_zero([(x,fp(x)) for x in ix]) for ix in combinations(xs,d)]
assert len(set(changed))>1
# Hash-shaped certificate inputs: choose 3 headers which fail an 8-leading-zero-bit mock target.
# Public share oracle f(hash(header) mod q) would still permit immediate recovery.
headers=[b'invalid synthetic parent '+str(i).encode() for i in range(20)]
bad=[]
for h in headers:
    digest=hashlib.sha256(hashlib.sha256(h).digest()).digest()
    x=1 + int.from_bytes(digest,'big') % (q-1)
    if digest[0]!=0 and x not in [z[0] for z in bad]:
        bad.append((x, f(x),digest.hex()))
    if len(bad)==d: break
assert len(bad)==d
assert all(int(z[2][:2],16)!=0 for z in bad)
assert at_zero([(x,y) for x,y,_ in bad]) == K
print(json.dumps({"scope":"synthetic interpolation and rejected headers only; not authenticated Bitcoin/Syscoin, not FE", "field":q,"threshold":d,"all_valid_subsets":len(all_reconstructed),"common_release":K,"single_modified_share_subset_outputs":sorted(set(changed)),"recovery_from_three_invalid_parent_hashes":at_zero([(x,y) for x,y,_ in bad]),"invalid_parent_hashes":[z[2] for z in bad]},sort_keys=True,indent=2))
