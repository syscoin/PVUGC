#!/usr/bin/env python3
"""R247 minimum SHA/GGM source-gate counterexample; NOT original BTC/SYS proof.
Run: python checker_min.py. No external dependencies.
"""
import hashlib,json
H=lambda x:hashlib.sha256(x).digest()
H2=lambda x:H(H(x))
X=lambda a,b:bytes(i^j for i,j in zip(a,b))
T=0x15ff; P=['0000','000100','0001010']
match=lambda d:[p for p in P if f'{d:016b}'.startswith(p)]
for d in range(65536): assert (len(match(d))==1)==(d<=T)
s=H(b'R247-builder-master'); sigma=H(b'R247-frozen-claim-native-placeholder')
node=lambda p:H(b'GGM-prefix'+s+p.encode())
public=[(p,node(p),X(sigma,H(b'pad'+node(p)))) for p in P]
# Full-public recovery requires no header, source or verifier transcript.
p,k,e=public[0]
assert X(e,H(b'pad'+k))==sigma
# Every toy target-matched header opens the same public-token sigma.
def header(n):
    return (4).to_bytes(4,'little')+H(b'prev')+H(b'merkle')+(1700000000).to_bytes(4,'little')+(0x207fffff).to_bytes(4,'little')+n.to_bytes(4,'little')
found=[]
for n in range(10000):
    h=header(n); d=int.from_bytes(H2(h)[:2],'big')
    if d<=T:
        found.append((h,d))
        if len(found)==32:break
assert len(found)==32
for h,d in found:
    p=match(d)[0]; key=node(p)
    assert X(dict((p,e) for p,k,e in public)[p],H(b'pad'+key))==sigma
h0,d0=found[0]
h1,d1=next((h,d) for h,d in found[1:] if match(d)==match(d0))
ct=X(sigma,H(b'source'+H2(h0)))
assert X(ct,H(b'source'+H2(h0)))==sigma
assert X(ct,H(b'source'+H2(h1)))!=sigma
print(json.dumps({'checked_digest_range':65536,'toy_sha256d_headers':32,'raw_public_open_without_source':True,'second_source_pad_open':False,'secure_original_wkem':False},sort_keys=True))
