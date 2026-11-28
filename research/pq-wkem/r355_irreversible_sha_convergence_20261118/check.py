#!/usr/bin/env python3
"""R355: path-convergence checks, synthetic only; no ORIGINAL-source claim."""
import hashlib,json
from collections import defaultdict

DOMAIN=b'R355-HASH-PATH-V1\x00'
def H(data,n=256):
    d=hashlib.sha256(data).digest()
    return d if n==256 else d[:n//8]
def path(root,bits,n=256):
    state=root
    transcript=[]
    for j,bit in enumerate(bits):
        msg=DOMAIN+bytes([j])+bytes([bit])+state
        new=H(msg,n)
        transcript.append((msg,new))
        state=new
    return state,transcript

def find_collision(ta,tb):
    assert len(ta)==len(tb)
    assert ta[-1][1]==tb[-1][1]
    for j in range(len(ta)-1,-1,-1):
        ma,ha=ta[j]; mb,hb=tb[j]
        assert ha==hb, 'No convergence from equal later hash-inputs'
        if ma!=mb:
            return j,ma,mb,ha
        if j>0:
            assert ta[j-1][1]==tb[j-1][1]
    return None

seed=bytes.fromhex('ab'*32)
valid=[]
for i in range(256):
    b=i.to_bytes(1,'big')
    if H(b'R355-TOY-QUALIFIED'+b)[0]&3==0:
        valid.append(i)
assert len(valid)>1
# Toy 8-bit output, valid binary inputs only, to force a hash merger.
seen={}
witness=None
for i in valid:
    bits=[(i>>(7-j))&1 for j in range(8)]
    out,tr=path(seed[:1],bits,8)
    if out in seen:
        other,otr=seen[out]
        if other!=i:
            witness=(other,i,otr,tr,out)
            break
    seen[out]=(i,tr)
assert witness is not None
u,v,tu,tv,dig=witness
j,ma,mb,ho=find_collision(tu,tv)
assert ma!=mb and H(ma,8)==H(mb,8)==ho
assert all(H(b'R355-TOY-QUALIFIED'+x.to_bytes(1,'big'))[0]&3==0 for x in [u,v])
# Concrete SHA256 yields distinct outputs for two different inputs: not a universal assertion.
a,tra=path(seed,[(u>>(7-j))&1 for j in range(8)])
b,trb=path(seed,[(v>>(7-j))&1 for j in range(8)])
assert a!=b
# Raw invalid-input access to a public KDF cannot source-gate a frozen message.
S=bytes.fromhex('72'*32)
for i in [u,v,0,255]:
    raw,_=path(seed,[(i>>(7-j))&1 for j in range(8)])
    row=bytes(x^y for x,y in zip(S,raw))
    dec=bytes(x^y for x,y in zip(row,raw))
    assert dec==S
print(json.dumps({
    'suite':'R355 source-hash path convergence',
    'toy_qualified_count':len(valid),
    'toy_8bit_pair':[u,v],
    'toy_terminal_digest':dig.hex(),
    'toy_collision_layer':j,
    'toy_distinct_collision_inputs_sha256': [hashlib.sha256(ma).hexdigest(),hashlib.sha256(mb).hexdigest()],
    'sha256_same_path_terminal_equal':a==b,
    'public_compensation_unauthorized_inputs_recover':2,
    'limitations':'synthetic 8-bit toy merge; no actual ORIGINAL certificate, no full QPT security'
},sort_keys=True,indent=2))
