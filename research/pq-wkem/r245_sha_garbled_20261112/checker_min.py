#!/usr/bin/env python3
"""R245 minimal public-garbled-source FALSE attack (synthetic, not WKEM)."""
import hashlib, secrets, json

def H(*p): return hashlib.sha256(b''.join(len(v).to_bytes(4,'big')+v for v in p)).digest()
def X(a,b): return bytes(i^j for i,j in zip(a,b))
def pad(g,a,b=b''): return H(b'pad',g,a,b)[:16]
def key(g,a,b=b''): return H(b'row',g,a,b).hex()
L={w:[secrets.token_bytes(16) for _ in range(2)] for w in ('x','notx','out')}
K=secrets.token_bytes(16)
# Honest verifier V(x)=x AND NOT x is FALSE for both possible x.
not_rows={key(b'not', L['x'][x]):X(L['notx'][1-x],pad(b'not',L['x'][x])) for x in (0,1)}
and_rows={key(b'and', L['x'][x],L['notx'][y]):X(L['out'][x&y],pad(b'and',L['x'][x],L['notx'][y])) for x in (0,1) for y in (0,1)}
E=X(K,H(b'release',L['out'][1])[:16])
# The actual public view has BOTH labels for the unknown future source bit.
public={'x':L['x'],'not_rows':not_rows,'and_rows':and_rows,'E':E,'check':H(b'check',K)}
for x in (0,1):
    nx=X(public['not_rows'][key(b'not',public['x'][x])],pad(b'not',public['x'][x]))
    o=X(public['and_rows'][key(b'and',public['x'][x],nx)],pad(b'and',public['x'][x],nx))
    assert o==L['out'][0]  # no witness opens FALSE
# Raw attacker does NOT have L, K, or a valid source certificate.
not_labels={X(public['not_rows'][key(b'not',a)],pad(b'not',a)) for a in public['x']}
out_labels=set()
for a in public['x']:
    for b in not_labels:
        out_labels.add(X(public['and_rows'][key(b'and',a,b)],pad(b'and',a,b)))
found=[X(public['E'],H(b'release',t)[:16]) for t in out_labels]
assert len(out_labels)==2 and len([v for v in found if H(b'check',v)==public['check']])==1
assert K in found
# Different hypothetical future source certificates hash to different keys.
dbl=lambda b:hashlib.sha256(hashlib.sha256(b).digest()).digest()
assert H(b'source-label',dbl(b'future1'))!=H(b'source-label',dbl(b'future2'))
print(json.dumps({'run':'R245_min','false_witnesses':0,'honest_open_count':0,'raw_attack_recovers_K':True,'publicly_reached_output_labels':len(out_labels),'scope':'synthetic SHA rows, no original source or QPT proof'},sort_keys=True))
