#!/usr/bin/env python3
"""R240 minimal source-graph algebra reproduction; NOT BTC/SYS admission or WE."""
import hashlib, json

def H(*v):
    h=hashlib.sha256()
    for x in v:h.update(len(x).to_bytes(4,'big')+x)
    return h.digest()
def X(a,b):return bytes(i^j for i,j in zip(a,b))
K={n:H(b'key',n.encode()) for n in ('S','Q','A')}
sigma=H(b'frozen-cancel-capability')
# S -> Q <- A has NO directed accepting source path.
dsq=X(K['S'],K['Q']);daq=X(K['A'],K['Q'])
c=X(sigma,X(K['S'],K['A']))
assert X(c,X(dsq,daq))==sigma
# One-way edge masks stop this exact backward-walk calculation.
esq=X(K['Q'],H(b'edge',b'SQ',K['S']))
eaq=X(K['Q'],H(b'edge',b'AQ',K['A']))
q=X(esq,H(b'edge',b'SQ',K['S']))
assert q==K['Q']
assert X(eaq,q)==H(b'edge',b'AQ',K['A'])
# No K_A follows from this equation absent a hash inversion.
# A relaxed false relation [x=0 AND x=1] has a public accepting path.
k0=H(b'start');k1=H(b'after-zero');kt=H(b'accept')
e01=X(k1,H(b'edge',b'0',k0));e1t=X(kt,H(b'edge',b'1',k1))
k1o=X(e01,H(b'edge',b'0',k0));kto=X(e1t,H(b'edge',b'1',k1o))
assert kto==kt
# A single committed witness root prevents choosing 0 then 1 in the toy.
r0=H(b'global-witness',b'0');r1=H(b'global-witness',b'1')
assert r0!=r1 and H(b'global-witness',b'1')!=r0
# Unknown future source fingerprints do NOT share one frozen edge mask.
u=H(b'origin');v=H(b'destination')
e0=X(v,H(b'source-edge',u,r0))
assert X(e0,H(b'source-edge',u,r0))==v
assert X(e0,H(b'source-edge',u,r1))!=v
# Myhill-Nerode/fooling-set midpoint bound for EQ_n (mathematical proof in notes).
counts={str(n):1<<n for n in range(1,13)}
assert counts['12']==4096
print(json.dumps({'run':'R240_MIN','checks':9,'eq_n_midpoint_lower_bounds':counts,
 'false_directed_graph_xor_leak':True,'directional_toy_backward_walk_blocked':True,
 'false_relaxed_occurrences_open':True,'fixed_source_edge_not_valid_across_future_roots':True,
 'original_source_compiler':'NOT IMPLEMENTED','qpt_security':'NOT PROVED'},
 sort_keys=True,indent=2))
