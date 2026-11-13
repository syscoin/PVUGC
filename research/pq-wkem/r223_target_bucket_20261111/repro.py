#!/usr/bin/env python3
"""R223 small PoW-target release counterexample; no original-source or QPT proof."""
import hashlib, json
H=lambda x: hashlib.sha256(x).digest()
D=lambda x: H(H(x))
def X(a,b):return bytes(x^y for x,y in zip(a,b))
P=H(b'R223 synthetic 76-byte header')*2+H(b'prefix')[:12]
assert len(P)==76
S=[(n,D(P+n.to_bytes(4,'little'))) for n in range(65536)]
S=[(n,z) for n,z in S if z[0]==0]
assert len(S)>2
K=H(b'R223 frozen synthetic capability')
# A: all true-work digests have common public prefix zero.
C=X(K,H(S[0][1][:1]))
assert all(X(C,H(z[:1]))==K for _,z in S)
assert X(C,H(b'\0'))==K  # fabricate digest 0, no source history
# B: raw header preimage-pad yields a different key for other valid witnesses.
mask=lambda n: H(P+n.to_bytes(4,'little'))
E=X(K,mask(S[0][0]))
assert sum(X(E,mask(n))==K for n,_ in S)==1
# C: polynomially sized per-solution toy table can be used early.
rows={n:X(K,mask(n)) for n,_ in S}
assert X(rows[S[0][0]],mask(S[0][0]))==K
print(json.dumps({'accepted_toy_nonces':len(S),'prefix_unlocks_from_fabricated_digest':True,
 'single_header_pad_valid_witnesses':1,'precomputed_table_unlocks_early':True,
 'status':'broken target-bucket release; no actual BTC/SYS evidence'},sort_keys=True))
