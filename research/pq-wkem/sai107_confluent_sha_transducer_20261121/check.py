#!/usr/bin/env python3
"""Toy SHA state-confluence screen; not ORIGINAL evidence or an FE implementation."""
import hashlib,itertools,json
H=lambda a:hashlib.sha256(a).digest()
q0=b"\x00";k0=H(b"private random demo seed"+b"\x01")
def sem(q,b):return H(b"semantic"+q+bytes([b]))[:1]
def label(k,b):return H(b"implicit-label"+k+bytes([b]))
seen={}; pair=None
for bits in itertools.product((0,1),repeat=10):
 q=q0;k=k0
 for b in bits:q=sem(q,b);k=label(k,b)
 if q in seen and seen[q][1]!=k:
  pair=(seen[q],(bits,k),q);break
 seen[q]=(bits,k)
assert pair
(p,k1),(r,k2),q=pair
assert p!=r and k1!=k2
S=H(b"TEST-ONLY-FROZEN-CANCEL-CAPABILITY")
canon=H(b"public-canonical-state"+q)
pad=H(b"terminal"+canon)
cipher=bytes(x^y for x,y in zip(S,pad))
recovered=bytes(x^y for x,y in zip(cipher,H(b"terminal"+canon)))
assert recovered==S
print(json.dumps({"model":"10-bit input with 8-bit truncated SHA semantic state; no original PoW","same_semantic_state":q.hex(),"distinct_paths":["".join(map(str,p)),"".join(map(str,r))],"implicit_labels_equal":k1==k2,"public_semantic_canonicalization_reveals_secret_without_path":recovered==S,"status":"candidate falsified; no independently instantiated implicit state delegation; not a release advance"},sort_keys=True,indent=2))
