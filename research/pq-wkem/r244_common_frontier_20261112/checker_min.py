#!/usr/bin/env python3
"""R244 minimal SYNTHETIC SHA-linked fork-frontier; NOT a source WKEM."""
import hashlib, struct, json
H=lambda b: hashlib.sha256(hashlib.sha256(b).digest()).digest()
X=lambda a,b: bytes(i^j for i,j in zip(a,b))
def chain(d=99, salt=0):
    result=[]
    for i in range(20):
        prev=result[-1] if result else bytes(32)
        branch=0 if i<d else salt
        raw=struct.pack('<I',1)+prev+H(struct.pack('<II',i,branch))+struct.pack('<III',i+1,0x207fffff,i+branch)
        assert len(raw)==80
        result.append(H(raw))
    return result
base=chain()
# Forks share SHA-linked prefix; first divergence is d=5 or d=9.
# Rebuild by selecting the baseline prefix but hashing later child headers.
def fork(d,salt):
    result=base[:d]
    for i in range(d,20):
        prev=result[-1]
        raw=struct.pack('<I',1)+prev+H(struct.pack('<II',i,salt))+struct.pack('<III',i+1,0x207fffff,i+salt)
        result.append(H(raw))
    return result
alts=[fork(5,11),fork(9,12),fork(9,13)]
sigma=H(b'R244-cancel-placeholder')
table={d:X(sigma,H(b'frontier'+struct.pack('<I',d)+base[d-1])) for d in range(1,18)}
for alt in alts:
    d=next(i for i,(a,b) in enumerate(zip(base,alt)) if a!=b)
    assert alt[17]!=base[17]
    assert X(table[d],H(b'frontier'+struct.pack('<I',d)+base[d-1]))==sigma
# The same keys exist to a classical attacker with NO alternate witness.
for d in table: assert X(table[d],H(b'frontier'+struct.pack('<I',d)+base[d-1]))==sigma
assert H(b'future'+alts[1][9]) != H(b'future'+alts[2][9])
print(json.dumps({'qualified_synthetic_alts':3,'raw_premature_opens':len(table),
 'same_depth_suffix_pads_differ':True,'status':'REJECTED; no original-source WE'},sort_keys=True))
