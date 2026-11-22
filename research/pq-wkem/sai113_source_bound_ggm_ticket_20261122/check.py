#!/usr/bin/env python3
"""Toy SHA256d preimage-range constrained GGM prefix-cover census.
Not a source certificate, FE or WKEM security test.
"""
import hashlib,json,math
M=16; THRESH=1 << 12
SID=b'SAI113-ORIGINAL-CLAIM-ANCHOR-CONSTANT'
def hash16(i):
    blob=b'fictional 80-byte anchored-header:' + SID + i.to_bytes(2,'little')
    return int.from_bytes(hashlib.sha256(hashlib.sha256(blob).digest()).digest()[:2],'big')
valid=[hash16(i)<THRESH for i in range(1<<M)]
# Exact minimal safe prefix cover: merge siblings only when all leaves below accepted.
def visit(lo,k):
    if k==0: return [ (lo,k) ] if valid[lo] else []
    left=visit(lo,k-1);right=visit(lo+(1<<(k-1)),k-1)
    if len(left)==len(right)==1 and left[0]==(lo,k-1) and right[0]==(lo+(1<<(k-1)),k-1):
        return [(lo,k)]
    return left+right
cover=visit(0,M)
assert all(all(valid[lo:lo+(1<<k)]) for lo,k in cover)
assert sum(1<<k for lo,k in cover)==sum(valid)
# Hash output range less than 4096 admits one 4-bit zero-prefix key.
assert THRESH == (1 << (M-4))
# An output-prefix key covers h=0 with no preimage/certificate at all.
output_fake_hash=0
assert output_fake_hash<THRESH
# A wrong-anchored string is directly in the output prefix even though it has no source certification.
result={'scope':'synthetic SHA256d output range vs random accepted 16-bit header-domain GGM prefixes; NOT ORIGINAL source','domain_bits':M,'target_prefix_bits':4,'valid_headers':sum(valid),'source_input_minimal_prefix_keys':len(cover),'source_input_cover_by_size':{str(k):sum(1 for _,j in cover if k==j) for k in sorted({j for _,j in cover})},'output_range_prefix_keys':1,'unconstrained_output_hash_0_grants_access':True,'no_source_certificate_or_release_compiler':True}
print(json.dumps(result,sort_keys=True,indent=2))
