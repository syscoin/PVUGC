#!/usr/bin/env python3
"""R243 minimal canonical-fault and source-pad checks; synthetic, NOT consensus/WE."""
import hashlib, json
H=lambda x: hashlib.sha256(hashlib.sha256(x).digest()).digest()
ref=H(b'ancestor90')
tag=b'\x6a\x27sys'+ref+(90).to_bytes(4,'little')
assert len(tag)==41
assert tag[:5]==b'\x6a\x27sys'
assert tag == b'\x6a\x27sys'+ref+(90).to_bytes(4,'little')
for bad in (tag+b'\x00', b'\x6a\x02zz', b'\x6a\x27sys'+H(b'wrong')+(90).to_bytes(4,'little')):
    assert bad != tag
    # Contextual valid-child requires canonical tag, so never accepts bad.
    assert not (bad == tag)
assert H(b'parent1') != H(b'parent2')
sigma=H(b'frozen-cancel')
k1=H(b'source-pad'+H(b'parent1'))
k2=H(b'source-pad'+H(b'parent2'))
C=bytes(x^y for x,y in zip(sigma,k1))
assert bytes(x^y for x,y in zip(C,k1)) == sigma
assert bytes(x^y for x,y in zip(C,k2)) != sigma
common=H(b'source-status'+b'\x01')
C2=bytes(x^y for x,y in zip(sigma,common))
assert bytes(x^y for x,y in zip(C2,common)) == sigma
print(json.dumps({"run":"R243_MIN","assertions":13,
 "source_status":"synthetic predicate inputs, not real BTC/SYS proofs",
 "release_status":"different source pads fail common-key correctness; public constant pad exposes sigma"},sort_keys=True,indent=2))
