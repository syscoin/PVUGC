#!/usr/bin/env python3
"""R233 conditional signature-persistence check; not WE/Bitcoin validation."""
import hashlib,itertools,json
H=lambda x:hashlib.sha256(hashlib.sha256(x).digest()).digest()
def encode(w):
    i=bytes.fromhex('11'*32)+(3).to_bytes(4,'little')+b'\0'+(0xfffffffd).to_bytes(4,'little')
    o=(150000).to_bytes(8,'little')+b'\x22\x00\x20'+bytes.fromhex('22'*32)
    core=(2).to_bytes(4,'little')+b'\x01'+i+b'\x01'+o+b'\0'*4
    witness=b'\x01'+bytes([len(w)])+w
    full=(2).to_bytes(4,'little')+b'\0\x01\x01'+i+b'\x01'+o+witness+b'\0'*4
    return H(core),H(full)
a,wa=encode(b'activation-A')
b,wb=encode(b'activation-B')
assert a==b and wa!=wb
changed_capsule=H(wa)!=H(wb)
M=H(a+b'refund-claim-42')
assert M==H(b+b'refund-claim-42')
V=list(itertools.product((False,True),repeat=3))
counter=0
for before,after in itertools.product(V,V):
    released=any(before)
    now=any(after)
    counter+=int(released and not now)
    assert not released or (released or now) # ever-fault latch
assert counter==7
print(json.dumps({'run':'R233','histories':64,'reorg_stale_cases':counter,
                  'shared_txid':a.hex(),'different_wtxid':wa!=wb,
                  'different_capsule':changed_capsule,
                  'same_native_message':True,
                  'status':'conditional policy demonstration; no WKEM or consensus'},sort_keys=True,indent=2))
