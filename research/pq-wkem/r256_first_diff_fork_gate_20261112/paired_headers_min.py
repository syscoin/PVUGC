#!/usr/bin/env python3
"""Two synthetic SHA256d header encodings per prefix class; NOT real consensus."""
from hashlib import sha256
import json,struct
def h(x):return sha256(x).digest()
def sha2(x):return h(h(x))
def firstdiff(x,y):
    n=int.from_bytes(x,'big')^int.from_bytes(y,'big')
    return 256-n.bit_length() if n else None
A=h(b'R256-original-sys-child-baseline'); pairs={i:[] for i in range(8)};nonce=0
while any(len(p)<2 for p in pairs.values()):
    hd=(b'R256 synt child header'+bytes(64))[:76].ljust(76,b'\0')+struct.pack('<I',nonce)
    d=sha2(hd);i=firstdiff(A,d)
    if i in pairs and len(pairs[i])<2:pairs[i].append((hd,d))
    nonce+=1
    assert nonce<20000
K=h(b'R256-builder-unknown-K')
for i,((h0,d0),(h1,d1)) in pairs.items():
    assert firstdiff(A,d0)==firstdiff(A,d1)==i and d0!=d1
    pad0=h(b'R256-source-full-sha'+h0+d0);pad1=h(b'R256-source-full-sha'+h1+d1)
    assert pad0!=pad1
    t=bytes(x^y for x,y in zip(K,pad0))
    assert bytes(x^y for x,y in zip(t,pad1))!=K
print(json.dumps({'run':'R256_PAIRED_HEADERS','classes_tested':8,'same_class_pair_nonconvergence':8,'synthetic_hash_nonce_trials':nonce,'status':'nonqualifying synthetic; no consensus/PoW admission'},sort_keys=True,indent=2))
