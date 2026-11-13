#!/usr/bin/env python3
"""R260 finite hash-only signature-gate experiment. NOT a source WKEM."""
import hashlib
import json

def h(*parts):
    return hashlib.sha256(b''.join(parts)).digest()

def xor(a,b):
    return bytes(x ^ y for x,y in zip(a,b))

def sign_bits(message,n=12):
    d = h(b'message:',message)
    return [((d[i//8] >> (7-i%8)) & 1) for i in range(n)]

def make(seed,n=12):
    pre = [[h(b'preimage:',seed,bytes([i,b])) for b in range(2)] for i in range(n)]
    shares = [h(b'share:',seed,bytes([i])) for i in range(n)]
    key = bytes(32)
    for x in shares: key=xor(key,x)
    pub = [[h(b'public:',p) for p in pair] for pair in pre]
    caps = [[xor(shares[i],h(b'pad:',pre[i][b])) for b in range(2)] for i in range(n)]
    return pre,pub,caps,key

def sig(pre,msg):
    return [pre[i][bit] for i,bit in enumerate(sign_bits(msg,len(pre)))]

def verify(pub,msg,s):
    return len(s)==len(pub) and all(h(b'public:',s[i])==pub[i][bit] for i,bit in enumerate(sign_bits(msg,len(pub))))

def raw_open(caps,msg,s):
    out=bytes(32)
    for i,bit in enumerate(sign_bits(msg,len(caps))):
        out=xor(out,xor(caps[i][bit],h(b'pad:',s[i])))
    return out

count=0
for test in range(32):
    seed=h(b'testseed',str(test).encode())
    pre,pub,caps,key=make(seed)
    legitimate=b'canonical-source-fork-proof' + bytes([test])
    ordinary=b'unrelated-normal-source-signature' + bytes([test])
    for msg in [legitimate,ordinary]:
        s=sig(pre,msg)
        assert verify(pub,msg,s)
        assert raw_open(caps,msg,s)==key
        count+=1
    # The signer or capsule builder holding both preimages can decrypt without any source message.
    recover=bytes(32)
    for i in range(len(pre)):
        recover=xor(recover,xor(caps[i][0],h(b'pad:',pre[i][0])))
    assert recover==key
    count+=1
    # Synthetic acceptance filter rejects an unrelated message but DOES NOT prevent raw decryption.
    assert ordinary != legitimate
    assert raw_open(caps,ordinary,sig(pre,ordinary))==key
    count+=1
print(json.dumps({"run":"R260_HASH_SIGNATURE_GATE","cases":32,"assertion_groups":count,
                  "qualified_message_recovers":32,"unrelated_message_recovers":32,
                  "private_builder_recovers_pre_evidence":32,
                  "status":"nonqualifying signer-controlled release; not original source WE"},sort_keys=True,indent=2))
