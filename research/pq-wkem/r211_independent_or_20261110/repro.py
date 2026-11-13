#!/usr/bin/env python3
"""Independent-OR algebra only; actual source KEM and PQ security absent."""
import hashlib, json
n=0
for s in (0,37,255):
    seen=set()
    for a in range(256):
        for b in range(256):
            d=(s^a,s^b)
            assert (d[0]^a)==(d[1]^b)==s
            seen.add(d);n+=1
    assert len(seen)==65536
for s in range(65536):
    a=(s*37+11)&65535;b=(s*19+71)&65535
    c1=a>>8;c2=b&255
    d1=s^a;d2=s^b
    assert (((d1>>8)^c1)<<8)|((d2&255)^c2)==s
    n+=1
for i in range(100):
    k=hashlib.sha256(b'k'+bytes([i])).digest()
    u=hashlib.sha256(b'u'+bytes([i])).digest()
    ck=hashlib.sha256(k).digest()
    assert ck==hashlib.sha256(k).digest()!=hashlib.sha256(u).digest()
    n+=1
print(json.dumps({'run':'R211-repro','checks':n,'meaning':'OR pad algebra and complementary leakage only; no witness encryption'},sort_keys=True))
