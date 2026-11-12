#!/usr/bin/env python3
"""Exact disjoint-prefix check; toy hash-only token failure; NOT source admission."""
import hashlib,json,struct
def H(x): return hashlib.sha256(x).digest()
def D(x): return H(H(x))
def firstdiff(a,b,n):
    z=a^b
    return n-z.bit_length() if z else None
num=0
for n in range(1,10):
    for a in range(1<<n):
        for b in range(1<<n):
            match=[i for i in range(n) if (a>>(n-i))==(b>>(n-i)) and (((a^(b))>>(n-i-1))&1)]
            assert len(match)==(0 if a==b else 1)
            assert (match[0] if match else None)==firstdiff(a,b,n)
            num+=1
A=H(b"r256-pinned-original-baseline"); K=H(b"r256-synthetic-private-cancellation-key")
S=H(b"r256-synthetic-frozen-cancel-sig"); E=bytes(x^y for x,y in zip(S,K))
tokens={}
for i in range(256):
    pad=H(b"R256-PREFIX"+A+struct.pack('>H',i))
    tokens[i]=bytes(x^y for x,y in zip(K,pad))
    recovered=bytes(x^y for x,y in zip(tokens[i],pad))
    assert recovered==K and bytes(x^y for x,y in zip(E,recovered))==S
    assert firstdiff(int.from_bytes(A,'big'),int.from_bytes(A,'big')^(1<<(255-i)),256)==i
headers=[b"R256-SYNTHETIC\x00".ljust(76,b"!")+i.to_bytes(4,'little') for i in range(256)]
digests=[D(h) for h in headers]
assert len(set(digests))==256
assert len(set(H(b"R256-HEADER-STATE"+d+h) for d,h in zip(digests,headers)))==256
print(json.dumps({"run":"R256_FIRST_DIFF","exact_cover_tuples":num,"public_prefix_classes":256,"public_token_key_recoveries":256,"fake_class_candidates":256,"synthetic_distinct_source_digests":256,"status":"NONQUALIFYING: public token collapse; full ORIGINAL Build/Open absent"},sort_keys=True,indent=2))
