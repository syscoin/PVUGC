#!/usr/bin/env python3
"""R198 finite SHA-GGM PoW-prefix counterexample; NOT a source/KEM validator."""
import hashlib
import json

def H(label, value):
    return hashlib.sha256(label.encode()+b'\x00'+value).digest()

def bits(v,n):
    return format(v, f'0{n}b')

def cover(n,target):
    result=[]
    start=0
    while start <= target:
        span=1
        while start%(span*2)==0 and start+span*2-1<=target:
            span*=2
        result.append(bits(start,n)[:n-(span.bit_length()-1)])
        start+=span
    return result

def descend(seed,path):
    for b in path:
        seed=H('ggm-'+b,seed)
    return seed

def key_for(y, public):
    for prefix,seed in public:
        if y.startswith(prefix):
            return descend(seed,y[len(prefix):])
    return None

def xor(a,b):
    return bytes(x^y for x,y in zip(a,b))

def run():
    n=10; target=301
    master=H('master',b'R198')
    public=[(p,descend(master,p)) for p in cover(n,target)]
    checked=0
    for i in range(1<<n):
        y=bits(i,n)
        key=key_for(y,public)
        assert (key is not None)==(i<=target)
        if key is not None:
            assert key==descend(master,y)
        checked+=1
    K=H('cancel',b'fixed-message')
    a=key_for(bits(42,n),public)
    b=key_for(bits(43,n),public)
    assert a!=b
    E=xor(K,H('pad',a))
    assert xor(E,H('pad',a))==K
    assert xor(E,H('pad',b))!=K
    for _,seed in public:
        row=xor(K,H('prefix-pad',seed))
        assert xor(row,H('prefix-pad',seed))==K
    forged=bits(0,n)
    assert key_for(forged,public) is not None
    # No Bitcoin header, AuxPoW proof, coinbase, or Syscoin source required.
    return {'case':'R198-SCPRF-PUBLISHED','cover_nodes':len(public),
            'interval_values_checked':checked,
            'distinct_valid_digest_leaves':a!=b,
            'other_valid_digest_fails_same_key':True,
            'public_prefix_row_opens_without_source':True,
            'fabricated_digest_accepted_without_header':True,
            'security':'classical counterexample only; no ORIGINAL KEM/QPT claim'}

if __name__=='__main__':
    print(json.dumps(run(),indent=2,sort_keys=True))
