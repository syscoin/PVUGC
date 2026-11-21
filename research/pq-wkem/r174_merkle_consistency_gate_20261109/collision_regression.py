#!/usr/bin/env python3
"""Truncated Merkle-root adversarial binding negative control. NOT a SHA256 break."""
import hashlib,itertools,json

def h(prefix,*parts):
    v=prefix+ b''.join(len(p).to_bytes(2,'big')+p for p in parts)
    return hashlib.sha256(v).digest()[:2]
def root_levels(bs):
    levels=[[h(b'leaf',i.to_bytes(2,'big'),bytes([b])) for i,b in enumerate(bs)]]
    while len(levels[-1])>1:
        v=levels[-1];levels.append([h(b'node',v[i],v[i+1]) for i in range(0,len(v),2)])
    return levels
def proof(lv,i):
    ps=[]
    for arr in lv[:-1]:ps.append(arr[i^1]);i//=2
    return ps
def verify(r,i,b,ps):
    x=h(b'leaf',i.to_bytes(2,'big'),bytes([b]))
    for p in ps:
        x=h(b'node',p,x) if (i&1) else h(b'node',x,p)
        i//=2
    return x==r
seen={};num=0
for integer in range(65536):
    bs=tuple((integer>>i)&1 for i in range(16))
    lv=root_levels(bs);r=lv[-1][0];num+=1
    if r in seen:
        other,lv2=seen[r]
        if other!=bs:
            idx=next(i for i in range(16) if other[i]!=bs[i])
            assert verify(r,idx,other[idx],proof(lv2,idx))
            assert verify(r,idx,bs[idx],proof(lv,idx))
            print(json.dumps({'model':'SHA256 truncated to 16 bits at each Merkle node; NOT a SHA256 attack',
                              'queries_until_same_root':num,'different_witnesses':True,
                              'same_root_different_bit_verified':True,'index':idx,
                              'root_hex':r.hex()},indent=2,sort_keys=True))
            break
    else:seen[r]=(bs,lv)
else:raise AssertionError('No collision found')
