#!/usr/bin/env python3
"""Source Merkle same-root contradiction -> hash collision, toy 16-bit demonstration only."""
import hashlib, json

def H(tag, *xs):
    d=bytes([len(tag)])+tag+b''.join(len(x).to_bytes(2,'big')+x for x in xs)
    return hashlib.sha256(d).digest()[:2]   # intentionally toy 16-bit, NOT a real hash

def leaf(i,value):return H(b'L',i.to_bytes(1,'big'),value)
def parent(a,b):return H(b'N',a,b)

def merkle_root(vs):
    h=[leaf(i,v) for i,v in enumerate(vs)]
    return parent(parent(h[0],h[1]),parent(h[2],h[3]))

def proof(vs,i):
    h=[leaf(j,v) for j,v in enumerate(vs)]
    if i//2==0:return (h[i^1], parent(h[2],h[3]))
    return (h[i^1], parent(h[0],h[1]))

def path_hashes(i,value,siblings):
    z=leaf(i,value); chain=[z]; inp=[(b'L',i.to_bytes(1,'big'),value)]
    for s in siblings:
        a,b=(s,z) if i&1 else (z,s)
        inp.append((b'N',a,b));z=parent(a,b);chain.append(z);i//=2
    return inp,chain

def find_collision(i,v1,p1,v2,p2,root):
    assert i in range(4) and v1 !=v2
    in1,hs1=path_hashes(i,v1,p1)
    in2,hs2=path_hashes(i,v2,p2)
    assert hs1[-1]==hs2[-1]==root
    # At leaf level or first layer where divergent digests converge,
    # unequal hash inputs have the SAME output: an explicit collision.
    for t in range(3):
        if in1[t]!=in2[t] and hs1[t]==hs2[t]:
            return {'level':t,'distinct_inputs':True,'equal_output':True}
    raise AssertionError('no hash collision found')

def run():
    cases=[];tries_sum=0
    for seed in range(32):
        seen={};pair=None
        for nonce in range(5000):
            v=seed.to_bytes(2,'big')+nonce.to_bytes(4,'big')
            d=leaf(1,v)
            if d in seen and v!=seen[d]:
                pair=(seen[d],v,nonce+1)
                break
            seen[d]=v
        assert pair is not None
        v1,v2,t=pair;tries_sum+=t
        a=[b'a0',v1,b'a2',b'a3'];b=[b'a0',v2,b'a2',b'a3']
        r=merkle_root(a)
        assert r==merkle_root(b)
        cert=find_collision(1,v1,proof(a,1),v2,proof(b,1),r)
        assert cert['level']==0
        cases.append(cert)
    return {'cases':len(cases),'assertions':len(cases)*4,
            'total_search_trials':tries_sum,
            'all_collisions_at_leaf':all(c['level']==0 for c in cases),
            'scope':'16-bit intentionally insecure toy Merkle; real QPT collision resistance is an unproved assumption in this run',
            'sha256_source':hashlib.sha256(open(__file__,'rb').read()).hexdigest()}

if __name__=='__main__':print(json.dumps(run(),sort_keys=True,indent=2))
