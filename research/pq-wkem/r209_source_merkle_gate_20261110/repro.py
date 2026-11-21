#!/usr/bin/env python3
"""R209 minimal synthetic source-root/key convergence regression; NOT BTC/SYS/WKEM."""
from hashlib import sha256
import json

def H(t,*a):
    x=t+b'\0'+b''.join(len(v).to_bytes(2,'big')+v for v in a)
    return sha256(x).digest()
def X(a,b):return bytes(x^y for x,y in zip(a,b))
def leaf(i,v):return H(b'L',bytes([i]),v)
def N(a,b):return H(b'N',a,b)
def root(v):return N(N(leaf(0,v[0]),leaf(1,v[1])),N(leaf(2,v[2]),leaf(3,v[3])))
def path(v):return (leaf(0,v[0]),N(leaf(2,v[2]),leaf(3,v[3])))
def verify(r,v,p):return N(N(p[0],leaf(1,v)),p[1])==r

def run():
    out={'auth_own':0,'cross_root_rejected':0,'same_root_conflict_rejected':0,
         'selected_future_opens':0,'other_future_incomplete':0,'wildcard_early_opens':0}
    for seed in range(12):
        s=seed.to_bytes(2,'big'); a=[b'a',H(b'A',s),b'c',b'd']
        ba=[a[:2]+[b'c',b'd'] for _ in range(3)]
        for j in range(3):ba[j][1]=H(b'B',s,bytes([j]))
        ra=root(a); rb=[root(b) for b in ba]
        K=H(b'K',s);La=H(b'label',a[1]);L=[H(b'label',b[1]) for b in ba]
        E=X(K,H(b'pair',La,L[0]))
        assert X(E,H(b'pair',La,L[0]))==K
        out['selected_future_opens']+=1
        for j in (1,2):
            assert X(E,H(b'pair',La,L[j]))!=K
            out['other_future_incomplete']+=1
        for b,r in zip(ba,rb):
            assert verify(r,b[1],path(b));out['auth_own']+=1
            assert not verify(ra,b[1],path(b));out['cross_root_rejected']+=1
            assert not verify(ra,b[1],path(a));out['same_root_conflict_rejected']+=1
        U=H(b'public-wildcard');EW=X(K,H(b'pair',La,U))
        assert X(EW,H(b'pair',La,U))==K
        out['wildcard_early_opens']+=1
    out['assertions']=sum(out.values())
    out['status']='synthetic Merkle/opening regression, NOT original source or secure release'
    out['source_sha256']=sha256(open(__file__,'rb').read()).hexdigest()
    return out
if __name__=='__main__':print(json.dumps(run(),sort_keys=True,indent=2))
