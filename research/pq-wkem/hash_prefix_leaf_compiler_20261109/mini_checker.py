#!/usr/bin/env python3
"""Executable nonlinear prefix-hash toy; NOT an authenticated PoW or secure WKEM."""
import hashlib, json, random

def h(*a):
    x = b"R167"
    for z in a:
        x += len(z).to_bytes(2,"big") + z
    return hashlib.sha256(x).digest()

def xb(a,b):return bytes(x^y for x,y in zip(a,b))

class T:
    def __init__(self,ctx):self.ctx=ctx;self.edges={}
    def root(self):return h(b"root",self.ctx)
    def step(self,old,bit):
        out=h(b"branch",self.ctx,old,bytes([bit]))
        self.edges[old,bit]=out
        return out
    def leaf(self,w,n):
        t=self.root()
        for i in range(n-1,-1,-1):t=self.step(t,(w>>i)&1)
        return t
    def tag(self,leaf):return h(b"tag",self.ctx,leaf)
    def pad(self,leaf):return h(b"pad",self.ctx,leaf)

def build(o,ws,n,K):
    return {o.tag(o.leaf(w,n)):xb(K,o.pad(o.leaf(w,n))) for w in ws}

def open_raw(o,rows,w,n):
    leaf=o.leaf(w,n);e=rows.get(o.tag(leaf))
    return None if e is None else xb(e,o.pad(leaf))

def trace_witnesses(o,n,R):
    at=[(o.root(),0,0)]
    for depth in range(n):
        nxt=[]
        for label,_,w in at:
            for b in (0,1):
                child=o.edges.get((label,b))
                if child is not None:nxt.append((child,depth+1,2*w+b))
        at=nxt
    return [w for _,_,w in at if R(w)]

def test():
    K=h(b"frozen",b"one")
    n=8;o=T(b"fixed-first")
    valid=list(range(128,256))
    rows=build(o,valid,n,K)
    assert len(rows)==128
    assert all(open_raw(o,rows,w,n)==K for w in valid)
    assert all(open_raw(o,rows,w,n) is None for w in range(128))
    # Nonlinear safe-prefix repair: one full-correctness row for all valid w.
    root=o.root();first=o.step(root,1)
    safe={o.tag(first):xb(K,o.pad(first))}
    assert len(safe)==1
    assert all(xb(safe[o.tag(first)],o.pad(first))==K for _ in valid)
    assert o.tag(o.step(root,0)) not in safe
    successes=0;extracted=0
    for seed in range(64):
        planted=int.from_bytes(h(b"plant",bytes([seed]))[:2],"big")%256
        y=h(b"source",bytes([planted]))[:2]
        R=lambda w:h(b"source",bytes([w]))[:2]==y
        rng=random.Random(seed+800)
        probes=rng.sample(range(256),32)
        found=[w for w in probes if R(w)]
        o2=T(b"hard-true"+y+bytes([seed]))
        capsule=build(o2,found,8,K)
        recovered=trace_witnesses(o2,8,R)
        assert set(found).issubset(recovered)
        if found:
            successes+=1
            assert recovered and all(open_raw(o2,capsule,w,8)==K for w in found)
            extracted+=1
    assert successes==extracted
    return {"first_bit_accepted":128,"leaf_rows":128,"sound_prefix_rows":1,"hard_true_fixtures":64,"builder_hits":successes,"classical_query_trace_extractions":extracted,"model":"SHA256 toy, not QROM/Bitcoin/security"}

if __name__=="__main__":print(json.dumps(test(),sort_keys=True,indent=2))
