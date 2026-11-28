#!/usr/bin/env python3
"""Exact small SHA-Lamport partial-signature experiments. Research only.
NOT a WKEM, native SLH signature, PoW verifier, or generic relation compiler.
"""
from hashlib import sha256
from random import Random
import json

def H(domain: bytes, msg: bytes, n=2):
    return sha256(domain + len(msg).to_bytes(4,'big') + msg).digest()[:n]

def build(y: bytes, seed: int, msgbits=(1,0,1,0,1,1), missing=3):
    rng = Random(seed)
    pub = []
    part = []
    for i,b in enumerate(msgbits):
        a,c = (rng.randbytes(5), rng.randbytes(5))
        p = [H(b'leaf',a,len(y)),H(b'leaf',c,len(y))]
        secret = (a,c)[b]
        if i==missing:
            p[b] = y
            secret=None
        pub.append(tuple(p))
        part.append(secret)
    return {'pub':pub,'part':part,'message':msgbits,'missing':missing}

def verify(c, signature):
    if len(signature)!=len(c['message']):return False
    return all(H(b'leaf',s,len(c['pub'][i][b]))==c['pub'][i][b]
               for i,(s,b) in enumerate(zip(signature,c['message'])))

def open_sig(c, w):
    sig=list(c['part']);sig[c['missing']]=w
    return tuple(sig) if verify(c,sig) else None

def run():
    rng=Random(17120261109)
    checks=0
    recovered=0
    fake_rejected=0
    multi_preimages=0
    same_sig_violations=0
    premature_unlocks=0
    for t in range(40):
        src=rng.randbytes(4)
        y=H(b'leaf',src,2)
        c=build(y,seed=t)
        sig=open_sig(c,src)
        assert sig is not None and verify(c,sig);checks+=2
        recovered+=1
        # Test random false evidence as signature ingredient.
        fake=rng.randbytes(4)
        if fake !=src and H(b'leaf',fake,2)!=y:
            assert open_sig(c,fake) is None;fake_rejected+=1;checks+=1
        # Exhaust a 16-bit toy preimage domain for multiple valid witnesses.
        # These all satisfy H(w)=y (not the source's ORIGINAL relation).
        preimages=[i.to_bytes(2,'big') for i in range(65536) if H(b'leaf',i.to_bytes(2,'big'),2)==y]
        if len(preimages)>=2:
            multi_preimages+=1
            s0=open_sig(c,preimages[0]);s1=open_sig(c,preimages[1])
            assert s0 is not None and s1 is not None and s0!=s1;checks+=3
            same_sig_violations+=1
        # A purported ORIGINAL predicate requires first bit set and anchor byte.
        # A builder that only commits y=H(w_bad) cannot enforce ORIGINAL authenticity.
        invalid_source = b'\x00'+rng.randbytes(3)
        source_y=H(b'leaf',invalid_source,2)
        bad_c=build(source_y,seed=1000+t)
        assert open_sig(bad_c,invalid_source) is not None
        assert invalid_source[0] != 0xA7
        checks+=2;premature_unlocks+=1
    # False hash-preimage instance in short domain: sample unachievable digest in 4-bit domain.
    vals={H(b'leaf',bytes([i]),2) for i in range(16)}
    yy=next(i.to_bytes(2,'big') for i in range(65536) if i.to_bytes(2,'big') not in vals)
    c=build(yy,seed=7777)
    for i in range(16):
        assert open_sig(c,bytes([i])) is None;checks+=1
    print(json.dumps({'fixtures':40,'valid_preimage_partial_signatures':recovered,
                      'independent_fake_rejections':fake_rejected,
                      'multi_preimage_fixtures':multi_preimages,
                      'different_valid_signatures':same_sig_violations,
                      'original_source_invalid_early_unlock':premature_unlocks,
                      'false_preimage_instance_rejections':16,'checks':checks,
                      'status':'TOY hash-preimage OTS component only: NOT generic WKEM; same sigma fails; source validity unbound'},sort_keys=True,indent=2))

if __name__=='__main__':run()
