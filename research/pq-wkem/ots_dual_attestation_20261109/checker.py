#!/usr/bin/env python3
"""Synthetic source-attestation hash-release experiment. Not BTC/SYS evidence or secure generic NP WKEM."""
import hashlib, random, json, sys

def h(dom, data):
    return hashlib.sha256(dom + len(data).to_bytes(4,'big') + data).digest()
def mask(k,n):
    return hashlib.shake_256(b'SIG-MASK-v1'+k).digest(n)
def xor(a,b):
    assert len(a)==len(b)
    return bytes(x^y for x,y in zip(a,b))

def setup(seed):
    # Tiny seeded deterministic fixtures; real setup needs crypto-secure randomness.
    a=h(b'a',seed); b=h(b'b',seed); k=xor(a,b)
    sigma=h(b'native-test',seed)+h(b'other',seed)+h(b'last',seed)
    context=h(b'context',seed)
    c={"ctx":context,"vk0":h(b'OTS0'+context,a),"vk1":h(b'OTS1'+context,b),"ck":h(b'keycheck'+context,k),"D":xor(sigma,mask(k,len(sigma)))}
    return c,(a,b),k,sigma

def public_open(c,e0,e1):
    if h(b'OTS0'+c['ctx'],e0)!=c['vk0']:return None
    if h(b'OTS1'+c['ctx'],e1)!=c['vk1']:return None
    k=xor(e0,e1)
    if h(b'keycheck'+c['ctx'],k)!=c['ck']:return None
    return xor(c['D'],mask(k,len(c['D'])))

def run():
    n=64; count=0; checks=0; rejected=0; recovered=0; bypasses=0
    rng=random.Random(981127)
    for j in range(n):
        seed=j.to_bytes(4,'big'); c,(a,b),k,sigma=setup(seed)
        # Correct release requires both cryptographic branch preimages.
        assert public_open(c,a,b)==sigma;checks+=1;recovered+=1
        # Straight-line extractor: any exact K recovered after a single tag-0 token
        # yields tag-1 token, regardless of how the adversary found K.
        extracted=xor(k,a)
        assert extracted==b and h(b'OTS1'+c['ctx'],extracted)==c['vk1'];checks+=1
        # Fake source: both preimages can be released privately without authenticated chain evidence.
        # Deliberately give arbitrary fake child header/noncanonical proof and ignore post-hoc verifier.
        bad_header=h(b'fake-child',seed)
        source_valid=lambda _hdr: False  # no original admissible anchored source exists
        assert not source_valid(bad_header);checks+=1
        assert public_open(c,a,b)==sigma;checks+=1;bypasses+=1
        assert public_open(c,a,h(b'forged-other',seed)) is None;checks+=1;rejected+=1
        assert public_open(c,h(b'forged-first',seed),b) is None;checks+=1;rejected+=1
        assert public_open(c,b,a) is None;checks+=1;rejected+=1
        # Distinct arbitrary headers with same branch-signing token do not satisfy actual anchoring.
        for q in range(3):
            mb=rng.getrandbits(128).to_bytes(16,'big')
            assert not source_valid(mb);checks+=1
            assert public_open(c,a,b)==sigma;checks+=1
    # 256-bit secret check digest can always be brute force inverted given unbounded time; no QPT measured.
    return dict(fixtures=n, assertions=checks, honest_releases=recovered, wrong_preimage_rejections=rejected, fake_source_releases=bypasses, single_disclosure_key_to_second_preimage_extractions=n, claim="restricted opposing-authentication-secret carrier ONLY; source validity and malformed signer bypass not bound", security="not generic NP; malicious signer knows both preimages; no source anchoring; no QPT proof", reproducible_seed=981127)
if __name__=='__main__':print(json.dumps(run(),indent=2,sort_keys=True))
