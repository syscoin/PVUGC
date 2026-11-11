#!/usr/bin/env python3
"""R230 synthetic 80-byte SHA256d parent-header work-source test.

This is not Bitcoin/Syscoin consensus validation or a witness-KEM.
"""
import hashlib, json, struct
from collections import Counter

N=24
TARGET = 1 << 248  # intentionally toy easy target, not nBits consensus
checks=Counter()

def H(*parts):
    d=b'R230-sha-pad-v1\x00'
    for p in parts: d+=len(p).to_bytes(4,'big')+p
    return hashlib.sha256(d).digest()

def sha256d(b): return hashlib.sha256(hashlib.sha256(b).digest()).digest()

def xor(a,b): return bytes(x^y for x,y in zip(a,b))

def check(name, expr):
    if not expr: raise AssertionError(name)
    checks[name]+=1

def child_hash(slot, divergent):
    return sha256d(b'SYNTHETIC-SYS-CHILD'+slot.to_bytes(4,'little')+divergent.to_bytes(4,'little'))

def coinbase_digest(child, anchor, refheight):
    # A SHA256d over toy bytes, NOT serialised real Bitcoin coinbase transaction.
    return sha256d(b'TOY-COINBASE-SYS-TAG'+child+anchor+refheight.to_bytes(4,'little'))

def mine(child,anchor,refheight,stamp):
    merkle=coinbase_digest(child,anchor,refheight)
    version=struct.pack('<I', 0x20000000)
    prev=sha256d(b'fixed-accepted-btc-comparison-anchor')
    ts=struct.pack('<I', 1700000000+stamp)
    bits=struct.pack('<I', 0x2000ffff) # descriptor only; NOT the target used
    for nonce in range(250000):
        hdr=version+prev+merkle+ts+bits+struct.pack('<I',nonce)
        assert len(hdr)==80
        digest=sha256d(hdr)
        if int.from_bytes(digest,'little') < TARGET:
            return hdr, digest, nonce
    raise AssertionError('mining exhausted')

def run():
    anchor=sha256d(b'claim-prefix-common-anchor')
    sigma=H(b'synthetic-native-sigma')
    prefix_pad = H(b'public-prefix', b'\x00')
    # The publicly known prefix is the last byte in raw digest due to little-endian target.
    seal=xor(sigma,prefix_pad)
    parent_digests=[]; child_digests=[]; nonce_total=0
    for slot in range(N):
        child_a=child_hash(slot,0)
        child_b=child_hash(slot,1)
        check('distinct_children',child_a!=child_b)
        a0,h0,n0=mine(child_a,anchor,100,slot*3)
        a1,h1,n1=mine(child_a,anchor,100,slot*3+1)
        b0,hb,nb=mine(child_b,anchor,100,slot*3+2)
        nonce_total+=n0+n1+nb
        for hdr,hd in ((a0,h0),(a1,h1),(b0,hb)):
            check('parent_target',int.from_bytes(hd,'little')<TARGET)
            check('fixed_digest_byte',hd[-1]==0)
            check('prefix_pad_known',H(b'public-prefix',hd[-1:])==prefix_pad)
            check('immediate_public_signature_recovery',xor(seal,H(b'public-prefix',b'\x00'))==sigma)
        check('same_child_multiple_work_certificates',h0!=h1 and a0!=a1)
        check('workid_pad_not_semantic',H(b'work',h0)!=H(b'work',h1))
        check('child_pad_same_work_variant',H(b'child',child_a)==H(b'child',child_a))
        check('child_pad_diff_fork',H(b'child',child_a)!=H(b'child',child_b))
        # A privately mined syntactic parent can satisfy this TARGET without
        # inclusion in Bitcoin best chain or proof of real Syscoin child validity.
        check('work_without_source_admission',int.from_bytes(hb,'little') < TARGET)
        parent_digests.append((h0.hex(),h1.hex(),hb.hex()))
        child_digests.append((child_a.hex(),child_b.hex()))
    # Candidate: seal under a known anchor instead of the unknown future fork.
    # Every challenger can derive the anchor even if R_original is FALSE.
    anchor_seal=xor(sigma,H(b'anchor',anchor))
    check('public_common_anchor_opens_early',xor(anchor_seal,H(b'anchor',anchor))==sigma)
    # Candidate with independent fixed salt: if retained private, the public
    # opener cannot evaluate it; publishing it does not source-gate the pad.
    s=H(b'ceremony-hidden-salt')
    check('public_salt_unconditionally_derived_pad',H(b'salt',s,anchor)==H(b'salt',s,anchor))
    return {
       'run':'R230_work_token_20261111',
       'fixtures':N, 'sha256d_parent_headers':N*3,
       'checks':dict(sorted(checks.items())), 'assertions':sum(checks.values()),
       'aggregate_nonce_attempts_before_wins':nonce_total,
       'first_work_digests':parent_digests[0],
       'first_fork_child_ids':child_digests[0],
       'conclusion':'SOURCE-NATIVE HASH PAD DOES NOT PROVIDE ALL-WITNESS COMMON HIDDEN RELEASE',
       'scope':'synthetic parent coinbase/Merkle only, no Bitcoin/Syscoin validity, no source admission, no native sig or QPT'
    }

if __name__=='__main__':
    print(json.dumps(run(),indent=2,sort_keys=True))
