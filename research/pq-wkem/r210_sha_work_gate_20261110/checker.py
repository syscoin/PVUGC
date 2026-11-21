#!/usr/bin/env python3
"""R210: genuine SHA256d of synthetic 80-byte parent headers.

This tests an ORIGINAL-work-dependent *candidate* and its bypass. It is NOT
full Bitcoin difficulty/contextual validation, AuxPoW, or a PQ release.
"""
from __future__ import annotations
import hashlib,json,struct
from itertools import combinations
from collections import Counter

N=1<<16
D=5 # toy 5-bit work target, not Bitcoin chain difficulty
SFX=10
C=Counter()

def h(*parts: bytes)->bytes:
    encoded=b''.join(len(p).to_bytes(4,'big')+p for p in parts)
    return hashlib.sha256(encoded).digest()
def h2(x: bytes)->bytes:
    return hashlib.sha256(hashlib.sha256(x).digest()).digest()
def xor(a:bytes,b:bytes)->bytes:
    assert len(a)==len(b)
    return bytes(x^y for x,y in zip(a,b))
def ck(b:bool,label:str):
    if not b: raise AssertionError(label)
    C[label]+=1

def prefix(digest: bytes, nbits=D) -> int:
    # sha256d output displayed as a big-endian work integer after byte reversal.
    # A toy target 2^(256-D) is used for this experiment.
    return int.from_bytes(digest,'little') >> (256-nbits)

def header(context: bytes, nonce:int) -> bytes:
    # Bitcoin-like serialized 80-byte header with synthetic, fixed prev/root/time.
    prev=h(b'original-btc-anchor',context)
    merkle=h(b'syscoin-child-auxpow-merkle',context)
    return struct.pack('<I32s32sIII',0x20000000,prev,merkle,1_700_000_000,0x207fffff,nonce)

def bits_after_prefix(digest:bytes,n=10):
    x=int.from_bytes(digest,'little')
    return [(x>>(255-D-i))&1 for i in range(n)]

def quadratic_row(bits):
    # Monomials in 10 *unconstrained* digest suffix bits (degree<=2).
    return 1 | sum(b<<(i+1) for i,b in enumerate(bits)) | sum((bits[i]&bits[j])<<(11+k) for k,(i,j) in enumerate(combinations(range(10),2)))

def binary_rank(rows):
    piv={}
    for r in rows:
        while r:
            j=r.bit_length()-1
            if j not in piv:
                piv[j]=r; break
            r^=piv[j]
    return len(piv)

def run_one(seed:int):
    context=h(b'withdrawal-context',seed.to_bytes(4,'big'))
    accepted=[]
    for nonce in range(N):
        raw=header(context,nonce)
        digest=h2(raw)
        if prefix(digest)==0: accepted.append((nonce,raw,digest))
    ck(len(accepted)>80,'adequate_toy_witnesses')
    # Simulated precommitted frozen release target; no native signature is made.
    secret=h(b'capsule-K',context)
    sigma=h(b'fake-native-cancel-signature',context)
    pad=h(b'work-prefix-pad',context,bytes([D]),bytes([0]))
    sealed=xor(secret,pad)
    ciphertext=xor(sigma,h(b'sig-pad',secret,context))
    check=h(b'checking-key',secret,context)
    for nonce,raw,digest in accepted:
        ck(prefix(digest)==0,'sha256d_work_fixture_accepts')
        recovered=xor(sealed,h(b'work-prefix-pad',context,bytes([D]),bytes([prefix(digest)])))
        ck(recovered==secret,'all_qualifying_work_recovers_same_K')
        ck(h(b'checking-key',recovered,context)==check,'checking_key_agrees')
    # Full-view bypass: an attacker does not need to mine the corresponding header.
    synthetic_digest=bytes(32) # chosen apparent work hash, no SHA preimage
    outsider=xor(sealed,h(b'work-prefix-pad',context,bytes([D]),bytes([prefix(synthetic_digest)])))
    ck(outsider==secret,'raw_capsule_opens_without_header')
    ck(xor(ciphertext,h(b'sig-pad',outsider,context))==sigma,'raw_capsule_reveals_frozen_capability')
    # Nonlinear/higher degree public post-digest selector also unconditionally
    # exposes its fixed value on the all-zero accepted digest.
    nonlinear=lambda d:h(b'nonlinear',context,bytes([prefix(d)]),bytes([prefix(d)**2%256]))
    ck(nonlinear(synthetic_digest)==nonlinear(accepted[0][2]),'public_nonlinear_prefix_same')
    # One special source-bound input recovers, but all OTHER accepted sources
    # produce different pads, breaking the demanded all-witness property.
    n0,raw0,d0=accepted[0]
    fullmask=h(b'full-sha-preimage',context,raw0,d0)
    fullsealed=xor(secret,fullmask)
    for nonce,raw,digest in accepted[1:]:
        recovered=xor(fullsealed,h(b'full-sha-preimage',context,raw,digest))
        ck(recovered!=secret,'full_header_mask_breaks_completeness')
    # Known pre-claim anchor is shared by every source; is publicly reconstructible.
    public_anchor=h(b'original-btc-anchor',context)
    anchorpad=h(b'anchor-pad',context,public_anchor)
    anchorsealed=xor(secret,anchorpad)
    ck(xor(anchorsealed,h(b'anchor-pad',context,public_anchor))==secret,
       'shared_anchor_opens_without_competitor')
    # Degree<=2 suffix-polynomial rank illustrates output-suffix variability
    # among genuine SHA256d work certificates. This is not a security lemma
    # about all of SHA or a statement-independent restriction.
    rows=[quadratic_row(bits_after_prefix(digest,SFX)) for _,_,digest in accepted]
    ck(binary_rank(rows)==1+SFX+(SFX*(SFX-1)//2),'toy_suffix_degree2_full_rank')
    return {'seed':seed,'qualifying_header_count':len(accepted),
            'first_qualifying_nonce':n0,'sha256d_first':d0.hex(),
            'degree2_suffix_rank':binary_rank(rows),
            'candidate':'prefix-pad common key but publicly extractable; header-pad not all-witness'}

if __name__=='__main__':
    cases=[run_one(i) for i in range(3)]
    out={'run':'R210_SHA_WORK_GATE_20261110',
         'cases':cases,'functional_assertions':sum(C.values()),
         'assertions_by_label':dict(sorted(C.items())),
         'scope':'SHA256d synthetic Bitcoin-format parent headers; toy target D=5; NOT full original-source qualification or cryptographic WE',
         'security_result':'raw public gate opens without header; selected-header repair violates every-witness correctness',
         'tool_provenance':'Python stdlib local run; no QPT cryptanalysis, no BTC mining validation'}
    print(json.dumps(out,sort_keys=True,indent=2))
