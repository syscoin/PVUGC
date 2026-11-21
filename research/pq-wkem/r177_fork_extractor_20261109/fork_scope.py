#!/usr/bin/env python3
"""R177: synthetic SHA-linked fork scope and raw-key bypass controls.
NOT real Bitcoin/AuxPoW, actual source qualification, PQ proof or witness KEM.
"""
import hashlib, json
from collections import Counter

C=Counter()
def ok(q,label):
    if not q: raise AssertionError(label)
    C[label]+=1

def h(domain,*parts):
    b=domain+b''.join(len(p).to_bytes(4,'big')+p for p in parts)
    return hashlib.sha256(b).digest()

def num(x):return x.to_bytes(4,'big')
def tag_height(n):return ((n-6)//10)*10
def tag_ready(d):return ((d+9)//10)*10+6
def baseline_min(hrel,k):return max(tag_ready(hrel),hrel+k-1)

def histories(d,seed,tip=120):
    A=[(bytes(32),b'genesis',h(b'child',num(0),bytes(32),b'genesis'))]
    for i in range(1,tip+1):
        p=A[-1][2];n=h(b'A',num(seed),num(i));A.append((p,n,h(b'child',num(i),p,n)))
    B=A[:d]
    for i in range(d,tip+1):
        p=B[-1][2];n=h(b'B',num(seed),num(i));B.append((p,n,h(b'child',num(i),p,n)))
    return A,B

def valid(chain,n,anchor,anchor_hash):
    if n>=len(chain) or chain[anchor][2]!=anchor_hash:return False
    for i,(p,nonce,digest) in enumerate(chain[:n+1]):
        if i and p!=chain[i-1][2]:return False
        if h(b'child',num(i),p,nonce)!=digest:return False
    return True

def fork(A,nA,B,nB,anchor,k):
    if not valid(A,nA,anchor,A[anchor][2]) or not valid(B,nB,anchor,A[anchor][2]):return None
    low=min(tag_height(nA),tag_height(nB))
    if low<=anchor or A[low][2]==B[low][2]:return None
    d=next((i for i in range(anchor+1,low+1) if A[i][2]!=B[i][2]),None)
    if d is None or nA-d+1<k or nB-d+1<k:return None
    return d

def main():
    anchor=20
    for rel in range(21,56):
        for k in (1,7,12,22):
            na=baseline_min(rel,k)
            ok(tag_height(na)>=rel and na-rel+1>=k,'mature_baseline')
            ok(tag_height(na-1)<rel or na-rel<k,'minimal_baseline')
            for d in range(anchor+1,rel+1):
                A,B=histories(d,7*rel+11*d)
                nb=max(tag_ready(d),d+k-1)
                ok(fork(A,na,B,nb,anchor,k)==d,'relevant_fork_single_alternate')
                ok(fork(A,na,A,nb,anchor,k) is None,'workid_variation_same_child')
            # No baseline observation with tag below rel covers a fork at rel.
            A,B=histories(rel,13*rel+k)
            early=tag_ready(rel)-1
            nb=max(tag_ready(rel),rel+k-1)
            ok(fork(A,early,B,nb,anchor,1) is None,'immature_tag_blind_spot')
            if tag_ready(rel)-rel+1<k:
                ok(fork(A,tag_ready(rel),B,nb,anchor,k) is None,
                   'immature_lightclient_depth_blind_spot')
            # Tag discrepancy beyond relevant prefix cannot be a safe veto.
            for d in range(rel+1,tag_height(na)+1):
                A,B=histories(d,97*rel+d)
                nb=max(tag_ready(d),d+k-1)
                ok(fork(A,na,B,nb,anchor,1)==d,'tag_mismatch_can_be_irrelevant')
                ok(not (fork(A,na,B,nb,anchor,k) is not None and d<=rel),
                   'first_divergence_guard_rejects_irrelevant_fork')
            d=tag_height(na)+1
            A,B=histories(d,101*rel+k)
            nb=max(tag_ready(d),d+k-1)
            ok(fork(A,na,B,nb,anchor,1) is None,'fixed_baseline_misses_later_fork')
    # A full-public raw hash-pad table keyed by a guessed divergence descriptor
    # trivially reveals a fixed secret without any authentic source witness.
    key=h(b'K',b'fixed');context=h(b'claim',b'withdrawal')
    for slot in range(4):
        for bit in (0,1):
            selector=num(slot)+num(bit)
            pad=h(b'pad',context,selector)
            enc=bytes(x^y for x,y in zip(key,pad))
            got=bytes(x^y for x,y in zip(enc,h(b'pad',context,selector)))
            ok(got==key,'fake_selector_raw_key_recovery')
    return {'name':'R177 claim-relevant one-sided tag completeness',
       'checks':sum(C.values()),'groups':dict(sorted(C.items())),
       'source_sha256':hashlib.sha256(open(__file__,'rb').read()).hexdigest(),
       'scope':'synthetic SHA-linked histories, NOT actual AuxPoW/Bitcoin qualification or any release proof'}
if __name__=='__main__':print(json.dumps(main(),indent=2,sort_keys=True))
