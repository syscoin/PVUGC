#!/usr/bin/env python3
"""R209 authenticated-path/future-token carrier regression; NOT ORIGINAL source/WKEM."""
import hashlib, json
from collections import Counter

stats=Counter()
def h(tag, *parts):
    payload=len(tag).to_bytes(2,'big')+tag
    for p in parts: payload+=len(p).to_bytes(4,'big')+p
    return hashlib.sha256(payload).digest()

def xor(a,b): return bytes(x^y for x,y in zip(a,b))

def check(predicate, label):
    if not predicate: raise AssertionError(label)
    stats[label]+=1

def lh(pos, value): return h(b'R209/leaf', pos.to_bytes(4,'big'), value)
def par(a,b): return h(b'R209/node', a,b)

class AuthTree:
    def __init__(self, leaves):
        assert len(leaves) > 1 and len(leaves)&(len(leaves)-1)==0
        self.leaves=leaves
        self.L=[[lh(i,v) for i,v in enumerate(leaves)]]
        while len(self.L[-1])>1:
            prev=self.L[-1]; self.L.append([par(prev[i],prev[i+1]) for i in range(0,len(prev),2)])
        self.root=self.L[-1][0]
    def prove(self, i):
        ret=[]
        for level in self.L[:-1]:
            ret.append(level[i^1]);i//=2
        return ret

def verify(root,i,leaf,proof,depth):
    if len(proof)!=depth:return False
    digest=lh(i,leaf)
    for s in proof:
        if len(s)!=32:return False
        digest=par(s,digest) if i&1 else par(digest,s)
        i//=2
    return digest==root

def source_leaf(seed,i):return h(b'R209/synthetic-child', seed, i.to_bytes(4,'big'))

def label(leaf):return h(b'R209/label',leaf)

def public_pad(lA,lB):return h(b'R209/pair',lA,lB)

def trial(seed):
    # Merkle roots are synthetic SOURCE HISTORY COMMITMENTS, NOT PoW or deployed consensus.
    baseline=[source_leaf(seed.to_bytes(4,'big'),i) for i in range(16)]
    conflict_idx=7
    B=[]
    for variant in range(3):
        bs=baseline[:]
        bs[conflict_idx]=h(b'R209/alternative',seed.to_bytes(4,'big'),bytes([variant]))
        B.append(AuthTree(bs))
    A=AuthTree(baseline)
    check(all(verify(A.root,i,baseline[i],A.prove(i),4) for i in range(16)), 'baseline_authentication')
    for b in B:
        check(verify(b.root,conflict_idx,b.leaves[conflict_idx],b.prove(conflict_idx),4),'alternative_authenticated_under_own_root')
        check(not verify(A.root,conflict_idx,b.leaves[conflict_idx],b.prove(conflict_idx),4),'cross_root_proof_rejected')
        check(not verify(A.root,conflict_idx,b.leaves[conflict_idx],A.prove(conflict_idx),4),'same_root_conflict_not_openable')
        check(A.root!=b.root,'distinct_roots')
    K=h(b'R209/frozen-secret',seed.to_bytes(4,'big'))
    lA=label(baseline[conflict_idx])
    labels=[label(b.leaves[conflict_idx]) for b in B]
    # Fixed initial future candidate: only that candidate recovers K.
    row=xor(K,public_pad(lA,labels[0]))
    check(xor(row,public_pad(lA,labels[0]))==K,'preselected_future_correct')
    for i in (1,2):check(xor(row,public_pad(lA,labels[i]))!=K,'preselected_future_incomplete')
    # Any input-independent wildcard / normalized pad is publicly recoverable before event.
    wildcard=h(b'R209/public-wildcard')
    row2=xor(K,public_pad(lA,wildcard))
    check(xor(row2,public_pad(lA,wildcard))==K,'wildcard_public_early_open')
    # If Build somehow knows every future B and publishes a row per B,
    # any one prepublished row and its PUBLIC selector opens K independent of authentication.
    for b in B:
        lab=label(b.leaves[conflict_idx]); r=xor(K,public_pad(lA,lab))
        check(xor(r,public_pad(lA,lab))==K,'public_indexed_row_early_open')
    # Source root alone carries no share: a made-up token with no Merkle proof is rejected.
    made_up=h(b'R209/fake-value',seed.to_bytes(4,'big'))
    check(not verify(A.root,conflict_idx,made_up,A.prove(conflict_idx),4),'forged_merkle_leaf_rejected')
    # Even though all roots are real for their own synthetic trees, their labels
    # differ, and a static E cannot be tied to one K for all future paths.
    check(len({r for r in labels})==len(labels),'distinct_future_labels')
    return A,B,K

def public_table_trial():
    # Tiny 8-bit COMPLETE table of candidate values. Not Bitcoin work.
    baseline=b'baseline'
    K=h(b'R209/table-secret')
    lA=label(baseline)
    rows=[]
    for b in range(256):
        u=bytes([b]); lab=label(u)
        rows.append(xor(K,public_pad(lA,lab)))
    # Publish all 256 rows as a key recovery table -> key is publicly recoverable
    # using arbitrary syntactic b, regardless of whether b authenticates as source.
    for b in range(256):
        u=bytes([b]); recovered=xor(rows[b],public_pad(lA,label(u)))
        check(recovered==K,'enumerated_table_opens_without_source')
    # Committing to row table root does NOT make secret row value derivable from root.
    table=AuthTree(rows)
    check(verify(table.root,137,rows[137],table.prove(137),8),'table_root_authenticates_known_row')
    check(not verify(table.root,137,b'guessed-row',table.prove(137),8),'table_root_rejects_unknown_row')
    # A public deterministic evaluator for table entries equivalent to rows[]
    # also opens early; making the evaluator seed private prevents witness-only opening.
    return table.root.hex()

def run():
    for seed in range(24):trial(seed)
    root=public_table_trial()
    return {'run':'R209-source-Merkle-gate', 'assertions':sum(stats.values()),
            'groups':dict(sorted(stats.items())),'synthetic_table_merkle_root':root,
            'source_sha256':hashlib.sha256(open(__file__,'rb').read()).hexdigest(),
            'limitations':['synthetic authenticated Merkle trees not Bitcoin or Syscoin histories',
                           'no original source verifier or authenticated BTC anchoring',
                           'no QPT security proof or native signature implementation',
                           'no secure cryptographic Build/Open mechanism']}

if __name__=='__main__':print(json.dumps(run(),sort_keys=True,indent=2))
