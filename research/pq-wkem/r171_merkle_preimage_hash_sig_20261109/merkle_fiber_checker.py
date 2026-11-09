#!/usr/bin/env python3
"""Merkle top-preimage release: source-correlation positive toy, ORIGINAL-gating negative control.
No true Bitcoin header/transaction proofs, no native signature, no QPT test.
"""
from hashlib import sha256
from random import Random
import json

def sha256d(b): return sha256(sha256(b).digest()).digest()

def tree(leaves):
    level=list(leaves); levels=[level]
    while len(level)>1:
        assert len(level)%2==0
        level=[sha256d(level[j]+level[j+1]) for j in range(0,len(level),2)]
        levels.append(level)
    return levels

def proof(levels,idx):
    siblings=[]
    for level in levels[:-1]:
        siblings.append((idx&1,level[idx^1]));idx//=2
    return siblings

def derive_top_preimage(leaf,siblings):
    h=leaf;preimage=None
    for direction,sib in siblings:
        preimage=(sib+h) if direction else (h+sib)
        h=sha256d(preimage)
    return h,preimage

def run():
    rng=Random(17190611)
    counts={'trees':0,'valid_leaf_paths':0,'same_top_preimage_across_all_paths':0,'correct_digest_openings':0,
            'nonqualifying_leaf_opens_digest':0,'false_original_rejections':0,'private_root_without_top_pair_is_not_tested_as_hard':0}
    for k in range(35):
        # Fixed-height complete Merkle tree of 8 SHA256d leaves (not actual BTC transaction Merkle rules).
        leaves=[sha256d(b'leaf'+k.to_bytes(4,'big')+i.to_bytes(1,'big')+rng.randbytes(12)) for i in range(8)]
        lv=tree(leaves);root=lv[-1][0]
        derived=[]
        for j,leaf in enumerate(leaves):
            sib=proof(lv,j)
            rr,p=derive_top_preimage(leaf,sib)
            assert rr==root and sha256d(p)==root
            counts['valid_leaf_paths']+=1
            counts['correct_digest_openings']+=1
            derived.append(p)
            # Original relation requires an anchored, tagged special leaf at index 0.
            # A native hashlock on root accepts every other leaf's top pair anyway.
            if j!=0:
                assert j!=0 and sha256d(p)==root
                counts['nonqualifying_leaf_opens_digest']+=1
        assert len(set(derived))==1
        assert derived[0]==lv[-2][0]+lv[-2][1]
        counts['same_top_preimage_across_all_paths']+=1
        # Corrupt one sibling and check Merkle consistency fails.
        sb=proof(lv,0)
        bad=list(sb)
        direction,s=bad[0]
        bad[0]=(direction,bytes([s[0]^1])+s[1:])
        rr,p=derive_top_preimage(leaves[0],bad)
        assert rr!=root
        counts['false_original_rejections']+=1
        counts['trees']+=1
    print(json.dumps({'counts':counts,'conclusion':
     'Any valid path to a fixed SHA256d Merkle root reveals the same top-level 64-byte preimage. '
     'Root-preimage hashlock also opens for nonqualifying leaves and the tree creator knows the top pair before release. '
     'No native SLH domain match, arbitrary-NP compiler, exact frozen signature or future source timing security.'},indent=2,sort_keys=True))

if __name__=='__main__':run()
