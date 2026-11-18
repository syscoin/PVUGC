#!/usr/bin/env python3
"""Exact, bounded membership-trie cover for a SHA256 target predicate.
Not a bridge or WKEM checker; a constructibility filter for GGM-prefix key constraints.
"""
import hashlib,json,math

def cover(n,d,domain):
    valid=[]
    for j in range(1<<n):
        m=j.to_bytes((n+7)//8, 'big')
        v=hashlib.sha256(hashlib.sha256(domain+m).digest()).digest()
        valid.append(int.from_bytes(v,'big') < (1<<(256-d)))
    full_by_k={k:0 for k in range(1,n+1)}
    def visit(left,right,k):
        if right-left == 1:
            return valid[left],int(valid[left])
        mid=(left+right)//2
        ok_l,cl=visit(left,mid,k-1)
        ok_r,cr=visit(mid,right,k-1)
        if ok_l and ok_r:
            full_by_k[k]+=1
            return True,1
        return False,cl+cr
    _,covered=visit(0,1<<n,n)
    good=sum(valid)
    paired=full_by_k[1]
    assert covered <= good
    assert covered == good-sum(full_by_k.values())
    assert covered==0 or good>0
    # For a prefix-free exact cover, every key denotes only permitted leaves.
    return {'n':n,'d':d,'valid_inputs':good,'minimum_exact_prefix_keys':covered,
            'valid_fraction':good/(1<<n),'key_to_valid_ratio':covered/good if good else None,
            'adjacent_valid_pairs':paired, 'full_subtree_merges':sum(full_by_k.values()), 'full_subtree_sizes':{str(k):v for k,v in full_by_k.items() if v}, 'ideal_random_expected_keys':(1<<n)*(2**-d)-sum((1<<(n-k))*(2**(-d*2**k)) for k in range(1,n+1))}

cases=[]
for n,d in [(12,3),(14,4),(16,4),(16,6)]:
    cases.append(cover(n,d,b'R352-sha-trie/'+bytes([n,d])))
print(json.dumps({'model':'bounded 12-16 bit synthetic header encodings; actual SHA256d computation; random-function expectation is an idealization','cases':cases},sort_keys=True,indent=2))
