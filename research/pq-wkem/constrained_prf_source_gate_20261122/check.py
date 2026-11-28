#!/usr/bin/env python3
"""GGM puncturing as a candidate hash-only LABEL mechanism, NOT source release.
No network evidence, consensus validation, witness encryption or cryptographic security proof.
"""
from hashlib import sha256
import json

def h(domain, s):
    return sha256(domain + len(s).to_bytes(4,'big') + s).digest()

def child(seed, bit):
    return h(b'ggm-child-0' if bit == '0' else b'ggm-child-1', seed)

def bits(x, depth):
    return format(x, f'0{depth}b')

def evaluate_root(seed, path):
    for b in path:
        seed=child(seed, b)
    return h(b'ggm-final', seed)

def puncture(seed, blocked):
    siblings=[]
    for depth,b in enumerate(blocked):
        siblings.append((blocked[:depth]+('0' if b=='1' else '1'), child(seed, '0' if b=='1' else '1')))
        seed=child(seed,b)
    return siblings

def eval_punctured(siblings, blocked, path):
    assert len(path) == len(blocked)
    if path==blocked:
        raise ValueError('punctured point')
    first=next(i for i,(a,b) in enumerate(zip(path,blocked)) if a!=b)
    prefix,seed=siblings[first]
    assert prefix == path[:first+1]
    for b in path[first+1:]:
        seed=child(seed,b)
    return h(b'ggm-final',seed)

def main():
    depth=10
    root=h(b'fixed-synthetic-GGM-key', b'RESEARCH-ONLY')
    blocked=bits(239,depth)
    siblings=puncture(root,blocked)
    passed=0
    for i in range(1<<depth):
        path=bits(i,depth)
        if path==blocked:
            try: eval_punctured(siblings,blocked,path)
            except ValueError: passed+=1
            else: raise AssertionError('excluded path was exposed')
        else:
            assert eval_punctured(siblings,blocked,path)==evaluate_root(root,path)
            passed+=1
    # An arbitrary invented, non-baseline attribute is computable without authenticated source.
    fake=bits(240,depth)
    assert fake!=blocked
    fake_key=eval_punctured(siblings,blocked,fake)
    # A candidate with a fixed public nonpunctured label fails early release:
    fixed=bits(241,depth)
    assert fixed!=blocked
    K=eval_punctured(siblings,blocked,fixed)
    S=h(b'fixed-synthetic-cancel-payload',b'RESEARCH-ONLY')
    ct=bytes(a^b for a,b in zip(S,K))
    early=bytes(a^b for a,b in zip(ct,eval_punctured(siblings,blocked,fixed)))
    assert early==S
    print(json.dumps({
        'model':'synthetic 10-bit attribute index only, NOT original certificate',
        'punctured_leaf_count':1,'public_sibling_seed_count':len(siblings),
        'full_domain_checks':passed,
        'unqualified_nonbaseline_attribute_can_get_ggm_label':len(fake_key)==32,
        'fixed_public_nonbaseline_label_recovers_payload_early':early==S,
        'no_source_gated_compiler':True,'no_original_qpt_reduction':True
    },sort_keys=True,indent=2))

if __name__=='__main__':main()
