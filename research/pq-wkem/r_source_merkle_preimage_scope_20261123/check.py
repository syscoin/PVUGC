#!/usr/bin/env python3
"""Synthetic source-Merkle-preimage capsule SCREEN; not an ORIGINAL bridge WKEM."""
import hashlib, json

def sha(x): return hashlib.sha256(hashlib.sha256(x).digest()).digest()
def leaf(i, val): return sha(b'leaf-v1'+bytes([i])+val)
def inner(a,b): return sha(b'node-v1'+a+b)
def tree(values):
    levels=[[leaf(i, v) for i,v in enumerate(values)]]
    while len(levels[-1])>1:
        v=levels[-1];levels.append([inner(v[i],v[i+1]) for i in range(0,len(v),2)])
    return levels

def prove(levels,index):
    siblings=[]; i=index
    for level in levels[:-1]:
        siblings.append(level[i^1]); i//=2
    return siblings

def verify_and_top(idx,val,siblings,root):
    a=leaf(idx,val); i=idx;top=None
    for s in siblings:
        l,r=(s,a) if i%2 else (a,s)
        top=(l,r)
        a=inner(l,r);i//=2
    assert a==root
    return top

def xor(x,y):return bytes(a^b for a,b in zip(x,y))

def run(values):
    levels=tree(values); root=levels[-1][0]
    # Builder knows the Merkle commitment's top children and thus can seal S.
    top=tuple(levels[-2]);K=sha(b'pad-v1'+b''.join(top))
    secret=sha(b'synthetic private cancellation bytes')
    ciphertext=xor(secret,K)
    opens=[]
    for i,val in enumerate(values):
        siblings=prove(levels,i)
        actual_top=verify_and_top(i,val,siblings,root)
        Ki=sha(b'pad-v1'+b''.join(actual_top))
        opens.append(xor(ciphertext,Ki)==secret)
    return {"root":root.hex(),"key":K.hex(),"ciphertext":ciphertext.hex(),"all_open":opens,"secret":secret.hex()}

# Source qualification: ONLY index 3 carrying the exact absence marker is eligible.
false_values=[f'present-{i}'.encode() for i in range(8)]
true_values=false_values.copy();true_values[3]=b'CLAIM-ABSENT'
F=run(false_values);T=run(true_values)
# Attempted relevance repair: hash exactly the target-key sibling path, but
# include a *publicly asserted* empty-leaf marker instead of checking the root
# inside protected release. A real membership proof exposes the same siblings.
def target_path_probe(values):
    levels=tree(values); siblings=prove(levels,3)
    root=levels[-1][0]
    assert verify_and_top(3,values[3],siblings,root)
    K=sha(b'claim-absence-pad-v1'+bytes([3])+b'CLAIM-ABSENT'+b''.join(siblings))
    S=sha(b'synthetic private cancellation bytes'); D=xor(S,K)
    # Attacker is given the genuine complete membership proof, not valid absence.
    bad_status=values[3]!=b'CLAIM-ABSENT'
    forged_K=sha(b'claim-absence-pad-v1'+bytes([3])+b'CLAIM-ABSENT'+b''.join(siblings))
    return {"claimed_nonmembership_is_false":bad_status,"fake_absence_check_does_not_authenticate_root":bad_status,"public_path_pad_recovers_secret":xor(D,forged_K)==S}
PF=target_path_probe(false_values)
assert PF['claimed_nonmembership_is_false'] and PF['public_path_pad_recovers_secret']
assert not any(v==b'CLAIM-ABSENT' for v in false_values)
assert all(F['all_open']) and all(T['all_open'])
assert F['key']!=T['key']
print(json.dumps({
    "scope":"synthetic SHA256d root-preimage release, not authentic Bitcoin/Syscoin or protected Build/Open",
    "false_instance_qualified_witness_exists":False,
    "false_instance_unrelated_authenticated_merkle_proof_unmasks_capability":F['all_open'][0],
    "false_instance_all_eight_paths_unmask":F['all_open'],
    "true_instance_qualified_witness_exists":True,
    "true_instance_all_eight_paths_unmask":T['all_open'],
    "distinct_roots_have_distinct_pads":F['key']!=T['key'],
    "different_source_roots_do_not_provide_one_frozen_key":F['key']!=T['key'],
    "claim_specific_false_membership_relabel_attack":PF,
    "false_root":F['root'],"true_root":T['root']},sort_keys=True,indent=2))
