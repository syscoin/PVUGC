#!/usr/bin/env python3
"""R233 fixed-outpoint capability persistence across Bitcoin reorgs.

Toy fixed-SegWit tx serializer and source-policy state-machine. No actual Bitcoin
script/native PQ signatures, PoW, witness-KEM, or consensus admission checker.
An 'opened' capability here is a conditional premise, not a release algorithm.
"""
import hashlib, itertools, json
from collections import Counter

C=Counter()
def ck(b,label):
    assert b,label
    C[label]+=1

def h256(b):return hashlib.sha256(hashlib.sha256(b).digest()).digest()
def le32(x):return x.to_bytes(4,'little')
def le64(x):return x.to_bytes(8,'little')
def cs(n):
    assert 0<=n<253
    return bytes([n])

def template(witness):
    # One-input one-output synthetic-but-standard-format SegWit v0 transaction.
    # Prior output fixed; witness changes only after marker/flag.
    v=le32(2)
    txin=bytes.fromhex('11'*32)+le32(3)+cs(0)+le32(0xfffffffd)
    txout=le64(150000)+cs(34)+bytes.fromhex('0020'+'22'*32)
    old=v+cs(1)+txin+cs(1)+txout+le32(0)
    wit=cs(len(witness))+b''.join(cs(len(w))+w for w in witness)
    new=v+b'\x00\x01'+cs(1)+txin+cs(1)+txout+wit+le32(0)
    return {'txid':h256(old).hex(),'wtxid':h256(new).hex(),
            'outpoint':h256(old).hex()+':0','stripped':old,'whole':new}

def run():
    A=template([b'one-notary signature',b'ASSERT:burn-is-missing'])
    B=template([b'one-notary signature',b'ASSERT:burn-correct'])
    ck(A['txid']==B['txid'],'same_txid_different_witness')
    ck(A['wtxid']!=B['wtxid'],'distinct_wtxids')
    ck(A['outpoint']==B['outpoint'],'same_outpoint')
    # A canonical fixed cancellation message commits to the outpoint and a
    # claim-scoped refund script. HMAC stand-in models the byte identity of a
    # PRE-SIGNED authorization; it is not a native signature implementation.
    M=h256((A['outpoint']+'|refund=owner|claim=42').encode())
    key=bytes.fromhex('24'*32)
    import hmac
    sigma=hmac.new(key,M,hashlib.sha256).digest()
    ck(hmac.compare_digest(sigma,hmac.new(key,M,hashlib.sha256).digest()),
       'one_fixed_authorization')
    # Even domain-separated capsules can't retract the native sigma after
    # disclosure; a capsule ID is not an input to the native signature.
    capA=h256(b'capsule-A'+bytes.fromhex(A['wtxid']))
    capB=h256(b'capsule-B'+bytes.fromhex(B['wtxid']))
    ck(capA!=capB,'capsule_ids_distinct')
    ck(hmac.compare_digest(sigma,hmac.new(key,M,hashlib.sha256).digest()),
       'native_does_not_check_capsule_id')

    # For every ordered transition of two histories, each with any of the
    # 2^3 truth vectors for Rwork,Rburn,Rfork, model capability retrieval once
    # there exists ONE admitted ORIGINAL witness. This is a conditional
    # logical simulation, not implementation of Build/Open.
    V=list(itertools.product([False,True],repeat=3))
    nonmono=0
    for x,y in itertools.product(V,V):
        released=any(x)
        allowed_now=any(y)
        # By Boolean algebra, the key persists after release, even if the
        # source predicate later becomes false.
        if released and not allowed_now:
            nonmono+=1
            ck(True,'nonmonotone_reorg_risk')
        # Repair 1 is ever-fault slot semantics (monotone latch). It is safe
        # only IF the policy intentionally allows permanence of any formerly
        # qualifying evidence, including later orphaned histories.
        evergreen=any(x) or any(y)
        ck(not released or evergreen,'ever_fault_latch_aligns_bearer_reuse')
        # An activation-specific OUTPOINT (not merely wtxid in ciphertext)
        # can make A's native sigma inapplicable to B. This is hypothetical:
        # the endpoint must actually bind a different txid/outpoint.
        changed_outpoint=h256(bytes.fromhex(A['txid'])+bytes.fromhex(B['wtxid']))
        different_M=h256(changed_outpoint+b'|refund=owner|claim=42')
        ck(M!=different_M,'different_outpoint_changes_native_message')
        # Repair 2 via PUBLIC off-chain wtxid marker alone does NOT change M.
        ck(A['outpoint']==B['outpoint'] and M==h256((B['outpoint']+'|refund=owner|claim=42').encode()),
           'wtxid_marker_no_native_enforcement')
    ck(nonmono==7,'exact_bad_history_pairs') # seven nonempty x, all-false y
    # A stronger 3-state history: valid challenge in S0, no challenge in S1,
    # valid again in S2. Release cannot be revoked between states.
    histories=[(True,False,False),(False,False,False),(False,False,True)]
    hold=False
    for ix,world in enumerate(histories):
        hold |= any(world)
        ck(hold,'monotone_capability_memory')
        if ix==1:
            ck(hold and not any(world),'stale_after_reorg')
    return {'run':'R233_20261111', 'assertions':sum(C.values()),
            'groups':dict(sorted(C.items())), 'nonmonotone_pairs':nonmono,
            'txid':A['txid'], 'wtxid_a':A['wtxid'], 'wtxid_b':B['wtxid'],
            'limitations':['no actual consensus or native signatures','conditional ideal release event is not a construction','no Build/Open','no QPT simulation']}
if __name__=='__main__':print(json.dumps(run(),sort_keys=True,indent=2))
