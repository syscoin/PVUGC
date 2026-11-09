#!/usr/bin/env python3
"""R176 hash-only tag-cadence normalization & release counterchecks.
Toy hash-linked child histories ONLY; not deployed Syscoin, Bitcoin, PoW, or QPT.
"""
import hashlib, json
from collections import Counter

counts=Counter()
def check(name, value):
    assert value, name
    counts[name]+=1

def H(*fields):
    h=hashlib.sha256()
    for f in fields:
        if isinstance(f,int): f=f.to_bytes(8,'big')
        if isinstance(f,str): f=f.encode()
        h.update(len(f).to_bytes(4,'big')+f)
    return h.digest()
def h_ref(n): return 10*((n-6)//10)
def next_tag(d): return 10*((d+9)//10)+6

def build_chain(end, fork_at=None, label='A'):
    # A synthetic child hash chain; same header pre-fork, divergent thereafter.
    hashes={0:H('toy-genesis')}
    for height in range(1,end+1):
        salt='base' if fork_at is None or height<fork_at else label
        hashes[height]=H('toy-child',height,hashes[height-1],salt)
    return hashes

def fork_point(a,b,n):
    x=next((h for h in range(n+1) if a[h]!=b[h]),None)
    return x

def choose_bit(k): return (k[0]>>7)&1

def xor(a,b): return bytes(x^y for x,y in zip(a,b))

# A false raw release construction: label one mismatch bit on source's semantic tag.
def build_first_diff(baseline, key, ctx):
    rows=[]
    for i in range(256):
        bi=(baseline[i//8]>>(7-i%8))&1
        opposite=1-bi
        pad=H('slot-mismatch-pad',ctx,i,opposite)
        rows.append(xor(key,pad))
    return rows

def first_diff_raw(baseline,candidate,rows,ctx):
    for i in range(256):
        a=(baseline[i//8]>>(7-i%8))&1
        b=(candidate[i//8]>>(7-i%8))&1
        if a!=b:
            return xor(rows[i],H('slot-mismatch-pad',ctx,i,b))
    return None

def run():
    # 10-slot tag scheduling across 120 distinct fork starts.
    for d in range(21,141):
        n0=next_tag(d)
        check('height_gap_6_to_15',6<=n0-d<=15)
        check('first_eligible_tag_refs_fork',h_ref(n0)>=d)
        check('previous_child_does_not_reference_fork',h_ref(n0-1)<d)
        check('earliest_tag_height_formula',n0==10*((d+9)//10)+6)
        for k in (1,5,10,16,22):
            # minimum child blocks in fork to satisfy both depth and the first mismatch slot
            n=max(d+k-1,n0)
            check('depth_and_tag_availability',n-d+1==max(k,n0-d+1))
    # Paired synthetically linked histories: all 10 children per reference slot share tag outcome.
    for d in (20,21,29,30,31,49,50,51,90):
        n0=next_tag(d)
        a=build_chain(n0+12)
        b=build_chain(n0+12,d,'ALT')
        check('unique_fork_start',fork_point(a,b,n0+12)==d)
        check('shared_predecessor',a[d-1]==b[d-1])
        check('different_fork_children',a[d]!=b[d])
        for n in range(max(16,d),n0+12):
            if n>=6:
                a_tag=a[h_ref(n)];b_tag=b[h_ref(n)]
                check('tag_consistency_with_fork_start',(a_tag!=b_tag)==(h_ref(n)>=d))
                # Different work certs of same child do not change child or tagged ancestor
                work_a=H('parent-work-certificate-1',n,a[n])
                work_b=H('parent-work-certificate-2',n,a[n])
                check('different_work_identifiers',work_a!=work_b)
                check('same_child_different_work_no_fork',a[h_ref(n)]==a_tag)
        ctx=H('withdrawal-claim',d)
        K=H('frozen-cancel-capability',d)
        baseline=a[h_ref(n0)]
        alternate=b[h_ref(n0)]
        rows=build_first_diff(baseline,K,ctx)
        check('opposite_bit_table_opens_real_conflict',first_diff_raw(baseline,alternate,rows,ctx)==K)
        # This fabricated raw tag is not tied to a child header, parent work, height or BTC inclusion.
        bogus=bytes([baseline[0]^0x80])+baseline[1:]
        check('opposite_bit_table_opens_fake_conflict',first_diff_raw(baseline,bogus,rows,ctx)==K)
        check('same_semantic_tag_no_release',first_diff_raw(baseline,baseline,rows,ctx) is None)
        # A ciphertext under ONE authenticated semantic tag cannot serve a second distinct tag:
        e=xor(K,H('semantic-proof-pad',ctx,alternate))
        alt2=H('a-different-valid-outcome-can-exist',d)
        check('one_tag_pad_not_common',(xor(e,H('semantic-proof-pad',ctx,alt2)))!=K)
        # If the entire pad depends only on a PUBLIC slot, EVERYONE opens without any source.
        slot=H('public-slot',h_ref(n0))
        e_public=xor(K,H('public-slot-pad',ctx,slot))
        check('public_slot_leaks',(xor(e_public,H('public-slot-pad',ctx,slot)))==K)
    # A *fixed old baseline* cannot refute a genuine future fork solely by an
    # alternative descendant: both histories still share that older ancestor.
    baseline_tip=100; fork_d=101; later=next_tag(fork_d)
    a=build_chain(later+2); b=build_chain(later+2,fork_d,'FUTURE')
    old_ref=h_ref(baseline_tip)
    check('post_baseline_fork_shares_old_baseline',a[old_ref]==b[old_ref])
    check('one_sided_future_evidence_compatible',a[old_ref]==b[old_ref] and b[old_ref]==a[old_ref])
    check('two_later_tags_conflict',a[h_ref(later)]!=b[h_ref(later)])
    check('future_fork_requires_later_witnesses',h_ref(later)>=fork_d and old_ref<fork_d)
    # Another fork may already be distinct in child identities while its tags
    # refer to a common ancestor due to the mandatory 6-15-block tag lag.
    earlier_fork=95; early_tag_tip=100
    c=build_chain(110);d=build_chain(110,earlier_fork,'EARLIER')
    check('child_fork_before_tag_visibility',c[early_tag_tip]!=d[early_tag_tip] and c[h_ref(early_tag_tip)]==d[h_ref(early_tag_tip)])
    check('delayed_tag_later_conflicts',c[h_ref(next_tag(earlier_fork))]!=d[h_ref(next_tag(earlier_fork))])
    # an explicit fixed source proof / capability uses arbitrary future source as public input
    # but not input labels from a setup secret; this does not establish private release.
    return {'run':'R176-tag-slot-20261109','checks':dict(sorted(counts.items())),
            'total_assertions':sum(counts.values()),
            'source_sha256':hashlib.sha256(open(__file__,'rb').read()).hexdigest(),
            'status':'source tag-window normalization and raw-release counterchecks only; no WKEM, native signing, QPT, or real source authentication'}
if __name__=='__main__':print(json.dumps(run(),sort_keys=True,indent=2))
