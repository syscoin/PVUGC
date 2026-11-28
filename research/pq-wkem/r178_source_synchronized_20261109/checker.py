#!/usr/bin/env python3
"""R178: hash-only SSHT candidate boundary, SHA256d synthetic Bitcoin headers.

No real Bitcoin acceptance, real Syscoin AuxPoW/coinbase Merkle,
anchor admission, real source qualification, or QPT experiment.
"""
import hashlib, json

def sha(b): return hashlib.sha256(b).digest()
def dsha(b): return sha(sha(b))
def H(label, *xs):
    return sha(label + b''.join(len(x).to_bytes(4,'big')+x for x in xs))
def xor(a,b):return bytes(x^y for x,y in zip(a,b))
def mk_parent(child_id, nonce, salt):
    # 80-byte syntactically sized parent header; Merkle root synthetic,
    # not authenticated to a true Bitcoin coinbase or chain.
    merkle=dsha(b'coinbase' + child_id + salt)
    return (1).to_bytes(4,'little')+sha(b'anchor')+merkle+(1600000000).to_bytes(4,'little')+(0x1f0fffff).to_bytes(4,'little')+nonce.to_bytes(4,'little')
def mine(child_id, salt, count=2, free_bits=8):
    out=[]
    # model 12 leading-zero SHA256d work bits, NOT actual nBits target
    for nonce in range(250000):
        header=mk_parent(child_id, nonce, salt)
        assert len(header)==80
        v=int.from_bytes(dsha(header),'big')
        if v >> (256-12)==0:
            bucket=(v>>(256-12-free_bits)) & ((1<<free_bits)-1)
            out.append((header,dsha(header),bucket))
            if len(out)==count:return out,nonce+1
    raise RuntimeError('fixture search bound exhausted')

def run():
    result={'run':'R178-SSHT-20261109','scope':'synthetic SHA256d work certificates, not Bitcoin/Syscoin inclusion or WE security'}
    baseline=H(b'child-id',b'syscoin-child-A')
    fork=H(b'child-id',b'syscoin-child-B')
    same,attempt_a=mine(baseline,b'A',3)
    alt,attempt_b=mine(fork,b'B',3)
    K=H(b'frozen-cancel-key',b'seed1')
    ctx=H(b'withdrawal-context',b'claim-1')
    rows={i:xor(K,H(b'bucket-pad',ctx,bytes([i]))) for i in range(256)}
    def raw(bucket):return xor(rows[bucket],H(b'bucket-pad',ctx,bytes([bucket])))
    # Honest-toy fork opens, but adversary can open with *any* bucket.
    assert all(raw(p[2])==K for p in same+alt)
    assert all(raw(j)==K for j in range(256))
    # Different parent work certificates of same child do not constitute fork.
    assert len({p[1] for p in same})==3 and baseline==baseline
    # Full-header pad replacement cannot predict any later parent hash.
    e_full=xor(K,H(b'full-work-pad',ctx,same[0][0]))
    ok0=xor(e_full,H(b'full-work-pad',ctx,same[0][0]))
    bad1=xor(e_full,H(b'full-work-pad',ctx,same[1][0]))
    bad_fork=xor(e_full,H(b'full-work-pad',ctx,alt[0][0]))
    assert ok0==K and bad1!=K and bad_fork!=K
    # Public fixed-anchor normalization is computable without new evidence.
    anchor=H(b'fixed-anchor',ctx)
    e_anchor=xor(K,H(b'anchor-pad',ctx,anchor))
    assert xor(e_anchor,H(b'anchor-pad',ctx,anchor))==K
    # Parent SHA hashes are not output-semantic identities.
    workids={p[1].hex() for p in same}
    assert len(workids)==3
    # For m unconstrained work digest bits, future honest sample hit rate
    # for a setup-selected bucket is exactly 2**(-m) in ideal uniform model,
    # not an all-witness completeness property.
    q=16
    exact={'m8_single':1/256,'m8_at_least_16':1-(255/256)**q,
           'm128_single':2**-128,'m128_at_least_16':1-(1-2**-128)**q}
    # Numerical cancellation loses m128 here; use exact symbolic bound.
    assert exact['m8_single'] < .004 and exact['m8_at_least_16']<.062
    assert q*2**-128 < 2**-123
    result.update({
        'parent_header_bytes':80,'synthetic_leading_zero_bits':12,
        'mining_hash_tries':attempt_a+attempt_b,
        'same_child_work_ids':[x[1].hex() for x in same],
        'same_child_work_buckets':[x[2] for x in same],
        'fork_child_work_buckets':[x[2] for x in alt],
        'valid_fork_table_releases_all':True,
        'raw_unauthenticated_table_releases_all_256_buckets':True,
        'same_child_multiple_work_ids_not_semantic_fork':True,
        'full_header_pad_only_opens_preselected_header':True,
        'fixed_anchor_pad_is_early_public':True,
        'ideal_hit_prob_m8_setup_bucket':exact['m8_single'],
        'ideal_hit_prob_16_m8_attempts':exact['m8_at_least_16'],
        'ideal_hit_prob_16_m128_union_bound':q*2**-128,
        'limitations':['synthetic 80-byte SHA256d headers, no true BTC difficulty/DAA',
        'no AuxPoW coinbase Merkle, canonical inclusion or context',
        'no native signature or secure Build/Open','no quantum extractor'],
        'source_sha256':hashlib.sha256(open(__file__,'rb').read()).hexdigest()})
    return result
if __name__=='__main__':print(json.dumps(run(),sort_keys=True,indent=2))
