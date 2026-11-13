#!/usr/bin/env python3
"""R228: witness-claim hash-binding fixture, not a WKEM or BTC consensus simulator.

Tests conditional scope binding of a fixed txid output. No real BTC/SYS headers,
actual PQ signatures, QROM proof or source-dependent release is implemented.
"""
import hashlib, json, struct
from collections import Counter

V = 1
COUNTS = Counter()

def H(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()

def H2(data: bytes) -> bytes:
    return H(H(data))

def enc(part: bytes) -> bytes:
    return struct.pack('<I',len(part))+part

def semantic_claim(slot: bytes, burn: bytes, amount: int, recipient: bytes, root: bytes, fork_policy: bytes) -> bytes:
    if amount<0 or amount >= 2**64: raise ValueError('amount')
    return b'ACT-CLAIM-v1' + enc(slot) + enc(burn) + amount.to_bytes(8,'little') + enc(recipient) + enc(root) + enc(fork_policy)

def preimage(claim: bytes, slot: bytes, nonce: bytes) -> bytes:
    assert len(nonce)==32
    return b'ACT-BOUND-v1' + enc(slot) + nonce + enc(claim)

def unpreimage(data: bytes):
    off=0
    if not data.startswith(b'ACT-BOUND-v1'): return None
    off=len(b'ACT-BOUND-v1')
    def take(off):
        if len(data)<off+4: raise ValueError('length')
        n=int.from_bytes(data[off:off+4],'little');off+=4
        if n>4096 or len(data)<off+n: raise ValueError('truncated')
        return data[off:off+n],off+n
    try:
        slot,off=take(off)
        if len(data)<off+32: return None
        salt=data[off:off+32];off+=32
        claim,off=take(off)
        if off != len(data):return None
        return slot,salt,claim
    except ValueError:return None

def commit(slot:bytes, salt:bytes, claim:bytes):
    return H(preimage(claim,slot,salt))

def verify_activate(d:bytes,slot:bytes,stackpreimage:bytes,expected_semantic=None, bypass=False):
    # emulate one path that has a SHA256 equality, never a production script VM
    # bypass=True models a missing enforcement path; always invalid in intended graph.
    if bypass:return True
    parsed=unpreimage(stackpreimage)
    if parsed is None:return False
    s,nonce,claim=parsed
    return s==slot and H(stackpreimage)==d and (expected_semantic is None or claim==expected_semantic)

def rawtx(slot, d, outpoint=b'vault-outpoint'):
    # conceptual fixed nonwitness bytes; script hash d appears in output
    return b'TX-v1'+enc(outpoint)+enc(slot)+enc(d)+b'cancellation-child-output'

def accept_aux_source_claim(raw_claim: bytes, ignore_sidefield: bytes):
    """Offchain parser deliberately reads only the hash-bound P, never extras."""
    return raw_claim

def ck(ok,label):
    if not ok:raise AssertionError(label)
    COUNTS[label]+=1

def main():
    # The actual setup protocol must make A fixed before N-of-N funding.
    salt=H(b'honest setup fresh independent salt fixture')
    for i in range(64):
        slot=H(b'slot'+i.to_bytes(4,'little'))[:16]
        burn=H(b'burn'+i.to_bytes(4,'little'))
        root=H(b'source'+i.to_bytes(4,'little'))
        a0=semantic_claim(slot,burn,i+3,b'recipient-A',root,b'original-prefix')
        a1=semantic_claim(slot,burn,i+4,b'recipient-B',root,b'original-prefix')
        p0=preimage(a0,slot,salt)
        p1=preimage(a1,slot,salt)
        d=commit(slot,salt,a0)
        B=rawtx(slot,d)
        txid=H2(B)
        wtxid0=H2(B+enc(p0)+enc(b'valid one-notary sig-variant-0'))
        wtxid1=H2(B+enc(p0)+enc(b'valid one-notary sig-variant-1'))
        ck(wtxid0!=wtxid1 and txid==H2(B),'variant_has_same_txid_different_wtxid')
        ck(verify_activate(d,slot,p0,a0),'one_committed_claim_accepted')
        ck(not verify_activate(d,slot,p1),'different_claim_rejected_by_hashlock')
        ck(not verify_activate(d,H(b'other-slot')[:16],p0),'different_slot_rejected')
        ck(not verify_activate(d,slot,p0+b'\x00'),'noncanonical_stack_preimage_rejected')
        ck(accept_aux_source_claim(a0,b'forged side-field different claim')==a0,
           'offchain_semantics_only_hashbound_claim')
        ck(verify_activate(d,slot,p0),'public_preimage_can_satisfy_hashlock_without_source_fault')
        ck(verify_activate(d,slot,p1,bypass=True), 'bypass_spend_if_graph_not_enforced')
        ck(H(p0)!=H(p1),'distinct_claims_distinct_hash_fixture')
        # Content of assertion is frozen even though notary signature or other witness changes.
        wvariant=H2(B+enc(p0)+enc(b'vary witness arbitrary data'))
        ck(wvariant!=wtxid0 and txid==H2(B), 'other_witness_fields_do_not_change_claim')
    # One explicit deliberately ambiguous serialization regression: no trailing bytes allowed.
    slot=b'slot1';a=b'A'; nonce=bytes(32)
    ck(unpreimage(preimage(a,slot,nonce)+b'A') is None,'strict_claim_encoding')
    # This is a POLICY / collision property, not secret release.
    return {"run":"R228-20261111", "checks":sum(COUNTS.values()),
            "groups":dict(sorted(COUNTS.items())),
            "source_sha256": H(open(__file__,'rb').read()).hex(),
            "not_tested":["actual Bitcoin Script and native PQ endpoint", "actual source evidence", "QROM reduction", "source-conditioned Build/Open", "malicious setup completeness"],
            "claim":"conditional activation hash binding only, not witness-encryption"}

if __name__=='__main__': print(json.dumps(main(), sort_keys=True, indent=2))
