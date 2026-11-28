#!/usr/bin/env python3
"""R200 source-identity fixture: not real Bitcoin consensus, signature, WKEM, or QPT test."""
import hashlib, json, struct

def H(b): return hashlib.sha256(hashlib.sha256(b).digest()).digest()
def V(b): return bytes([len(b)])+b

def tx(msg):
    version=struct.pack('<I',2)
    vin=b'\x01'+b'\x17'*32+struct.pack('<I',1)+V(b'')+bytes.fromhex('fdffffff')
    vout=b'\x01'+struct.pack('<Q',100000)+V(b'\x51')
    lock=bytes(4)
    stripped=version+vin+vout+lock
    witness=b'\x01'+V(b'NOT-A-SIGNATURE;ASSERT='+msg)
    full=version+b'\x00\x01'+vin+vout+witness+lock
    return stripped,full

def run():
    groups={}
    def check(x,label):
        assert x,label
        groups[label]=groups.get(label,0)+1
    outpoints=set()
    for i in range(32):
        a,wa=tx(f'claim={i},valid'.encode())
        b,wb=tx(f'claim={i},invalid'.encode())
        tid,tida=H(a),H(b)
        witness_a,witness_b=H(wa),H(wb)
        check(a==b and tid==tida,'stripped_txid_equal')
        outpoints.add(tid+struct.pack('<I',0))
        check(witness_a!=witness_b,'wtxids_differ')
        salt=H(f'reserved-{i}'.encode())
        c_a=H(H(bytes(32)+witness_a)+salt)
        c_b=H(H(bytes(32)+witness_b)+salt)
        check(c_a!=c_b,'witness_commitments_differ')
        check(c_a!=H(H(bytes(32)+witness_b)+salt),'cross_variant_proof_fails')
        pad=lambda wid: H(b'R200/pad|'+wid)
        sig=H(f'synthetic-cancel-{i}'.encode())
        encrypted=bytes(x^y for x,y in zip(sig,pad(witness_a)))
        recovered_a=bytes(x^y for x,y in zip(encrypted,pad(witness_a)))
        recovered_b=bytes(x^y for x,y in zip(encrypted,pad(witness_b)))
        check(recovered_a==sig and recovered_b!=sig,'wtxid_pad_not_common')
        check(recovered_a==sig,'public_wtxid_pad_opens_early')
    check(len(outpoints)==1,'all_assertions_same_cancel_outpoint')
    return {'run':'R200-source-identity','assertions':sum(groups.values()),
            'groups':groups,'source_sha256':hashlib.sha256(open(__file__,'rb').read()).hexdigest(),
            'scope':'synthetic SegWit equations only; NOT secure release or valid chain'}
if __name__=='__main__': print(json.dumps(run(),sort_keys=True,indent=2))
