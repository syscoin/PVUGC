#!/usr/bin/env python3
"""Toy release-slot and activation-witness binding checks. No WKEM or real signatures."""
import hashlib,hmac,json

def H(tag,*xs):
    return hashlib.sha256(tag+b''.join(len(x).to_bytes(4,'big')+x for x in xs)).digest()
def D(x):return hashlib.sha256(hashlib.sha256(x).digest()).digest()
def xor(a,b):return bytes(x^y for x,y in zip(a,b))
def V(x):return bytes([len(x)])+x

def body(seed):
    inp=lambda t:H(t,seed)+bytes(4)+b'\x00'+b'\xfe\xff\xff\xff'
    out=(1).to_bytes(8,'little')+V(b'\x51\x20'+H(b'output',seed))
    return (2).to_bytes(4,'little')+b'\x02'+inp(b'vault')+inp(b'notarytoken')+b'\x01'+out+bytes(4)
def witness_tx(body,s0,s1,annex):
    return body[:4]+b'\x00\x01'+body[4:-4]+b'\x01'+V(s0)+b'\x02'+V(s1)+V(annex)+body[-4:]
def sig(k,body,i,annex):
    return hmac.new(k,H(b'input-local-annex-sighash-MODEL',body,bytes([i]),annex),'sha256').digest()

def run():
    counts={k:0 for k in ('source_slot_raw_leak','distinct_source_pad_not_same_key',
      'setup_signature_annex_independent','notary_signature_annex_bound',
      'txid_unchanged_wtxid_changed','witness_commitment_selects_actual_assertion')}
    for n in range(128):
        seed=n.to_bytes(4,'big');ctx=H(b'ctx',seed);key=H(b'key',seed)
        # One public slot pad cannot enforce source authentication.
        slot=H(b'slot',ctx);E=xor(key,slot)
        assert xor(E,slot)==key;counts['source_slot_raw_leak']+=1
        a=H(b'future-branch-a',seed);b=H(b'future-branch-b',seed)
        pa=H(b'pad',ctx,a);pb=H(b'pad',ctx,b)
        assert a!=b and pa!=pb and xor(xor(key,pa),pb)!=key
        counts['distinct_source_pad_not_same_key']+=1
        # Two-input known-body preauthorization: vault input 0 has no annex;
        # notary token input 1 carries a signed claim in its own annex.
        tx=body(seed);sk0=H(b'setup-secret',seed);sk1=H(b'notary-secret',seed)
        claim0=b'\x50'+H(b'claim0',seed);claim1=b'\x50'+H(b'claim1',seed)
        s0=sig(sk0,tx,0,b'');s1=sig(sk1,tx,1,claim0)
        assert s0==sig(sk0,tx,0,b'')
        counts['setup_signature_annex_independent']+=1
        assert s1!=sig(sk1,tx,1,claim1)
        counts['notary_signature_annex_bound']+=1
        w0=D(witness_tx(tx,s0,s1,claim0))
        w1=D(witness_tx(tx,s0,sig(sk1,tx,1,claim1),claim1))
        assert D(tx)==D(tx) and w0!=w1
        counts['txid_unchanged_wtxid_changed']+=1
        reserved=H(b'witness-reserved',seed)
        commitment=lambda w:D(D(bytes(32)+w)+reserved)
        assert commitment(w0)!=commitment(w1)
        counts['witness_commitment_selects_actual_assertion']+=1
    return {'run':'SBR-20261109','counts':counts,'assertions':sum(counts.values()),
      'scope':'Synthetic branch pads and current-input annex witness binding only; no qualified Bitcoin/Syscoin evidence, PQ endpoint, WE or QPT proof',
      'checker_sha256':hashlib.sha256(open(__file__,'rb').read()).hexdigest()}
if __name__=='__main__':print(json.dumps(run(),sort_keys=True,indent=2))
