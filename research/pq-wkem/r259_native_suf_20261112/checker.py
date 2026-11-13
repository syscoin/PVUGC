#!/usr/bin/env python3
"""R259 symbolic/native signature event partition regressions. No Bitcoin/PQ consensus implementation."""
import hashlib, json, random

def H(b): return hashlib.sha256(b).digest()

def msg(claim, outpoint, value, destination, sequence, reset):
    # test-only canonical fixed-width contextual transcript (NOT Bitcoin sighash)
    return H(b'PVUGC/R259/NATIVE-CANCEL/v1\x00' + claim.to_bytes(4,'little')
        + outpoint + value.to_bytes(8,'little') + destination
        + sequence.to_bytes(4,'little') + reset.to_bytes(4,'little'))

def keygen(seed, bits):
    s=[(H(b'sk0'+seed+i.to_bytes(2,'little')), H(b'sk1'+seed+i.to_bytes(2,'little'))) for i in range(bits)]
    pk=[(H(a), H(b)) for a,b in s]
    return s,pk

def bits_of_m(m, bits):
    x=H(m)
    return [(x[i//8]>>(i%8))&1 for i in range(bits)]

def sign(sk, m):
    bitv=bits_of_m(m,len(sk))
    return tuple(sk[i][bitv[i]] for i in range(len(sk)))

def verify(pk, m, sig):
    if not isinstance(sig,tuple) or len(sig)!=len(pk): return False
    bv=bits_of_m(m,len(pk))
    return all(isinstance(x,bytes) and len(x)==32 and H(x)==pk[i][bv[i]] for i,x in enumerate(sig))

def run():
    rng=random.Random(259)
    stats=dict(valid_opens=0,bit_flip_rejects=0,sibling_message_replay_rejects=0,
               identical_message_replays=0,unissued_message_rejects=0,
               second_preimage_example_searches=0)
    for trial in range(64):
        seed=rng.randbytes(16)
        sk,pk=keygen(seed,256)
        outpoint=rng.randbytes(36)
        dest=rng.randbytes(32)
        m=msg(trial+1,outpoint,100000+trial,dest,0,1)
        sigma=sign(sk,m)
        assert verify(pk,m,sigma)
        stats['valid_opens']+=1
        j=trial%256
        sig2=list(sigma)
        sig2[j]=H(b'wrong'+trial.to_bytes(4,'little'))
        assert not verify(pk,m,tuple(sig2))
        stats['bit_flip_rejects']+=1
        sibling=msg(trial+1001,outpoint,100000+trial,dest,0,1)
        # Hash digest of sibling message differs, and at least one among 256 selected Lamport bits differs.
        assert bits_of_m(m,256)!=bits_of_m(sibling,256)
        assert not verify(pk,sibling,sigma)
        stats['sibling_message_replay_rejects']+=1
        assert verify(pk,m,sigma) # replay of exactly same signed claim/message is allowed
        stats['identical_message_replays']+=1
        different=msg(trial+2001,outpoint,100000+trial,dest,0,2)
        assert not verify(pk,different,sigma)
        stats['unissued_message_rejects']+=1
    # Demonstrate why strong unforgeability needs second-preimage, using a deliberately
    # INSECURE 16-bit hash. Not an attack on SHA-256 or a quantum security test.
    def weak(z): return H(z)[:2]
    original=b'original-sig-preimage'
    target=weak(original)
    second=None
    for nonce in range(1,1_000_001):
        candidate=b'other-'+nonce.to_bytes(4,'little')
        if candidate!=original and weak(candidate)==target:
            second=candidate
            stats['second_preimage_example_searches']=nonce
            break
    assert second is not None and weak(second)==target and second!=original
    stats['weak_hash_same_message_alternate_accepts']=1
    stats['status']='event partition tests only; no source Build/Open or native consensus validation'
    print(json.dumps(stats,sort_keys=True,indent=2))

if __name__=='__main__':run()
