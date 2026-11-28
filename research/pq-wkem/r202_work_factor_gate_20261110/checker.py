#!/usr/bin/env python3
"""R202: SHA-output-factored release regressions. Synthetic PoW only;
no real BTC, SYS, native signature, Build/Open or QPT security claim."""
import hashlib, json
from collections import Counter
C=Counter()

def H(*a):
    d=b''.join(len(x).to_bytes(4,'big')+x for x in a)
    return hashlib.sha256(d).digest()

def ck(t,key):
    assert t,key
    C[key]+=1

def mine(slot,kind,seed,bits=12):
    prefix=b'claim-scope/witness/' + bytes([kind]) + seed.to_bytes(2,'big')+slot.to_bytes(1,'big')
    for nonce in range(1<<19):
        header=prefix+nonce.to_bytes(4,'big')
        y=H(b'parent-header',header)
        if int.from_bytes(y,'big') < (1<<(256-bits)):
            return header,y,nonce
    raise RuntimeError('bounded fixture did not find source work')

def pad_exact(x,y):
    return H(b'pad-exact',x,y)

def pad_range(x,y,bits=12):
    # one label for ALL eligible digest outputs
    eligible=int.from_bytes(y,'big') < (1<<(256-bits))
    return H(b'pad-range',x,b'eligible' if eligible else b'ineligible')

def run():
    valid=[]
    for seed in range(32):
        x=H(b'instance',seed.to_bytes(2,'big'))
        w0,y0,n0=mine(0,0,seed)
        w1,y1,n1=mine(0,1,seed)
        ck(y0!=y1,'different_valid_parent_digests')
        ck(int.from_bytes(y0,'big') < (1<<244) and int.from_bytes(y1,'big') < (1<<244),'both_valid_toy_work')
        ck(pad_exact(x,y0)!=pad_exact(x,y1),'exact_digest_pad_not_common')
        ck(pad_range(x,y0)==pad_range(x,y1),'range_pad_common')
        y_fake=b'\x00'*32
        # No source preimage exists in this call. The attacker directly
        # evaluates the entirely public output-factored pad on a fake y.
        ck(pad_range(x,y_fake)==pad_range(x,y0),'fake_digest_opens_range_pad')
        sigma=H(b'cancel-sig-standin',x)
        capsule=bytes(a^b for a,b in zip(sigma,pad_range(x,y0)))
        out=bytes(a^b for a,b in zip(capsule,pad_range(x,y_fake)))
        ck(out==sigma,'early_raw_key_recovery')
        # kind=0 stands for a valid source burn certificate; kind=1 for a
        # missing certificate. Work qualification does not identify which.
        # The public range-pad opens on a legitimate R2-FALSE activation too.
        open_good=bytes(a^b for a,b in zip(capsule,pad_range(x,y0)))
        ck(open_good==sigma,'work_pad_does_not_enforce_burn_fault')
        # Proof certificates can contain additional hidden information. Their
        # *absence* here is the defining limitation of the examined family.
        valid.append({'seed':seed,'nonce_work_a':n0,'nonce_work_b':n1})
    return {'run':'R202-WOF','assertions':sum(C.values()),'groups':dict(sorted(C.items())),
      'examples':valid[:2],
      'limitations':['only digest-factored hash pad',
          'headers and PoW are synthetic','source ancestry and Merkle proofs unimplemented',
          'not a complete source-dependent compiler','no QPT attack/proof'],
      'source_sha256':hashlib.sha256(open(__file__,'rb').read()).hexdigest()}

if __name__=='__main__':print(json.dumps(run(),sort_keys=True,indent=2))
