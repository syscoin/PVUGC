#!/usr/bin/env python3
"""Abstract WOTS-like hash-chain equivocation release screen (NOT Syscoin WOTS+)."""
import hashlib, json, random
N=16; W=16; LEN1=32; LEN2=3; SID=b'ORIGINAL-PVUGC-RESEARCH-ONLY'
H=lambda x: hashlib.sha256(x).digest()

def F(i,step,x):
    return H(b'F-step'+SID+bytes([i,step])+x)[:N]

def after(i,x,begin,end):
    for step in range(begin,end): x=F(i,step,x)
    return x

def digits(d):
    assert len(d)==16
    m=[(byte>>4) for byte in d]+[(byte&15) for byte in d]
    # Any consistent 32-nibble parsing works as long as both parties agree.
    checksum=sum(15-v for v in m)
    c=[(checksum>>8)&15,(checksum>>4)&15,checksum&15]
    return m+c

secrets=[H(b'secret'+SID+bytes([i]))[:N] for i in range(LEN1+LEN2)]
pks=[after(i,sk,0,15) for i,sk in enumerate(secrets)]

def sign(d):
    a=digits(d)
    return [after(i,secrets[i],0,a[i]) for i in range(len(a))]

def verify(d,sig):
    a=digits(d)
    return all(after(i,sig[i],a[i],15)==pks[i] for i in range(len(a)))

base=H(b'BASELINE STATEMENT')[:16]
a=digits(base); sig_a=sign(base)
assert verify(base,sig_a)
S=H(b'FROZEN SAFE CANCEL CAPABILITY')
caps=[]
for i,ai in enumerate(a):
    if ai==0: caps.append(None); continue
    predecessor=after(i,secrets[i],0,ai-1)
    mask=H(b'KDF'+SID+bytes([i])+predecessor)
    caps.append(bytes(x^y for x,y in zip(S,mask)))

def open_with_second(d):
    b=digits(d); sig_b=sign(d)
    assert verify(d,sig_b)
    for i,(ai,bi) in enumerate(zip(a,b)):
        if bi<ai:
            x=after(i,sig_b[i],bi,ai-1)
            mask=H(b'KDF'+SID+bytes([i])+x)
            return bytes(p^q for p,q in zip(caps[i],mask)),i
    return None,None

rng=random.Random(20261123)
total=256; coords=[]
for j in range(total):
    d=rng.getrandbits(128).to_bytes(16,'big')
    if d==base: continue
    got,idx=open_with_second(d)
    assert got==S and idx is not None
    coords.append(idx)

# An alternate statement has no authenticated source carrier. The same capsule
# still releases S solely because someone who owns the leaf signed it.
spurious=H(b'UNRELATED UNSOURCED STATEMENT')[:16]
malicious_open,idx=open_with_second(spurious)
assert malicious_open==S
print(json.dumps({'fixture':'abstract WOTS-like chains, not real WOTS+ or Core',
 'different_messages_tested':len(coords),
 'all_distinct_messages_release_same_secret':True,
 'distinct_chosen_coordinates':len(set(coords)),
 'baseline_known_signature':True,
 'unauthenticated_second_statement_releases_secret':True,
 'unauthenticated_second_statement_chosen_coordinate':idx,
 'no_authentication_of_original_source':True,
 'no_false_hard_true_qpt_security_claim':True,
 'no_original_bridge_build_open':True},sort_keys=True,indent=2))
