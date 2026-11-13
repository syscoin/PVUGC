#!/usr/bin/env python3
"""Run 397: deterministic bounded unary-orbit admission falsifier.
The fixture is a public unkeyed unary plaintext transition and public
release test. It is NOT CLZ code or a cryptographic implementation.
"""
import hashlib
import itertools
import json

checks=0

def check(v,why):
    global checks
    checks+=1
    if not v: raise AssertionError(f'check {checks}: {why}')

def H(tag,data):
    return hashlib.sha256(tag + data).digest()

def native_vk(k):
    return H(b'RUN397-NATIVE-TEST/', bytes([k]))

def native_sign(k,context):
    # Deliberately toy: a real native signature scheme would be required.
    return bytes([k]) + H(b'RUN397-TOY-SIGN/', bytes([k]) + context)

def native_verify(vk,context,sig):
    return (len(sig)==33 and native_vk(sig[0])==vk
            and H(b'RUN397-TOY-SIGN/',sig[:1]+context)==sig[1:])

def g(state,T):
    k,pos,nonce=state
    return (k,(pos+1)%T,nonce)  # unary; cannot admit w

def public_rerand(state,coin):
    k,pos,_=state
    return (k,pos,coin)         # changes ciphertext randomness only

def release(state,slots,context):
    k,pos,_=state
    return native_sign(k,context) if pos in slots else bytes(33)

def honest(C0,t,slots,T,context):
    s=C0
    for _ in range(t):s=g(s,T)
    return release(s,slots,context)

def unauthorized_enumerate(C0,slots,T,context):
    vk=native_vk(C0[0]);s=C0
    for t in range(T):
        candidate=release(s,slots,context)
        if native_verify(vk,context,candidate):return t,candidate
        s=g(s,T)
    return None,None

cases=0
for T in (2,3,4,5,6,7,8):
  for seed in (0,1,7,15,37,255):
    C0=(seed,0,b'initial')
    vk=native_vk(seed)
    context=H(b'RUN397-CONTEXT/',bytes([T,seed]))
    # Every possible nonempty accepting orbit subset: correctness for
    # any accepted 'witness-derived' step t, and bypass without that t.
    for mask in range(1,1<<T):
      slots={t for t in range(T) if (mask>>t)&1}
      got_t,got_sig=unauthorized_enumerate(C0,slots,T,context)
      check(got_t is not None,'enumeration succeeds for nonempty accepting subset')
      check(native_verify(vk,context,got_sig),'native verification of unauthorized candidate')
      check(got_t==min(slots),'first success matches first accepting step')
      for t in slots:
        check(native_verify(vk,context,honest(C0,t,slots,T,context)),
              'all accepted witness-selected steps recover one signer')
      check(public_rerand(C0,b'nonce1')[:2]==C0[:2],
            'rerandomization does not insert later plaintext witness')
      for t in range(T):
        s=C0
        for _ in range(t):s=g(s,T)
        check(public_rerand(s,b'nonce2')[:2]==s[:2],
              'rerandomized child has same source-independent unary state')
      cases+=1

# Explicit two-branch credential correlation check, not a new theorem.
ka,kb=31,77
ca,cb=b'utxo-A:challenge',b'utxo-B:challenge'
check(native_verify(native_vk(ka),cb,native_sign(ka,cb)),
      'same native seed authorizes a second context if reused there')
check(not native_verify(native_vk(kb),cb,native_sign(ka,cb)),
      'independent native seed excludes that cross-branch forgery')

result={'run':397,'status':'PASS','checks':checks,'fixtures':cases,
        'orbit_lengths':[2,3,4,5,6,7,8],
        'exhaustive_nonempty_acceptance_subsets':True,
        'all_witness_selected_steps_same_capability':True,
        'witness_free_t_query_enumeration':True,
        'rerandomization_only_changes_nonce':True,
        'toy_native_signature':True,'real_CLZ_implementation':False,
        'QPT_security_proven':False,'WKEM_completed':False}
print(json.dumps(result,sort_keys=True,indent=2))
