#!/usr/bin/env python3
"""Finite algebra/model checker; NOT a cryptographic construction or security test."""
import hashlib, json
from itertools import product

count=0

def check(ok, label):
    global count
    assert ok, label
    count+=1

# A fixed first slot is a plain Python object in this model: NO ENCRYPTION.
# This deliberately illustrates correct late-witness *semantics* only.

def R(p, target, w):
    return (w*w) % p == target

def eval_two_slot(p, target, first, second):
    sk, ctx0 = first
    w, ctx1 = second
    if ctx0 != ctx1 or ctx1 != (p, target, 'challenge', 'utxo-A'):
        return None
    return sk if R(p,target,w) else None

def bad_function_key_embedded_secret(sk,p,t):
    # Standard FE plaintext IND does NOT hide the description of its issued f.
    return {'function_description':('if square modulo p equals target then literal K else bottom', p, t, sk)}

multi=0
false_count=0
for p in [7,11,13,17,19,23]:
    for t in range(p):
        ctx=(p,t,'challenge','utxo-A')
        sk=hashlib.sha256(f'key:{p}:{t}'.encode()).hexdigest()[:32]
        first=(sk,ctx)
        valids=[w for w in range(p) if R(p,t,w)]
        if len(valids)>1: multi+=1
        if not valids: false_count+=1
        for w in range(p):
            cap=eval_two_slot(p,t,first,(w,ctx))
            check((cap == sk) == R(p,t,w),f'correct admission p{p} t{t} w{w}')
            check(cap is None or cap == sk,'same K')
            for badctx in [(p,t,'normal','utxo-A'),(p,t,'challenge','utxo-B'),(p,(t+1)%p,'challenge','utxo-A')]:
                check(eval_two_slot(p,t,first,(w,badctx)) is None,'context isolation')
        for w1,w2 in product(valids,valids):
            check(eval_two_slot(p,t,first,(w1,ctx)) == eval_two_slot(p,t,first,(w2,ctx)),'all-witness agreement')
        fk=bad_function_key_embedded_secret(sk,p,t)
        check(fk['function_description'][-1]==sk,'FE key description exposes K')
        # No accepted witness on false statements, in the toy model.
        if not valids:
            check(all(eval_two_slot(p,t,first,(w,ctx)) is None for w in range(p)),'false no release')

check(multi>0,'has multi-witness fixtures')
check(false_count>0,'has false-instance fixtures')
print(json.dumps({'run':406,'checker':'toy two-slot interface + FE function-key leak','assertions':count,'result':'PASS','primes':[7,11,13,17,19,23],'multi_witness_statements':multi,'false_statements':false_count,'model_only':True,'qpt_or_lwe_security_tested':False},sort_keys=True))
