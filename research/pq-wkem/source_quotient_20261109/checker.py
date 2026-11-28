#!/usr/bin/env python3
"""SHA256/Shake256 toy source-quotient checker; NOT secure WGKEM or genuine BTC/SYS validation.

The checked original relation is explicitly synthetic and the private chain flags are
not substitutes for authenticated best-chain evidence. This program tests whether
source qualification can protect a RAW hash-masked public capability.
"""
import hashlib, json, random


def H(tag: bytes, data: bytes, n: int = 32) -> bytes:
    t = len(tag).to_bytes(2, 'big') + tag + len(data).to_bytes(4, 'big') + data
    return hashlib.shake_256(t).digest(n)


def xor(a, b):
    assert len(a) == len(b)
    return bytes(x ^ y for x, y in zip(a, b))


def context(seed: int) -> bytes:
    return b'claim|path|window|relation|native-vk|' + seed.to_bytes(4, 'big')


def source_child(seed: int):
    return H(b'child', b'fixed-child|' + seed.to_bytes(4, 'big'))


def work_cert(seed: int, variant: int, *, qualify=True):
    # A CERT IS A DETERMINISTIC TOY BYTES OBJECT; NO REAL CONSENSUS VALIDITY.
    child = source_child(seed)
    parent = H(b'parent', seed.to_bytes(4, 'big') + variant.to_bytes(2, 'big'))
    # Two different parent certs are valid for the SAME child, by construction.
    return dict(child=child, parent=parent, valid_anchor=qualify,
                valid_parent=qualify, valid_canonical=qualify,
                right_claim=qualify)


def R_original_toy(seed, cert):
    return (cert['child'] == source_child(seed) and cert['valid_anchor'] and
            cert['valid_parent'] and cert['valid_canonical'] and cert['right_claim'])


def outcome_id(cert, ctx):
    return H(b'outcomeID', ctx + cert['child'])


def work_id(cert, ctx):
    return H(b'workID', ctx + cert['child'] + cert['parent'])


def build_with_known_classes(ctx, classes, key, frozen_signature):
    CK = H(b'CK', ctx + key)
    D = xor(frozen_signature, H(b'mask', ctx + key, len(frozen_signature)))
    rows = {}
    for u in classes:
        tag = H(b'tag', ctx + u)
        row = xor(key, H(b'pad', ctx + u))
        rows[tag] = row
    return {'CK': CK, 'D': D, 'rows': rows, 'context': ctx}


def raw_open(capsule, u):
    ctx = capsule['context']
    e = capsule['rows'].get(H(b'tag', ctx + u))
    if e is None:
        return None
    k = xor(e, H(b'pad', ctx + u))
    if H(b'CK', ctx + k) != capsule['CK']:
        return None
    return k, xor(capsule['D'], H(b'mask', ctx + k, len(capsule['D'])))


def honest_open(seed, capsule, cert, g):
    if not R_original_toy(seed, cert):
        return None
    return raw_open(capsule, g(cert, capsule['context']))


def run():
    counts = dict(fixtures=0, checks=0, valid_same_child_different_work=0,
                  honest_invalid_rejections=0, raw_fake_unlocks=0,
                  work_id_is_distinct=0, full_work_closure_checks=0)
    for seed in range(128):
        ctx = context(seed)
        key = H(b'key', ctx)
        sig = H(b'frozen-native-placeholder-0', ctx, 96)
        a, b = work_cert(seed, 0), work_cert(seed, 1)
        fake = work_cert(seed, 9, qualify=False)
        assert R_original_toy(seed,a) and R_original_toy(seed,b) and not R_original_toy(seed,fake)
        counts['checks'] += 3
        assert outcome_id(a,ctx) == outcome_id(b,ctx) == outcome_id(fake,ctx)
        assert len({work_id(c,ctx) for c in [a,b,fake]}) == 3
        counts['checks'] += 2
        c = build_with_known_classes(ctx,[outcome_id(a,ctx)],key,sig)
        assert honest_open(seed,c,a,outcome_id) == (key,sig)
        assert honest_open(seed,c,b,outcome_id) == (key,sig)
        assert honest_open(seed,c,fake,outcome_id) is None
        counts['checks'] += 3
        # Public hashes do not know the SOURCE predicate; raw source-fake succeeds.
        assert raw_open(c,outcome_id(fake,ctx)) == (key,sig)
        counts['checks'] += 1
        counts['valid_same_child_different_work'] += 1
        counts['honest_invalid_rejections'] += 1
        counts['raw_fake_unlocks'] += 1
        counts['work_id_is_distinct'] += 1
        # Full-WORKID classes require a row for each future certificate; one row
        # only opens one of two valid certificates, violating every-witness correctness.
        c2 = build_with_known_classes(ctx,[work_id(a,ctx)],key,sig)
        assert raw_open(c2,work_id(a,ctx)) == (key,sig)
        assert raw_open(c2,work_id(b,ctx)) is None
        counts['checks'] += 2
        counts['full_work_closure_checks'] += 1
        counts['fixtures'] += 1

    # Independent future work ids (uniform idealized class) vs setup-selected pad classes.
    # A WorkID made from SHA of ANY bytes is source-agnostic absent actual validity auth.
    N = 2048; q = 32; bits = 16; matches = 0
    for t in range(N):
        pub_seed = t.to_bytes(4,'big')
        rows = {H(b'setup-class', pub_seed + j.to_bytes(2,'big'), 2)
                for j in range(q)}
        future = H(b'future-full-evidence-class', pub_seed, 2)
        if future in rows:
            matches += 1
    expected_bound = N * q / (1 << bits)
    counts['future_source_independent_classes'] = {'trials':N,'q':q,'bits':bits,
         'matches':matches,'expected_upper_bound':expected_bound,
         'single_trial_hit_bound':q/(1<<bits)}
    # Merkle root over public rows authenticates bytes but does not change the raw
    # decrypt path; include a deterministic digest merely to verify that fact.
    ctx = context(777)
    c = build_with_known_classes(ctx,[outcome_id(work_cert(777,0),ctx)],H(b'key',ctx),H(b'sig',ctx,96))
    payload = b''.join(sorted(k+v for k,v in c['rows'].items()))
    root = H(b'merkle-like-commitment-only',payload)
    assert len(root)==32
    assert raw_open(c,outcome_id(work_cert(777,7,qualify=False),ctx)) is not None
    counts['checks'] += 2
    counts['root_authenticates_but_does_not_gate_raw_open'] = True
    counts['security'] = 'NONE. Synthetic source; future class idealized; public raw key recovery.'
    counts['source_authentication'] = 'NONE. Toy booleans, not BTC/SYS best-chain evidence.'
    counts['production'] = 'NO'
    return counts

if __name__=='__main__':
    print(json.dumps(run(),indent=2,sort_keys=True))
