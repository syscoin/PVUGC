#!/usr/bin/env python3
"""Deterministic SHA-256 functional checks for an *exponential*, nonsecure OW-KEM reference.
Not evidence of QPT hardness, generic PPT setup or deployed PoW authentication.
"""
import hashlib, json

def H(label, data, n=32):
    return hashlib.sha256(label + len(data).to_bytes(4, 'big') + data).digest()[:n]

def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

def encode_w(w):
    return w.to_bytes(2, 'big')

def keygen(seed):
    # 12-bit witness space, 16-bit public image; deliberately weak.
    sk = int.from_bytes(H(b'keygen', seed.to_bytes(4, 'big'), 2), 'big') % 4096
    pk = H(b'preimage', encode_w(sk), 2)
    return sk, pk

def build(pk, seed):
    # Enumerate all 2^12 possible witnesses (exponential for n-bit witnesses).
    ctx = b'R-hashpreimage-12' + pk
    K = H(b'uniform-toy-key', seed.to_bytes(4,'big'), 32)
    CK = H(b'keycheck', ctx + K)
    records = {}
    valid = []
    for w in range(4096):
        wb = encode_w(w)
        if H(b'preimage', wb, 2) != pk:
            continue
        tag = H(b'lookup', ctx + wb)
        e = xor(K, H(b'pad', ctx + wb))
        records[tag] = e
        valid.append(w)
    return {'ctx':ctx,'records':records,'check':CK}, K, valid

def open_with(c, w):
    wb = encode_w(w)
    ctx = c['ctx']
    tag = H(b'lookup', ctx + wb)
    e = c['records'].get(tag)
    if e is None: return None
    k = xor(e, H(b'pad', ctx + wb))
    return k if H(b'keycheck', ctx+k) == c['check'] else None

def main():
    cases = 24
    tests = 0
    max_valid = 0
    valid_total = 0
    enum_total = 0
    false_reject = 0
    for seed in range(cases):
        sk, pk = keygen(seed)
        c, K, valid = build(pk, seed)
        tests += 1; assert sk in valid
        valid_total += len(valid)
        max_valid = max(max_valid, len(valid))
        enum_total += 4096
        for w in valid:
            tests += 1; assert open_with(c, w) == K
        invalid = next(w for w in range(4096) if w not in valid)
        tests += 1; assert open_with(c, invalid) is None
        false_reject += 1
        # Attack finds a valid preimage by scanning; deliberately toy and unsound.
        found = next(w for w in range(4096) if H(b'preimage', encode_w(w), 2) == pk)
        tests += 1; assert open_with(c, found) == K
    data = {'test':'OW-KEM implication toy from exponential witness-indexed hash table','fixtures':cases,'checks':tests,'enumerated_candidates':enum_total,'accepted_witnesses':valid_total,'max_witnesses_per_fixture':max_valid,'false_witness_rejections':false_reject,'attacker_bruteforce_recoveries':cases,'security':'NONE: exhaustive Build; very small source domain; no QPT experiment'}
    print(json.dumps(data,indent=2,sort_keys=True))

if __name__=='__main__':main()
