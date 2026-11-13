#!/usr/bin/env python3
"""R201: synthetic hash-label source gate regression; NOT a BTC/SYS WKEM or QPT test.

Shows witness-occurrence mixing in a classical garbled circuit whose both
input labels are public. Checks alternative hash-of-source-fingerprint repair.
"""
import hashlib
import json
from collections import Counter

C = Counter()

def H(tag, *parts):
    x = tag.encode('ascii') + b'\0'
    for p in parts:
        x += len(p).to_bytes(4, 'big') + p
    return hashlib.sha256(x).digest()

def X(a, b):
    assert len(a) == len(b)
    return bytes(i ^ j for i, j in zip(a, b))

def check(cond, label):
    if not cond:
        raise AssertionError(label)
    C[label] += 1

def label(seed, wire, bit):
    return H('r201-wire', seed, wire.encode('ascii'), bytes([bit]))

def garble_not(seed, in0, in1, out0, out1):
    return [X(out1, H('r201-not', seed, in0)), X(out0, H('r201-not', seed, in1))]

def garble_and(seed, x0, x1, y0, y1, z0, z1):
    ins_x, ins_y = (x0, x1), (y0, y1)
    return [[X((z1 if a and b else z0), H('r201-and',seed,ins_x[a],ins_y[b]))
             for b in (0,1)] for a in (0,1)]

def try_no_witness_gate(seed):
    """UNSAT predicate R(x) := x & ~x, with public labels for x=0/1."""
    x0,x1 = (label(seed,'x',a) for a in (0,1))
    y0,y1 = (label(seed,'y',a) for a in (0,1))
    z0,z1 = (label(seed,'z',a) for a in (0,1))
    not_gate = garble_not(seed,x0,x1,y0,y1)
    and_gate = garble_and(seed,x0,x1,y0,y1,z0,z1)
    native = H('r201-frozen-cancel-signature',seed)
    sealed = X(native,H('r201-pad',z1))
    ck = H('r201-key-check',z1)

    for b in (0,1):
        xb=(x0,x1)[b]
        y_from_not = X(not_gate[b],H('r201-not',seed,xb))
        check(y_from_not==(y1 if b==0 else y0),'honest_NOT_consistency')
        out = X(and_gate[b][1-b],H('r201-and',seed,xb,y_from_not))
        check(out == z0, 'honest_all_inputs_yield_zero')
    # Inconsistent global trace: the y=1 label comes from x=0,
    # then the x=1 label is used at AND. No single x makes x AND NOT x true.
    y1_from_x0 = X(not_gate[0],H('r201-not',seed,x0))
    z1_forged = X(and_gate[1][1],H('r201-and',seed,x1,y1_from_x0))
    check(z1_forged == z1,'inconsistent_occurrence_opens_hidden_output')
    check(H('r201-key-check',z1_forged)==ck,'full_public_key_check_passes')
    check(X(sealed,H('r201-pad',z1_forged))==native,'raw_secret_recovered_without_witness')
    check(not any(b and not b for b in (0,1)),'original_relation_is_FALSE')


def branch(seed,d,h_rel=7):
    """Synthetic hashes of two diverging claim-prefix histories; not PoW."""
    vals=[H('prefix',seed,i.to_bytes(2,'big')) for i in range(h_rel+1)]
    for i in range(d,h_rel+1):
        vals[i]=H('alternative',seed,d.to_bytes(2,'big'),i.to_bytes(2,'big'))
    return vals

def fingerprint_test(seed):
    h_rel=7
    base=[H('prefix',seed,i.to_bytes(2,'big')) for i in range(h_rel+1)]
    b=branch(seed,2,h_rel)
    c=branch(seed,4,h_rel)
    # All three descend from shared root and each alternative conflicts
    # with the bound baseline at the claim-relevant height.
    check(b[0]==c[0]==base[0], 'source_anchor_common')
    check(b[-1]!=base[-1] and c[-1]!=base[-1], 'both_alternatives_claim_conflicts')
    check(b[-1]!=c[-1], 'distinct_valid_alternates_have_distinct_fingerprints')
    native=H('r201-frozen-cancel-signature',seed)
    pad_base=H('r201-source-pad',base[-1])
    public_sealed=X(native,pad_base)
    check(X(public_sealed,pad_base)==native,'fixed_public_baseline_opens_early')
    pad_b=H('r201-source-pad',b[-1]);pad_c=H('r201-source-pad',c[-1])
    check(pad_b!=pad_c,'witness_fingerprint_pads_differ')
    check(X(public_sealed,pad_b)!=native,'first_alternate_fails_fixed_baseline_seal')
    check(X(public_sealed,pad_c)!=native,'second_alternate_fails_fixed_baseline_seal')
    # Common anchor fixes pad across all candidates, but is public.
    anchpad=H('r201-source-pad',base[0])
    sealed_anchor=X(native,anchpad)
    check(X(sealed_anchor,H('r201-source-pad',b[0]))==native,
          'common_anchor_gives_same_output')
    check(X(sealed_anchor,anchpad)==native,'common_anchor_available_before_fork')


def main():
    for i in range(128):
        s=i.to_bytes(4,'big')
        try_no_witness_gate(s)
        fingerprint_test(s)
    return {'run':'R201_SOURCE_CONVERGENT_GATE', 'checks':sum(C.values()),
            'groups':dict(sorted(C.items())), 'scope':'synthetic hash-label circuit and non-PoW fork identities',
            'limitations':['no full Bitcoin/Syscoin parser','no real source proofs',
              'no actual qualifying witness release', 'no simulator/security theorem',
              'no QPT adversary tested']}

if __name__=='__main__':
    print(json.dumps(main(),indent=2,sort_keys=True))
