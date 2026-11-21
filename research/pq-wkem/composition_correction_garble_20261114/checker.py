#!/usr/bin/env python3
"""Actual SHA256 garbling of the R275 correction function, not a secure WKEM.

The attack receives ONLY Public, never labels/keys retained by Build. Private
seed and payload bits each expose one active label, NOT both labels. No source
consensus or native signature is implemented. Reproducible test coins are used.
"""
from __future__ import annotations
import hashlib
import json
import random
from dataclasses import dataclass
from pathlib import Path
from collections import Counter
from r280_circuit import Circuit, garble, hpad, xor16, bits_bytes, bit_bytes

CTX = hashlib.sha256(b'COMPOSE-CG-20261114 exact synthetic slot').digest()[:8]
COUNTS = Counter()

def check(p, name):
    if not p:
        raise AssertionError(name)
    COUNTS[name] += 1

def xor(a, b):
    if len(a) != len(b):
        raise ValueError('unequal XOR lengths')
    return bytes(x ^ y for x, y in zip(a, b))

def mask(j, key, suffix):
    return hashlib.sha256(b'CG-F' + bytes([j]) + CTX + key + bytes([suffix])).digest()

def outer_pad(v):
    return hashlib.sha256(b'CG-M' + CTX + v).digest()

@dataclass
class Public:
    c: Circuit
    variables: list
    public_pairs: dict
    fixed_labels: dict
    rows: list
    masks: list
    tail_start: int
    outputs: list
    decode: list
    allowed: tuple
    allowed_keys: tuple


def compile_circuit():
    c = Circuit()
    variables = [c.inp() for _ in range(9)] # first selector and eight suffix bits
    seeds = [[[c.inp() for _ in range(256)] for b in range(2)] for j in range(2)]
    payload = [c.inp() for _ in range(256)]
    masks = []
    for j in range(2):
        # Private branch seeds are analogous to children of a clause-first GGM.
        chosen = [c.XOR(a, c.AND(variables[0], c.XOR(a,b)))
                  for a,b in zip(seeds[j][0], seeds[j][1])]
        msg = bits_bytes(b'CG-F' + bytes([j]) + CTX) + chosen + variables[1:]
        masks.append(c.sha256(msg))
    tail_start = 2 + len(c.nodes)
    combined = [c.XOR(a,b) for a,b in zip(*masks)]
    pad = c.sha256(bits_bytes(b'CG-M' + CTX) + combined)
    outputs = [c.XOR(a,b) for a,b in zip(payload, pad)]
    return c, variables, seeds, payload, masks, tail_start, outputs


def build(compiled, rng, allowed=(0,1)):
    c, variables, seed_nodes, payload_nodes, masks, tail_start, outputs = compiled
    # Derive independent branch keys from private roots via domain-separated SHA.
    roots = [rng.randbytes(32) for _ in range(2)]
    keys = [[hashlib.sha256(b'CG-child'+CTX+bytes([j,b])+roots[j]).digest()
             for b in range(2)] for j in range(2)]
    secret = rng.randbytes(32)
    labels, rows = garble(c, rng)
    fixed = {0: labels[0][0], 1: labels[1][1]}
    for j in range(2):
        for b in range(2):
            for node, bit in zip(seed_nodes[j][b], bits_bytes(keys[j][b])):
                fixed[node] = labels[node][bit]
    for node, bit in zip(payload_nodes, bits_bytes(secret)):
        fixed[node] = labels[node][bit]
    public = Public(c,variables,{n:labels[n] for n in variables},fixed,rows,masks,
                    tail_start,outputs,
                    [{labels[n][b]:b for b in (0,1)} for n in outputs],
                    allowed,tuple(keys[j][allowed[j]] for j in range(2)))
    # Return the private values ONLY for the correctness test harness.
    return public, secret, keys


def gate_eval(public, active, start, end):
    for idx in range(start, end):
        op,x,y = public.c.nodes[idx-2]
        if op == 'IN':
            if idx not in active:
                raise ValueError('missing fixed or external input')
            continue
        a=active[x]; b=b'' if op=='NOT' else active[y]
        sel=(a[-1]&1) if op=='NOT' else 2*(a[-1]&1)+(b[-1]&1)
        active[idx]=xor16(public.rows[idx-2][sel], hpad(idx,a,b))
    return active


def trace_prefix(public, selector, suffix):
    bits=[selector]+bits_bytes(bytes([suffix]))
    active=dict(public.fixed_labels)
    active.update({n:public.public_pairs[n][b] for n,b in zip(public.variables,bits)})
    return gate_eval(public,active,2,public.tail_start)


def finish(public, active):
    gate_eval(public,active,public.tail_start,2+len(public.c.nodes))
    return bit_bytes([decoder[active[n]] for decoder,n in zip(public.decode,public.outputs)])


def honest_open(public, selector, suffix):
    if any(selector != b for b in public.allowed):
        return None
    e=finish(public, trace_prefix(public,selector,suffix))
    pads=[mask(j,public.allowed_keys[j],suffix) for j in range(2)]
    return xor(e,outer_pad(xor(*pads)))


def public_cut_attack(public):
    # Two complete vector observations suffice; no bitwise zero calibration,
    # private label map or guessed label semantics is needed.
    seen = []
    values = []
    for j in range(2):
        suffix = 7 + 12*j
        active = trace_prefix(public, public.allowed[j], suffix)
        seen.append({n:active[n] for n in public.masks[j]})
        values.append(mask(j, public.allowed_keys[j], suffix))
    # These vectors come from individually permitted but incompatible queries.
    active = dict(public.fixed_labels)
    active.update(seen[0]); active.update(seen[1])
    fake_cipher = finish(public, active)
    recovered = xor(fake_cipher, outer_pad(xor(*values)))
    return recovered, [1, 1]


def selector_clone_fixture():
    # Native-signature cryptography is NOT modeled. These are already available
    # preauthorized opening strings. A ledger tracks which branch can confirm.
    rng=random.Random(202611142)
    tokens=[rng.randbytes(32) for _ in range(2)]
    labels=[rng.randbytes(32) for _ in range(2)]
    wraps=[xor(labels[b],hashlib.sha256(b'choice'+tokens[b]).digest()) for b in (0,1)]
    public=(tokens,wraps)
    spent=False
    def submit(b):
        nonlocal spent
        if spent:return False
        spent=True
        return True
    stolen=[xor(public[1][b],hashlib.sha256(b'choice'+public[0][b]).digest()) for b in (0,1)]
    check(stolen==labels,'selector_both_labels_read_before_confirmation')
    check(submit(0),'selector_first_spend_confirms_in_model')
    check(not submit(1),'selector_second_spend_rejected_in_model')
    check(stolen==labels,'selector_ledger_rejection_does_not_unlearn_labels')


def main():
    compiled=compile_circuit()
    public,secret,private_keys=build(compiled,random.Random(2026111401))
    check(len(public.public_pairs)==9,'only_external_inputs_have_label_pairs')
    check(len(public.fixed_labels)==1282,'one_fixed_label_for_each_private_bit_and_constant')
    # Verify complete garbled output against independent hashlib calculations.
    for selector,suffix in [(0,0),(1,0),(0,7),(1,19),(0,239),(1,255)]:
        actual=finish(public,trace_prefix(public,selector,suffix))
        p=xor(mask(0,private_keys[0][selector],suffix),mask(1,private_keys[1][selector],suffix))
        check(actual==xor(secret,outer_pad(p)),'garbled_three_sha_matches_hashlib')
    # FALSE: selector must equal both zero and one. No legitimate opening exists.
    for selector in (0,1):
        check(honest_open(public,selector,0) is None,'false_honest_reject')
    recovered,probes=public_cut_attack(public)
    check(recovered==secret,'public_false_recovery_from_joint_view')
    # TRUE variant shares the same compiled algorithms; both local predicates
    # allow zero. No parameter/setup claim is inferred from these observations.
    from dataclasses import replace
    true_public=replace(public,allowed=(0,0),allowed_keys=(private_keys[0][0],private_keys[1][0]))
    for suffix in (1,2,3,5,13,31):
        check(honest_open(true_public,0,suffix)==secret,'distinct_true_witness_same_secret')
    selector_clone_fixture()
    out={'run':'COMPOSE-CG-20261114','status':'COMPOSITION_REJECTED_NOT_A_BRIDGE_SOLUTION',
         'gate_count':len(public.c.nodes),'garbled_row_count':sum(map(len,public.rows)),
         'public_external_label_pairs':len(public.public_pairs),'active_private_input_bits':1280,
         'sha256_calls_in_correction':3,'recovery_probes_per_clause':probes,
         'tests':dict(sorted(COUNTS.items())),'assertions':sum(COUNTS.values()),
         'native_signatures':False,'source_consensus':False,'qpt_security_established':False,
         'checker_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
         'sha_circuit_module_sha256':hashlib.sha256(Path(__file__).with_name('r280_circuit.py').read_bytes()).hexdigest()}
    print(json.dumps(out,sort_keys=True,indent=2))

if __name__=='__main__':main()
