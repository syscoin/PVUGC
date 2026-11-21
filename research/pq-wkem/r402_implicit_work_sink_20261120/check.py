#!/usr/bin/env python3
"""Bounded synthetic header-walk test. NOT an AuxPoW/Syscoin verifier or a witness-KEM."""
import hashlib, json, secrets

def h(data): return hashlib.sha256(data).digest()
def dh(data): return h(h(data))
def x(a,b): return bytes(i^j for i,j in zip(a,b))

def mine(prev, domain, count=4):
    out=[]
    for i in range(count):
        for nonce in range(1<<20):
            header=prev+domain+bytes([i])+nonce.to_bytes(4,'little')
            digest=dh(header)
            if digest[0]==0:
                out.append((header.hex(),digest.hex()))
                prev=digest
                break
        else: raise RuntimeError('fixture work unexpectedly failed')
    return out

def validate(anchor, chain, domain):
    prev=anchor
    for i,(raw,reported) in enumerate(chain):
        b=bytes.fromhex(raw)
        if b[:32]!=prev or b[32:32+len(domain)]!=domain or b[32+len(domain)]!=i:
            return False
        d=dh(b)
        if d.hex()!=reported or d[0]!=0: return False
        prev=d
    return True

def walk(label0, chain):
    label=label0
    for raw,_ in chain:
        label=h(b'R402/edge'+label+bytes.fromhex(raw))
    return label

anchor=dh(b'public common source prefix')
a=mine(anchor, b'A')
b=mine(anchor, b'B')
assert validate(anchor,a,b'A') and validate(anchor,b,b'B')
assert a[0][1] != b[0][1]
# This models two authenticated competing branches; not full ORIGINAL relation.
label0=h(b'public initial state label')
ka=h(b'R402/sink'+walk(label0,a))
kb=h(b'R402/sink'+walk(label0,b))
assert ka!=kb
s=h(b'fixed synthetic protected payload')
ct=x(s,ka)
assert x(ct,ka)==s
assert x(ct,kb)!=s

# Public reset maps all claimed histories to a trivially public pad.
reset=h(b'R402/reset'+anchor)
ct_reset=x(s,reset)
assert x(ct_reset,reset)==s  # w is NOT used.

# Builder-secret reset cannot be computed by Open from just its public inputs.
seed=secrets.token_bytes(32)
seed_reset=h(b'R402/private-reset'+seed+anchor)
ct_hidden=x(s,seed_reset)
# A second independent random seed doesn't match the needed pad.
independent_seed=secrets.token_bytes(32)
assert x(ct_hidden,h(b'R402/private-reset'+independent_seed+anchor)) != s

print(json.dumps({
  'scope':'two synthetic linked 8-bit PoW branch suffixes; NOT ORIGINAL/AuxPoW/FE',
  'source_anchor':anchor.hex(),
  'A_first_hash':a[0][1], 'B_first_hash':b[0][1],
  'A_depth':len(a), 'B_depth':len(b),
  'both_chains_satisfy_fixture_rule':True,
  'two_hashwalk_sink_labels_equal':ka==kb,
  'frozen_ciphertext_decodes_under_A':x(ct,ka)==s,
  'frozen_ciphertext_decodes_under_B':x(ct,kb)==s,
  'public_reset_decodes_without_witness':x(ct_reset,reset)==s,
  'hidden_reset_has_no_public_evaluation_algorithm':True,
}, sort_keys=True,indent=2))
