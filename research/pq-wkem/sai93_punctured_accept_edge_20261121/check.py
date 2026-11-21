#!/usr/bin/env python3
"""Synthetic punctured GGM-source-gate fixture. NOT an ORIGINAL witness KEM."""
import hashlib, json

def H(*parts):
    return hashlib.sha256(b'|'.join(parts)).digest()

def expand(s,b):
    return H(b'GGM',s,bytes([b]))

def bits(v,n=8):
    return tuple((v>>i)&1 for i in range(n-1,-1,-1))

def leaf(seed,value,n=8):
    for b in bits(value,n): seed=expand(seed,b)
    return seed

def puncture(seed,a,n=8):
    siblings=[]; prefix=seed
    for i,b in enumerate(bits(a,n)):
        siblings.append((i,expand(prefix,1-b)))
        prefix=expand(prefix,b)
    return siblings

def eval_punctured(siblings,a,q,n=8):
    assert q!=a
    ba,bq=bits(a,n),bits(q,n)
    k=next(i for i in range(n) if ba[i]!=bq[i])
    t=siblings[k][1]
    for b in bq[k+1:]:t=expand(t,b)
    return t

def xor(a,b):return bytes(x^y for x,y in zip(a,b))

def seal(from_label, p, a, final):
    pad=H(b'EDGE',p.to_bytes(2,'big'),a.to_bytes(2,'big'),from_label)
    return xor(final,pad)

def open_edge(from_label,p,a,patch):
    return xor(patch,H(b'EDGE',p.to_bytes(2,'big'),a.to_bytes(2,'big'),from_label))

def main():
    seed=H(b'PUBLIC REPRODUCIBLE TEST SEED; NEVER A REAL KEY')
    accept=255
    siblings=puncture(seed,accept)
    final=leaf(seed,accept)
    assert len(siblings)==8
    assert all(eval_punctured(siblings,accept,q)==leaf(seed,q) for q in range(256) if q!=accept)
    # The punctured key reveals all non-accept labels, but not the accept leaf.
    # Two different synthetic 'approved predecessors': merely labels, NOT ORIGINAL source certificates.
    p1,p2=5,78
    patches={p:seal(leaf(seed,p),p,accept,final) for p in (p1,p2)}
    opened={p:open_edge(eval_punctured(siblings,accept,p),p,accept,patches[p]) for p in patches}
    assert len(set(opened.values()))==1 and next(iter(opened.values()))==final
    # An attacker does not need evidence/headers/PoW because the predecessor label is random-access public.
    recovered=open_edge(eval_punctured(siblings,accept,p1),p1,accept,patches[p1])
    assert recovered==final
    secret=H(b'SYNTHETIC CANCEL SIGNATURE PLACEHOLDER')
    ciphertext=xor(secret,H(b'FINAL',final))
    assert xor(ciphertext,H(b'FINAL',recovered))==secret
    r={
        'scope':'punctured GGM + two public accepting-edge patches; no original certificate, FE, or quantum proof',
        'depth':8,'accept_leaf':accept,'published_sibling_seeds':len(siblings),
        'approved_synthetic_predecessors':[p1,p2],
        'all_255_other_leaves_derivable':True,
        'same_key_for_two_synthetic_paths':len(set(opened.values()))==1,
        'key_recovered_without_original_evidence':recovered==final,
        'synthetic_capability_recovered_without_original_evidence':xor(ciphertext,H(b'FINAL',recovered))==secret,
        'source_is_only_a_fixture':True}
    print(json.dumps(r,indent=2,sort_keys=True))

if __name__=='__main__':main()
