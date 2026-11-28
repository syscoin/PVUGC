#!/usr/bin/env python3
"""Hash-OTP labelled *enumerated* layered DFA: NOT ORIGINAL bridge WE.
Proof of classical-ROM FALSE secrecy in RESEARCH.md, no QPT theorem.
"""
import hashlib, json, itertools, random
from functools import reduce

def H(*parts):
    return hashlib.sha256(b''.join(parts)).digest()

def X(a,b):
    return bytes(x^y for x,y in zip(a,b))

def edgepad(i,q,b,label):
    return H(b'WKEM-DFA-edge-v1|', bytes([i,q,b]), label)

def accpad(label):
    return H(b'WKEM-DFA-final-v1|', label)

def compile_dfa(delta, acc, secret, seed=0):
    rng=random.Random(seed)
    L=len(delta); width=len(delta[0]); assert width == 4 and L==5
    labels=[[rng.randbytes(32) for q in range(width)] for i in range(L+1)]
    C=[]
    for i in range(L):
        C.append([[X(labels[i+1][delta[i][q][b]],edgepad(i,q,b,labels[i][q])) for b in (0,1)] for q in range(width)])
    D={str(q):X(secret,accpad(labels[L][q])) for q in acc}
    return {'L':L,'width':width,'delta':delta,'acc':sorted(acc), 'initial_label':labels[0][0], 'C':C,'D':D},labels

def open_dfa(C,bits):
    q=0; label=C['initial_label']
    for i,b in enumerate(bits):
        next_label=X(C['C'][i][q][b],edgepad(i,q,b,label))
        q=C['delta'][i][q][b]
        label=next_label
    if q not in C['acc']:
        return None
    return X(C['D'][str(q)],accpad(label))

def reachable(delta):
    Q={0}; out=[sorted(Q)]
    for step in delta:
        Q={step[q][b] for q in Q for b in (0,1)}
        out.append(sorted(Q))
    return out

def run():
    secret=H(b'only-public-synthetic-secret-for-test')
    true_delta=[[[ (2*q+b) % 4 for b in (0,1)] for q in range(4)] for i in range(5)]
    false_delta=[[[0 for b in (0,1)] for q in range(4)] for i in range(5)]
    C_T,labT=compile_dfa(true_delta,{2},secret,seed=20261123)
    C_F,labF=compile_dfa(false_delta,{3},secret,seed=20261124)
    all_bits=list(itertools.product((0,1),repeat=5))
    accepted=[]
    for bits in all_bits:
        q=0
        for i,b in enumerate(bits):q=true_delta[i][q][b]
        result=open_dfa(C_T,bits)
        assert (result == secret) == (q==2)
        if q!=2: assert result is None
        if q==2: accepted.append(''.join(map(str,bits)))
    for bits in all_bits:
        assert open_dfa(C_F,bits) is None
    reach_F=reachable(false_delta)
    assert all(3 not in Q for Q in reach_F)
    # Verify accepting terminal label is genuinely *unreachable from the public start*
    # in the enumerated state graph, NOT claim cryptographic secrecy from test.
    assert labF[5][3] not in [labF[i][q] for i,Q in enumerate(reach_F) for q in Q]
    # Complete commitments to the public bytes for reproduction; raw state labels
    # remain in the test process but are never serialized into the capsule.
    def public_digest(C):
        stream=b''.join([C['initial_label']] + [b for st in C['C'] for q in st for b in q] + list(C['D'].values()))
        return hashlib.sha256(stream).hexdigest()
    return {'scope':'enumerated-width-4 DFA, no authentic source, no QPT theorem',
            'true_accepting_count':len(accepted),'true_accepted_inputs':accepted,
            'true_all_witnesses_return_same_secret':True,
            'false_accepting_state_unreachable':True,
            'false_all_32_inputs_return_bottom':True,
            'true_public_capsule_digest':public_digest(C_T),
            'false_public_capsule_digest':public_digest(C_F),
            'model':'SHA256 domain-separated hash OTP with independent per-state labels'}

if __name__=='__main__':
    print(json.dumps(run(),indent=2,sort_keys=True))
