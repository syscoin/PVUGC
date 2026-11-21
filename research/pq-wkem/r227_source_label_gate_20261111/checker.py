#!/usr/bin/env python3
"""R227 classical public-label SHA-garbling test. NOT ORIGINAL source encryption."""
import hashlib, json, sys
from collections import Counter

C=Counter()

def H(*x):
    parts=[]
    for i in x:
        if isinstance(i,int): i=i.to_bytes(4,'big')
        if isinstance(i,str): i=i.encode()
        parts.append(len(i).to_bytes(4,'big')+i)
    return hashlib.sha256(b''.join(parts)).digest()

def xor(a,b): return bytes(x^y for x,y in zip(a,b))

def build(seed):
    labels={w:[H('wire',seed,w,b) for b in (0,1)] for w in ('x','notx','and')}
    sig=H('frozen-claim-cancel-signature',seed)
    notrows=[xor(labels['notx'][1-b],H('NOT',seed,b,labels['x'][b])) for b in (0,1)]
    androws=[[xor(labels['and'][a&b],H('AND',seed,a,b,labels['x'][a],labels['notx'][b])) for b in (0,1)] for a in (0,1)]
    public={'xlabels':labels['x'],'notrows':notrows,'androws':androws,
            'output_check':H('native-vk-standin',sig),
            'sealed':xor(sig,H('output-mask',labels['and'][1])),
            'label_tags':{w:[H('wirecheck',q) for q in pair] for w,pair in labels.items()},
            'seed':seed}
    return public,labels,sig

def evaluate_not(pub,xlabel,b):
    return xor(pub['notrows'][b],H('NOT',pub['seed'],b,xlabel))

def evaluate_and(pub,xlabel,notlabel,a,b):
    return xor(pub['androws'][a][b],H('AND',pub['seed'],a,b,xlabel,notlabel))

def recover(pub,z):
    return xor(pub['sealed'],H('output-mask',z))

def test(seed):
    p,secret_labels,sig=build(seed)
    for b in (0,1):
        notlab=evaluate_not(p,p['xlabels'][b],b)
        assert notlab==secret_labels['notx'][1-b]
        zend=evaluate_and(p,p['xlabels'][b],notlab,b,1-b)
        assert zend==secret_labels['and'][0]
        assert H('native-vk-standin',recover(p,zend))!=p['output_check']
        C['honest_false_witness_no_release']+=1
    # Attack: x=1 for positive occurrence, x=0 for negative occurrence.
    # Both labels were published for the same input wire, and all garbled rows
    # faithfully authenticate and decrypt, yet no globally consistent x exists.
    lbl_not_true=evaluate_not(p,p['xlabels'][0],0)
    assert H('wirecheck',lbl_not_true)==p['label_tags']['notx'][1]
    forged_true=evaluate_and(p,p['xlabels'][1],lbl_not_true,1,1)
    assert H('wirecheck',forged_true)==p['label_tags']['and'][1]
    assert recover(p,forged_true)==sig
    assert H('native-vk-standin',recover(p,forged_true))==p['output_check']
    C['false_instance_release_from_occurrence_mix']+=1
    # Source-input SHA check: replacing x with another public SHA equality gate
    # does not create any single-use capability; both x labels remain clonable.
    assert p['xlabels'][0]!=p['xlabels'][1]
    C['public_classical_labels_copyable']+=1

    # Witness-dependent transcript-context pad proposal:
    # a single static ciphertext row R = Lout xor H(T,Linput) cannot decrypt to
    # SAME Lout for two distinct valid source transcripts T0,T1, except if pads collide.
    t0=H('authenticated-workid-A',seed)
    t1=H('authenticated-workid-B',seed)
    lin=p['xlabels'][1]; lout=secret_labels['and'][1]
    row=xor(lout,H('context-gate',t0,lin))
    assert xor(row,H('context-gate',t0,lin))==lout
    assert xor(row,H('context-gate',t1,lin))!=lout
    C['static_row_fails_multi_transcript_context']+=1

    # Binding to a publicly known context (e.g. slot-id) makes both labels
    # usable again. It does not block the original occurrence mixing.
    known=H('public-slot',seed)
    ctx_notrows=[xor(secret_labels['notx'][1-b],H('CTX-NOT',known,b,p['xlabels'][b])) for b in (0,1)]
    ctx_androws=[[xor(secret_labels['and'][a&b],H('CTX-AND',known,a,b,p['xlabels'][a],secret_labels['notx'][b])) for b in (0,1)] for a in (0,1)]
    nottrue=xor(ctx_notrows[0],H('CTX-NOT',known,0,p['xlabels'][0]))
    andtrue=xor(ctx_androws[1][1],H('CTX-AND',known,1,1,p['xlabels'][1],nottrue))
    assert H('native-vk-standin',xor(p['sealed'],H('output-mask',andtrue)))==p['output_check']
    C['public_context_does_not_restore_consistency']+=1


def main():
    for i in range(128):test(H('seed',i))
    # Formula R(x)=x AND NOT(x) always false, independently of hash values.
    assert all(not (x and (not x)) for x in (False,True))
    C['original_relation_exhaustively_false']+=1
    result={'run':'R227_SOURCE_INPUT_GARBLE','assertions':sum(C.values()),
            'counts':dict(sorted(C.items())),
            'scope':'unconditional classical inconsistency of a SPECIFIED public-label hash-garbling family, NOT generic impossibility',
            'source_sha256':hashlib.sha256(open(__file__,'rb').read()).hexdigest(),
            'security_tests':'none (no quantum adversary or real BTC/SYS source)'}
    return result

if __name__=='__main__': print(json.dumps(main(),indent=2,sort_keys=True))
