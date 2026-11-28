#!/usr/bin/env python3
"""Exact hash-garbling false-instance counterexample from both public input labels.
R(x)=x AND (NOT x) has no witness. Not a production garbling scheme,
source verifier, BTC/SYS implementation, WE, or QPT experiment.
"""
import hashlib,json

def H(t,*xs):
    h=hashlib.sha256()
    h.update(t.encode()+b'\0')
    for x in xs:
        if isinstance(x,str):x=x.encode()
        if isinstance(x,int):x=x.to_bytes(4,'big')
        h.update(len(x).to_bytes(4,'big')+x)
    return h.digest()
def xor(a,b):return bytes(x^y for x,y in zip(a,b))
def tag(x):return x[-1]&1

def pair(ctx,name):
    p=H('wire-choice',ctx,name)[0]&1
    def lab(v):
        base=H('wire-label',ctx,name,v)
        return base[:-1]+bytes([(base[-1]&254)|(p^v)])
    return (lab(0),lab(1))

def garble(ctx,seed):
    x=pair(ctx,'x'); y=pair(ctx,'y'); z=pair(ctx,'z')
    not_rows=[None,None]
    for b in (0,1):
        not_rows[tag(x[b])]=xor(y[1-b],H('NOT-pad',ctx,x[b]))
    and_rows=[None]*4
    for a in (0,1):
        for b in (0,1):
            index=2*tag(x[a])+tag(y[b])
            and_rows[index]=xor(z[a&b],H('AND-pad',ctx,x[a],y[b]))
    sig=H('native-sig-synthetic',ctx,seed)
    sealed=xor(sig,H('output-pad',ctx,z[1]))
    chk=H('check',ctx,z[1])
    return (x,y,z,not_rows,and_rows,sealed,chk,sig)

def eval_not(ctx,c,not_rows):return xor(not_rows[tag(c)],H('NOT-pad',ctx,c))
def eval_and(ctx,a,b,and_rows):
    return xor(and_rows[2*tag(a)+tag(b)],H('AND-pad',ctx,a,b))
def try_open(ctx,z,seal,chk):
    return xor(seal,H('output-pad',ctx,z)) if H('check',ctx,z)==chk else None

def run():
    n=0
    for i in range(100):
        ctx=H('context',i)
        x,y,z,nrows,arows,seal,chk,sig=garble(ctx,i)
        # Neither consistent assignment has R=1.
        for b in (0,1):
            ny=eval_not(ctx,x[b],nrows)
            assert ny==y[1-b]
            rz=eval_and(ctx,x[b],ny,arows)
            assert rz==z[0]
            assert try_open(ctx,rz,seal,chk) is None
            n+=3
        # Using public label x0 to compute y1, and public label x1,
        # the attacker can forge an input to the AND gate which never
        # occurs in any consistent assignment to the original witness x.
        attacker_y1=eval_not(ctx,x[0],nrows)
        attacker_z1=eval_and(ctx,x[1],attacker_y1,arows)
        assert attacker_z1==z[1]
        assert try_open(ctx,attacker_z1,seal,chk)==sig
        n+=2
        assert try_open(ctx,attacker_z1,seal,H('wrong-check',ctx)) is None
        n+=1
    return {'assertions':n,'run':'R224-LOCAL-GARBLED-FALSE',
        'relation':'R(x)=x AND NOT(x), false for x=0 and x=1',
        'source_sha256':hashlib.sha256(open(__file__,'rb').read()).hexdigest(),
        'result':'garbled local-input wire mixing opens the sealed accepted-output capability without a globally consistent input',
        'scope':'100 synthetic seeded circuits; no real source, no native signature, no QPT or WE'}
if __name__=='__main__':print(json.dumps(run(),sort_keys=True,indent=2))
