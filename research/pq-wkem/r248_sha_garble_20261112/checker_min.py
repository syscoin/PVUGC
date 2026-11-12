#!/usr/bin/env python3
"""R248 minimal SHA-garbled UNSAT test. NOT a witness-KEM/source validator."""
import hashlib, json

def H(*xs):
    return hashlib.sha256(b'\x00'.join(xs)).digest()
def X(a,b):
    return bytes(x^y for x,y in zip(a,b))
def lab(n,b,i):
    return H(b'wire',n,bytes([b]),bytes([i]))[:16]
def wrap(key,value):
    return X(value,H(b'gate',key)[:len(value)])

checked=0
for trial in range(64):
    t=trial.to_bytes(4,'big')
    x=[lab(b'x',b,trial) for b in (0,1)]
    y=[lab(b'y',b,trial) for b in (0,1)]
    o=[lab(b'o',b,trial) for b in (0,1)]
    # Garbling x AND NOT x: fixed labels for a shared input x.
    nt=[wrap(x[b],y[1-b]) for b in (0,1)]
    ag=[[wrap(x[a]+y[b],o[a&b]) for b in (0,1)] for a in (0,1)]
    sigma=H(b'cancel',t)
    E=X(sigma,H(b'release',o[1]))
    for b in (0,1):
        notx=wrap(x[b],nt[b]); assert notx==y[1-b]
        result=wrap(x[b]+notx,ag[b][1-b]); assert result==o[0]
        assert X(E,H(b'release',result))!=sigma
        checked+=1
    # Unauthorized full-public mixed state: x=1 and NOT(x)=1 from x=0.
    notx1=wrap(x[0],nt[0]); assert notx1==y[1]
    out1=wrap(x[1]+notx1,ag[1][1]); assert out1==o[1]
    assert X(E,H(b'release',out1))==sigma
    checked+=1
print(json.dumps({'run':'R248_MIN','trials':64,'consistent_failures_to_open':128,
                  'unauthorized_full_public_recoveries':64,
                  'checked_cases':checked,'original_source_compiler':False,
                  'qpt_security':False},indent=2,sort_keys=True))
