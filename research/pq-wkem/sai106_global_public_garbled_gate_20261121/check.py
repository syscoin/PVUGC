#!/usr/bin/env python3
"""SHA256-only point-and-permute garbling: full global circuit, PUBLIC input labels.
Synthetic global verifier x AND (NOT x) is FALSE; OR variant is TRUE.
Not an original Bitcoin/Syscoin witness or quantum/Bitcoin test.
"""
import hashlib, json, random

L=32

def H(tag, *parts):
    b=tag
    for part in parts:
        b+=len(part).to_bytes(4,"big")+part
    return hashlib.sha256(b).digest()

def xx(a,b): return bytes(x^y for x,y in zip(a,b))

def wire(rng):
    p=rng.randrange(2)
    return (rng.randbytes(31)+bytes([2*rng.randrange(128)+p]),
            rng.randbytes(31)+bytes([2*rng.randrange(128)+1-p]))

def p(lab): return lab[-1]&1

def build(seed, op, secret):
    rng=random.Random(seed)
    x0,x1=wire(rng)
    y0,y1=wire(rng)
    z0,z1=wire(rng)
    X=[x0,x1];Y=[y0,y1];Z=[z0,z1]
    nrows=[None]*2; grows=[None]*4
    for x in (0,1):
        idx=p(X[x])
        nrows[idx]=xx(Y[1-x],H(b"not-gate-106",X[x]))
    for x in (0,1):
        for y in (0,1):
            bit=(x & y) if op=="AND" else (x | y)
            idx=2*p(X[x])+p(Y[y])
            grows[idx]=xx(Z[bit],H(b"global-gate-106",X[x],Y[y]))
    terminal=xx(secret,H(b"terminal-106",Z[1]))
    # Public capsule contains both raw input labels, which are needed for permissionless bit selection.
    C={"inputs":X,"not_rows":nrows,"gate_rows":grows,"terminal":terminal}
    return C, (X,Y,Z)

def open_w(C,x):
    Lx=C["inputs"][x]
    Ly=xx(C["not_rows"][p(Lx)],H(b"not-gate-106",Lx))
    Lz=xx(C["gate_rows"][2*p(Lx)+p(Ly)],H(b"global-gate-106",Lx,Ly))
    return xx(C["terminal"],H(b"terminal-106",Lz)),Lz,Ly

def extract_false(C):
    # Obtain y=1 from an evaluation of NOT with x=0; combine it with x=1.
    Lx1=C["inputs"][1]
    Lx0=C["inputs"][0]
    Ly1=xx(C["not_rows"][p(Lx0)],H(b"not-gate-106",Lx0))
    Lz1=xx(C["gate_rows"][2*p(Lx1)+p(Ly1)],H(b"global-gate-106",Lx1,Ly1))
    return xx(C["terminal"],H(b"terminal-106",Lz1)), Lz1

def main():
    cases=0
    for seed in range(100,164):
        secret=H(b"UNFUNDED PUBLIC TEST PAYLOAD",seed.to_bytes(4,"big"))
        C,(X,Y,Z)=build(seed,"AND",secret)
        # No whole assignment x satisfies x AND NOT x.
        assert all((x & (1-x))==0 for x in (0,1))
        out=[]
        for x in (0,1):
            recv,label,not_label=open_w(C,x)
            assert label==Z[0] and not_label==Y[1-x]
            out.append(recv)
        assert all(o!=secret for o in out)
        recovered,Lz1=extract_false(C)
        assert recovered==secret and Lz1==Z[1]
        # True fixture: x OR NOT x, every w opens SAME secret.
        Ctrue,(XT,YT,ZT)=build(seed+500,"OR",secret)
        assert all((x | (1-x))==1 for x in (0,1))
        assert all(open_w(Ctrue,x)[0]==secret for x in (0,1))
        cases+=1
    example_seed=121
    sec=H(b"UNFUNDED PUBLIC TEST PAYLOAD",example_seed.to_bytes(4,"big"))
    C,_=build(example_seed,"AND",sec)
    result={"candidate":"global SHA256 point-and-permute garbled circuit with both PUBLIC input bit labels",
     "false_predicate":"x AND NOT x, no satisfying whole x",
     "true_predicate":"x OR NOT x, both witnesses 0 and 1 accepted",
     "cases":cases,"false_secret_from_inconsistent_gates":extract_false(C)[0].hex(),
     "expected_test_secret":sec.hex(),"false_recovered_without_original_witness":extract_false(C)[0]==sec,
     "true_same_frozen_output_for_both_witnesses":True,
     "scope":"synthetic two-gate circuit only; no original source, FE, Bitcoin, native signatures, QPT, or actual SHA PoW certificates"}
    print(json.dumps(result,sort_keys=True,indent=2))

if __name__=='__main__':main()
