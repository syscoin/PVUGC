#!/usr/bin/env python3
"""3CNF clause-mask release: honest opening and two-point public extraction.
Toy GF(2)^256 arithmetic, no cryptographic or quantum security claim.
"""
import itertools, json, random, hashlib

def tuples(): return itertools.product((0,1),repeat=3)
def bad(c): return tuple(int(l<0) for l in c)
def local(c,w): return tuple(w[abs(l)-1] for l in c)
def sat(c,a): return a != bad(c)
def high(c,a): return int(a==tuple(1-b for b in bad(c)))
def valid(cs,w): return all(sat(c,local(c,w)) for c in cs)

def experiment(cs,n,rng):
    m=len(cs);k=256
    shares=[rng.getrandbits(k) for j in cs]
    masks={(j,i,b):rng.getrandbits(k) for j,c in enumerate(cs) for i in (abs(l)-1 for l in c) for b in (0,1)}
    degree3=[rng.getrandbits(k) for j in cs]
    K=0
    for s in shares:K^=s
    public={};correction={}
    for j,c in enumerate(cs):
        for a in tuples():
            if not sat(c,a):continue
            v=shares[j]
            for k0,l in enumerate(c):v^=masks[j,abs(l)-1,a[k0]]
            v^=degree3[j] if high(c,a) else 0
            public[j,a]=v
    for i in range(n):
        for b in (0,1):
            v=0
            for j,c in enumerate(cs):
                if i in {abs(l)-1 for l in c}:v^=masks[j,i,b]
            correction[i,b]=v
    def D(w):
        v=0
        for j,c in enumerate(cs):
            if high(c,local(c,w)):v^=degree3[j]
        return v
    def open_valid(w):
        assert valid(cs,w)
        v=D(w)
        for j,c in enumerate(cs):v^=public[j,local(c,w)]
        for i,b in enumerate(w):v^=correction[i,b]
        return v
    def raw_attack(z):
        # No satisfying witness: use a virtual local tuple at each violated clause.
        v=D(z)^D(tuple(1-b for b in z))
        for j,c in enumerate(cs):
            a=local(c,z)
            if sat(c,a):v^=public[j,a]
            else:
                for t in tuples():
                    if sat(c,t):v^=public[j,t]
        for i,b in enumerate(z):v^=correction[i,b]
        return v
    tests=0;witnesses=0
    for w in itertools.product((0,1),repeat=n):
        if valid(cs,w):
            witnesses+=1
            assert open_valid(w)==K;tests+=1
        assert raw_attack(w)==K;tests+=1
    return tests,witnesses,K

def run():
    rng=random.Random(20261109)
    examples=[];checks=0;unsat=0;true=0
    for n in range(3,7):
        for trial in range(60):
            cs=[]
            for j in range(n+2):
                ids=rng.sample(range(1,n+1),3)
                cs.append(tuple(i if rng.getrandbits(1) else -i for i in ids))
            c,w,K=experiment(cs,n,rng);checks+=c
            if w:true+=1
            else:unsat+=1
            if trial==0:examples.append({'n':n,'clauses':len(cs),'valid_witnesses':w,'checks':c,'key_check':hashlib.sha256(K.to_bytes(32,'big')).hexdigest()[:16]})
    # All eight clauses forbidden in n=3: no globally satisfying witness.
    cs=[]
    for f in tuples():cs.append(tuple(-(i+1) if f[i] else i+1 for i in range(3)))
    for trial in range(12):
        c,w,_=experiment(cs,3,rng);checks+=c
        assert w==0;unsat+=1
    return {'name':'clause mask with full-degree repair and publicly evaluable correction','checks':checks,'true_formulas':true,'false_formulas':unsat,'false_key_recoveries':unsat,'all_public_attacks_succeeded':True,'examples':examples,'limits':'Toy exact Boolean/XOR arithmetic only. Public D(w) unrestricted; no hash-only generic NP compiler, QPT proof, true Bitcoin/Syscoin PoW or native endpoint.'}
if __name__=='__main__':print(json.dumps(run(),indent=2,sort_keys=True))
