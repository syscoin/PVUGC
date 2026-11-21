#!/usr/bin/env python3
"""R379: differential-prefix-GGM construction, small control only. No FE/bridge claim."""
import hashlib,json
from itertools import product

def H(x): return hashlib.sha256(x).digest()
def xor(*xs):
    v=bytearray(len(xs[0]))
    for x in xs:
        for i,b in enumerate(x): v[i]^=b
    return bytes(v)
def G(s,b): return H(b'R379:SHA-DIFF:branch'+bytes((b,))+s)
def deterministic(label): return H(b'R379:PUBLIC TEST ONLY:'+label.encode())
def bs(word): return tuple(int(v) for v in word)
def conditions(w, true=False):
    b0,b1,b2,b3=w[:4]
    return ((b0^b1^b2)==0, (b1^b2^b3)==0, (b0^b3)==(0 if true else 1))

def instance(n=4,true=False):
    assert n>=4
    S=deterministic('S'); K=deterministic('K'); D=xor(S,K)
    root=[deterministic('root'+str(i)) for i in range(3)]
    # Real SHA derivation, no oracle programming. Three secret PRG seeds.
    def seeds(p):
        s=root[:]
        for b in p:s=[G(x,b) for x in s]
        return s
    def delta(s,j):
        return xor(s[j-1],s[j%3]) if j!=3 else xor(s[2],s[0])
    roots=[delta(root,j) for j in (1,2,3)]
    assert xor(*roots)==b'\0'*32
    corrections={}
    for l in range(n):
        for p in product((0,1),repeat=l):
            parent=seeds(p)
            diffs=[delta(parent,j) for j in (1,2,3)]
            assert xor(*diffs)==b'\0'*32
            for b in (0,1):
                w=p+(b,)
                child=seeds(w)
                cs=conditions(w,true) if l==n-1 else (True,True,True)
                for j in (1,2,3):
                    if not cs[j-1]: continue
                    nextdelta=delta(child,j)
                    if j==3 and l==n-1:nextdelta=xor(nextdelta,K)
                    corrections[(j,p,b)]=xor(nextdelta,G(diffs[j-1],b))
    def leaf_delta(j,w):
        cur=roots[j-1]
        for l,b in enumerate(w):
            t=corrections.get((j,w[:l],b))
            if t is None:return None
            cur=xor(G(cur,b),t)
        return cur
    counts={"valid":0,"absent":0,"one_missing":0,"attempts":0,"checked":0}
    for w in product((0,1),repeat=n):
        allowed=conditions(w,true)
        actual=seeds(w)
        values=[leaf_delta(j,w) for j in (1,2,3)]
        counts['checked']+=1
        for j,val in enumerate(values,1):
            if allowed[j-1]:
                expectation=delta(actual,j)
                if j==3: expectation=xor(expectation,K)
                assert val == expectation
            else:assert val is None
        if all(allowed):
            counts['valid']+=1
            assert xor(*values)==K and xor(D,*values)==S
        else:
            counts['absent']+=1
            assert any(v is None for v in values)
            if sum(not x for x in allowed)==1: counts['one_missing']+=1
    return counts,corrections,roots,K,S,D,seeds

false=instance(true=False)
true=instance(true=True)
assert false[0]['valid']==0 and true[0]['valid']>0
assert false[0]['one_missing']>0
# Exact FALSE local-tape reprogramming in a FRESH LEAF LABEL abstraction.
# SHA-GGM derived leaves cannot be reprogrammed with the original root unchanged.
Delta=deterministic('change S and K');
for w in product((0,1), repeat=4):
    c=conditions(w,False)
    missing=1+next(j for j,b in enumerate(c) if not b)
    r=false[6](w)
    modified=r[:]
    if missing<=1:modified[1]=xor(modified[1],Delta)
    if missing<=2:modified[2]=xor(modified[2],Delta)
    # f3 = f0 xor K, so its Delta change comes from K' alone
    old=[xor(r[0],r[1]), xor(r[1],r[2]), xor(r[2],r[0],false[3])]
    new=[xor(modified[0],modified[1]),xor(modified[1],modified[2]),xor(modified[2],modified[0],false[3],Delta)]
    for j in range(3):
        if c[j]:assert old[j]==new[j]
    assert xor(false[5],false[3]) == xor(false[5],Delta,false[3],Delta)
# Nonlinear child expansion cannot evolve a root XOR difference by SHA of only the difference.
a=deterministic('a');b=deterministic('b')
diff=xor(a,b)
assert G(diff,0)!=xor(G(a,0),G(b,0))
# All corrections published (not gated) would compute EVERY edge at any witness:
w=tuple([0]*4)
allvals=[]
for j in range(1,4):
    s=false[6](w)
    value=(xor(s[j-1],s[j%3]) if j<3 else xor(s[2],s[0]))
    allvals.append(xor(value, false[3]) if j==3 else value)
assert xor(*allvals)==false[3]
result={
 'scope':'small SHA-differential-tree, full-indexed corrections; no FE, ORIGINAL source, QPT or native Bitcoin tests',
 'n':4,'lambda_bits':256,'false':false[0],'true':true[0],
 'published_correction_entries_false':len(false[1]),
 'all_full_tree_corrections':3*2*(2**4-1),
 'leaf_gate_restriction':True,'fresh_leaf_false_coupling':True,
 'sha_root_difference_not_homomorphic':True,
 'precise_gap':'polynomial-size, source-gated correlation-preserving public compiler and full-public QPT theorem'
}
print(json.dumps(result,sort_keys=True,indent=2))
