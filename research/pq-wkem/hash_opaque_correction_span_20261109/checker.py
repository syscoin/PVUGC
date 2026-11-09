#!/usr/bin/env python3
"""Hash-local correction counterexample, NOT a public release construction.
A hypothetical public D evaluator is simulated using hidden seed-generated masks.
No QPT claim. Public-row attacker uses only records, feature layout and D queries.
"""
import hashlib
import itertools
import json

BAD = [
 [(1,0),(0,0),(3,1)], [(0,1),(1,0),(2,0)],
 [(1,0),(3,0),(2,1)], [(2,0),(0,1),(1,1)],
 [(2,1),(3,1),(0,1)], [(3,1),(2,1),(0,0)],
 [(2,0),(3,0),(0,0)], [(2,1),(3,0),(1,1)],
 [(1,1),(0,0),(2,0)],
]
N = 4
PATTERNS = tuple(itertools.product((0,1),repeat=3))

def local(w,c): return tuple((w>>i)&1 for i,_ in c)
def bad(c): return tuple(1-v for i,v in c)
def accepts(w,clauses): return all(local(w,c)!=bad(c) for c in clauses)
def word(*xs):
    return int.from_bytes(hashlib.sha256(repr(xs).encode()).digest()[:16], 'big')

def instance(clauses):
    dim={}
    for j in range(len(clauses)):dim[('s',j)]=len(dim)
    for j in range(len(clauses)):
        for k in range(3):
            for b in (0,1):dim[('r',j,k,b)]=len(dim)
    for j in range(len(clauses)):
        for a in PATTERNS:dim[('u',j,a)]=len(dim)
    secret={term:word('secret-mask',term) for term in dim}
    rows=[]
    def append(name, terms):
        mask=val=0
        for t in terms:
            mask^=1<<dim[t]
            val^=secret[t]
        rows.append((name,mask,val))
    for j,c in enumerate(clauses):
        for a in PATTERNS:
            if a!=bad(c):
                append(('A',j,a),[('s',j),('u',j,a)]+[('r',j,k,a[k]) for k in range(3)])
    for i in range(N):
        for b in (0,1):
            append(('B',i,b),[('r',j,k,b) for j,c in enumerate(clauses)
                                for k,(v,_) in enumerate(c) if v==i])
    # This D oracle is unimplemented in any public capsule: the test only
    # asks if even *granting* it as a public evaluator could be secure.
    for d in range(4):
        for subset in itertools.combinations(range(N),d):
            z=sum(1<<i for i in subset)
            append(('D',z),[('u',j,local(z,c)) for j,c in enumerate(clauses)])
    K=0;target=0
    for j in range(len(clauses)):
        K^=secret[('s',j)]
        target^=1<<dim[('s',j)]
    return rows,K,target

def recover(rows,target):
    piv={}
    for j,(_,mask,value) in enumerate(rows):
        combination=1<<j
        while mask:
            bit=mask.bit_length()-1
            if bit not in piv:
                piv[bit]=(mask,value,combination)
                break
            a,b,c=piv[bit]
            mask^=a;value^=b;combination^=c
    acc=0;mix=0
    while target:
        bit=target.bit_length()-1
        if bit not in piv:return None,0,len(piv)
        mask,value,comb=piv[bit]
        target^=mask;acc^=value;mix^=comb
    return acc,mix.bit_count(),len(piv)

def opening(rows,w,clauses):
    assert accepts(w,clauses)
    index=dict((name,value) for name,_,value in rows)
    result=0
    for j,c in enumerate(clauses):result^=index[('A',j,local(w,c))]
    for i in range(N):result^=index[('B',i,(w>>i)&1)]
    # Interpolate degree-<=3 D from only Hamming-weight-<=3 queries.
    coeff={}
    for d in range(4):
        for subset in itertools.combinations(range(N),d):
            z=sum(1<<i for i in subset)
            v=index[('D',z)]
            for t in range(d):
                for sub in itertools.combinations(subset,t):v^=coeff[sub]
            coeff[subset]=v
    for subset,v in coeff.items():
        if all((w>>i)&1 for i in subset):result^=v
    return result

def main():
    out={'model':'hypothetical public D(w)=xor SHA-derived per-clause hidden masks',
         'D_queries_per_instance':sum(1 for d in range(4) for _ in itertools.combinations(range(N),d)),
         'cases':[],'checks':0}
    for name,clauses in [('UNSAT-9',BAD),('SAT-8',BAD[1:])]:
        rows,K,target=instance(clauses)
        valid=[w for w in range(1<<N) if accepts(w,clauses)]
        assert bool(valid)==(name=='SAT-8')
        guessed,used,rank=recover(rows,target)
        assert guessed==K
        out['checks']+=2
        for w in valid:
            assert opening(rows,w,clauses)==K
            out['checks']+=1
        out['cases'].append({'name':name,'valid_witness_count':len(valid),
            'raw_extraction_succeeded':True,'attacker_witness_used':False,
            'public_row_count':len(rows),'rank':rank,'rows_used_in_extraction':used,
            'precommitted_K_sha256':hashlib.sha256(K.to_bytes(16,'big')).hexdigest()})
    print(json.dumps(out,sort_keys=True,indent=2))
if __name__=='__main__':main()
