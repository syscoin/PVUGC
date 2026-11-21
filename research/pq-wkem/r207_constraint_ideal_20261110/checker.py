#!/usr/bin/env python3
"""R207 public low-degree constraint-ideal carrier; exact algebra, NOT WKEM."""
import hashlib, itertools, json, random
from collections import Counter
P=257
N=3
counts=Counter()

def add(u,v):
    o=dict(u)
    for m,c in v.items():
        o[m]=(o.get(m,0)+c)%P
        if not o[m]:del o[m]
    return o

def scale(u,s):return {m:(c*s)%P for m,c in u.items() if (c*s)%P}
def mul(u,v):
    w={}
    for a,x in u.items():
        for b,y in v.items():
            m=tuple(i+j for i,j in zip(a,b))
            w[m]=(w.get(m,0)+x*y)%P
    return {m:v for m,v in w.items() if v}

def ev(u,z):
    return sum(c*__import__('math').prod(pow(x,p,P) for x,p in zip(z,m)) for m,c in u.items())%P

zero=(0,)*N
one={zero:1}
v=[{tuple(int(i==j) for i in range(N)):1} for j in range(N)]
a,b,c=v
bools=[add(mul(x,x),scale(x,-1)) for x in (a,b,c)]
# Constraint for SHA-like AND gate c=a*b; mismatch is a XOR b == 1.
constraints=bools + [add(c,scale(mul(a,b),-1)), add(add(a,b),add(scale(mul(a,b),-2),scale(one,-1)))]
# False relation: add mutually inconsistent a==0 and a==1.
constraints_false=bools + [a,add(a,scale(one,-1))]

def monos(d):
    return [i for i in itertools.product(range(d+1),repeat=N) if sum(i)<=d]

def columns(fs,degree=1):
    mon=monos(degree)
    return [mul(f,{m:1}) for f in fs for m in mon]

def rank(A):
    B=[list(row) for row in A]
    h=len(B);w=len(B[0]) if B else 0
    piv=[];r=0
    for j in range(w):
        k=next((k for k in range(r,h) if B[k][j]%P),None)
        if k is None: continue
        B[r],B[k]=B[k],B[r]
        inv=pow(B[r][j],-1,P)
        B[r]=[t*inv%P for t in B[r]]
        for k in range(h):
            if k!=r and B[k][j]:
                factor=B[k][j]
                B[k]=[(x-factor*y)%P for x,y in zip(B[k],B[r])]
        piv.append(j)
        r+=1
        if r==h:break
    return r,piv,B

def recover_k(coeffs,fs):
    # A public attacker solves P = sum_i r_i f_i + K*1, for unknown r_i and K.
    cs=columns(fs)
    basis=sorted(set(m for u in cs+[one,coeffs] for m in u))
    vec=lambda p:[p.get(m,0) for m in basis]
    # Unknowns are mask coefficients plus secret constant K, with K last.
    mat=[[vec(col)[r] for col in cs+[one]]+[vec(coeffs)[r]] for r in range(len(basis))]
    rr,piv,R=rank(mat)
    # Solve linear system for last unknown; if variable unconstrained return None.
    nvar=len(cs)+1
    if any(all(v==0 for v in row[:nvar]) and row[-1] for row in R):return 'INCONSISTENT'
    free=set(range(nvar))-{p for p in piv if p<nvar}
    # If K=last variable free or depends on free variable, not identifiable.
    if nvar-1 in free:return None
    row_idx=piv.index(nvar-1)
    if any(R[row_idx][j] for j in free):return None
    return R[row_idx][-1]%P

def run():
    rng=random.Random(207)
    ws=[z for z in itertools.product((0,1),repeat=N) if all(ev(f,z)==0 for f in constraints)]
    wf=[z for z in itertools.product((0,1),repeat=N) if all(ev(f,z)==0 for f in constraints_false)]
    assert len(ws)==2 and not wf
    counts['two_valid_witnesses']=1
    counts['false_has_no_witnesses']=1
    for fs,expect_true,label in ((constraints,True,'true'),(constraints_false,False,'false')):
        cs=columns(fs)
        # Static public-span test: constant in span iff quotient collapse.
        basis=sorted(set(m for u in cs+[one] for m in u))
        colvec=lambda p:[p.get(m,0) for m in basis]
        A=[[colvec(col)[r] for col in cs] for r in range(len(basis))]
        aug=[row+[colvec(one)[r]] for r,row in enumerate(A)]
        rankA=rank(A)[0]
        rankAug=rank(aug)[0]
        is_constant_in_span=(rankA==rankAug)
        assert is_constant_in_span==(not expect_true)
        counts[label+'_span_condition']+=1
        for t in range(80):
            K=rng.randrange(P)
            mask=[rng.randrange(P) for _ in cs]
            F=add(scale(one,K),{})
            for q,u in zip(mask,cs):F=add(F,scale(u,q))
            recover=recover_k(F,fs)
            if expect_true:
                assert recover==K
                counts['hard_true_public_extraction']+=1
                for z in ws:
                    assert ev(F,z)==K
                    counts['same_precommitted_key_all_witnesses']+=1
                for z in wf:
                    assert not all(ev(f,z)==0 for f in constraints_false)
            else:
                assert recover is None
                counts['false_mask_distribution_independent_of_key']+=1
    # Repair test: SHA-derived pseudorandom mask coefficients in the SAME
    # publicly known constraint-ideal span. No oracle assumption helps: the
    # annihilating public linear functional still extracts K exactly.
    cs=columns(constraints)
    for trial in range(80):
        seed=rng.getrandbits(256).to_bytes(32,'big')  # kept private at Build
        K=rng.randrange(P)
        F=scale(one,K)
        for i,pol in enumerate(cs):
            r=int.from_bytes(hashlib.sha256(
                b'R207/source-constraint-mask\0'+seed+i.to_bytes(4,'big')).digest(),
                'big')%P
            F=add(F,scale(pol,r))
        found=recover_k(F,constraints)
        assert found==K
        counts['sha_seeded_mask_still_publicly_extractable']+=1
        for z in ws:
            assert ev(F,z)==K
            counts['sha_seeded_all_witness_correctness']+=1
        # Simulated frozen native capability is a 32-byte fixture, NOT a
        # Bitcoin-native/SLH signature; D itself must remain fixed.
        sigma=hashlib.sha256(b'R207/synthetic-capability'+seed).digest()
        pad=hashlib.sha256(b'R207/pad'+K.to_bytes(2,'big')).digest()
        D=bytes(x^y for x,y in zip(sigma,pad))
        foundpad=hashlib.sha256(b'R207/pad'+found.to_bytes(2,'big')).digest()
        reconstructed=bytes(x^y for x,y in zip(D,foundpad))
        assert reconstructed==sigma
        counts['unauthorized_synthetic_capability_opening']+=1
    # Failure of naïve SHA-keyed replacement: public seed immediately gives K
    # from any point evaluation if all masks are publicly evaluable. When P is
    # not public and seeds hidden, witness cannot evaluate K from P(w).
    for t in range(80):
        secret=bytes(rng.randrange(256) for _ in range(32))
        sha=lambda t:hashlib.sha256(secret+t).digest()
        assert sha(b'mask-A')!=sha(b'mask-B')
        counts['nonlinear_sha_mask_distinct_outputs_fixture_only']+=1
    return {'run':'R207','field':P,'valid_witnesses':ws,'checks':dict(sorted(counts.items())),
            'total_checks':sum(counts.values()),
            'classification':'full-public linear-span recovery; NOT source-bound WKEM',
            'checker_sha256':hashlib.sha256(open(__file__,'rb').read()).hexdigest()}

if __name__=='__main__':print(json.dumps(run(),indent=2,sort_keys=True))
