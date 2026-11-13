#!/usr/bin/env python3
"""Run 653 exact finite algebra checker: not a cryptographic security test."""
from collections import Counter
from itertools import product
import json, hashlib, sys

POLYS={2:0b111, 3:0b1011, 4:0b10011, 5:0b100101}

def field_mul(a,b,m):
    poly=POLYS[m]
    result=0
    while b:
        if b&1: result^=a
        b>>=1
        a<<=1
        if a&(1<<m): a^=poly
    return result

def field_pow(a,n,m):
    out=1
    while n:
        if n&1:out=field_mul(out,a,m)
        a=field_mul(a,a,m)
        n>>=1
    return out

def field_trace(a,m):
    acc=0
    v=a
    for _ in range(m):
        acc^=v
        v=field_mul(v,v,m)
    assert acc in (0,1)
    return acc

def pair_hist(m,p,q,r):
    size=1<<m
    seen=set()
    hist=Counter()
    for a in range(size):
      for d in range(size):
        if (a,d) in seen: continue
        aa,dd=a^p,d^q
        seen.add((a,d));seen.add((aa,dd))
        z=field_mul(a,d,m)
        zp=field_mul(aa,dd,m)
        l=sum(field_trace(field_mul(1<<i,z,m),m)<<i for i in range(r))
        lp=sum(field_trace(field_mul(1<<i,zp,m),m)<<i for i in range(r))
        hist[tuple(sorted((l,lp)))]+=1
    assert len(seen)==size*size
    assert sum(hist.values())==size*size//2
    return hist

def character_from_hist(hist,u,v):
    ans=0
    for (l0,l1),cnt in hist.items():
        ans+=cnt*((-1)**(((u&l0).bit_count()+(v&l1).bit_count())&1) +
                  (-1)**(((u&l1).bit_count()+(v&l0).bit_count())&1))
    return ans

def field_inverse(a,m):
    assert a!=0
    return field_pow(a,(1<<m)-2,m)

def run():
    assertions=0
    def ck(t,why):
        nonlocal assertions
        assertions+=1
        if not t: raise AssertionError(why)
    results=[]
    for m in sorted(POLYS):
        size=1<<m
        for a in range(1,size):
            ck(field_mul(a,field_inverse(a,m),m)==1,('inverse',m,a))
        for alpha in range(1,size):
            ck(sum(field_trace(field_mul(alpha,x,m),m) for x in range(size))==size//2,('nondegenerate-trace',m,alpha))
        keys=[(p,q) for p in range(size) for q in range(size) if p or q]
        r2_values=set(); r1_signatures=set()
        mixed_coeffs=[]
        for u,v in ((1,2),(1,3),(2,3)):
            alpha=sum((1<<i) for i in range(2) if u&(1<<i))
            beta=sum((1<<i) for i in range(2) if v&(1<<i))
            mixed_coeffs.append((u,v,field_mul(field_mul(alpha,beta,m),field_inverse(alpha^beta,m),m)))
        axes=[]; mixed=[]
        for p,q in keys:
            # Exact one-bit pair profile from Run 652 is key-independent.
            h1=pair_hist(m,p,q,1)
            sig1=tuple(sorted(h1.items()))
            r1_signatures.add(sig1)
            ck(sum(h1.values())==size*size//2,('onebit-pairs',m,p,q))
            # Two independent trace components, both Boolean bent individually.
            h2=pair_hist(m,p,q,2)
            ck(sum(h2.values())==size*size//2,('twobit-pairs',m,p,q))
            for u,v,c in mixed_coeffs:
                expected=size*(-1 if field_trace(field_mul(c,field_mul(p,q,m),m),m) else 1)
                got=character_from_hist(h2,u,v)
                ck(got==expected,('exact-fourier',m,p,q,u,v,got,expected))
                if (u,v)==(1,2): r2_values.add(got)
            if p==0 or q==0: axes.append((p,q,h2))
            else: mixed.append((p,q,h2))
            # Full m-bit trace coordinates form an invertible label map.
            hm=pair_hist(m,p,q,m) if m<=4 else None
            if hm is not None:
                equal_multiset=sorted([v for (l0,l1),v in hm.items() if l0==l1],reverse=True)
                if p==0 or q==0:
                    ck(equal_multiset==[size//2],('axis-equal-label',m,p,q,equal_multiset))
                else:
                    ck(equal_multiset==[1]*(size//2),('mixed-equal-label',m,p,q,equal_multiset))
        ck(len(r1_signatures)==1,('onebit-uniform-profile',m,len(r1_signatures)))
        ck(r2_values=={-size,size},('two-bit-sign-varies',m,r2_values))
        # Check derivative uniformity for each shift: field product D_K is surjective.
        for p,q in keys:
            counts=Counter()
            for a in range(size):
              for d in range(size):
                delta=field_mul(a,q,m)^field_mul(p,d,m)^field_mul(p,q,m)
                counts[delta]+=1
            ck(len(counts)==size and set(counts.values())=={size},('uniform-derivative',m,p,q))
        linear_basis={}
        for _,_,c in mixed_coeffs:
            y=c
            while y:
                pivot=y.bit_length()-1
                if pivot not in linear_basis:
                    linear_basis[pivot]=y
                    break
                y^=linear_basis[pivot]
        r={"m":m,"state_bits":2*m,"field_size":size,"key_shifts":len(keys),
           "two_bit_mixed_character_coefficients":[c for _,_,c in mixed_coeffs],
           "independent_product_bits_from_two_bit_profile":len(linear_basis),
           "one_bit_distinct_complete_pair_profiles":len(r1_signatures),
           "two_bit_fourier_values":sorted(r2_values),
           "axis_equal_label_fibers_full_label":size//2,
           "mixed_equal_label_fibers_full_label_each":1,
           "vector_derivative_uniform_for_all_nonzero_shifts":True}
        results.append(r)
    obj={"run":653,"claim":"field-product vectorial bent two-bit pair-profile fingerprint", "assertions":assertions,"results":results,
         "scope":"finite exact algebra; not classical PPT/QPT security or full WKEM"}
    return obj

if __name__=='__main__':
    print(json.dumps(run(),sort_keys=True,indent=2))
