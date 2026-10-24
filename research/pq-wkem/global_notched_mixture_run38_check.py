#!/usr/bin/env python3
from fractions import Fraction
from collections import Counter
from itertools import product
from math import comb, log2
import json

P1 = Fraction(1,1)
P2 = Fraction(4,5)

def gf2_nullspace_basis(A):
    M=[row[:] for row in A]
    if not M:
        return []
    m=len(M); n=len(M[0]); r=0; piv=[]
    for c in range(n):
        p=next((i for i in range(r,m) if M[i][c]),None)
        if p is None:
            continue
        M[r],M[p]=M[p],M[r]
        for i in range(m):
            if i!=r and M[i][c]:
                M[i]=[a^b for a,b in zip(M[i],M[r])]
        piv.append(c); r+=1
        if r==m:
            break
    free=[c for c in range(n) if c not in piv]
    basis=[]
    for f in free:
        v=[0]*n; v[f]=1
        for i,p in enumerate(piv):
            if M[i][f]:
                v[p]=1
        basis.append(tuple(v))
    return basis

def quotient_basis(H,b):
    # R^\perp = {(z,t): H z + t b = 0}
    return gf2_nullspace_basis([row+[bi] for row,bi in zip(H,b)])

def csp_system(pred_masks):
    # Two global proof bits; each 2-query test gets a 4-coordinate local-state block.
    W=2; G=len(pred_masks); n=4+4*G
    rows=[]; bs=[]
    def add(ids, rhs=0):
        row=[0]*n
        for i in ids:
            row[i]^=1
        rows.append(row); bs.append(rhs)
    add([0,1],1); add([2,3],1)
    for g,mask in enumerate(pred_masks):
        base=4+4*g
        add([base+i for i in range(4)],1)
        add([1,base+2,base+3],0)
        add([3,base+1,base+3],0)
        add([base+i for i in range(4) if (mask>>i)&1],1)
    return rows,bs,list(range(4,n))

def generic_csp_system(W, tests):
    n=2*W+4*len(tests)
    rows=[]; bs=[]
    def add(ids,rhs=0):
        row=[0]*n
        for i in ids:
            row[i]^=1
        rows.append(row);bs.append(rhs)
    for i in range(W):
        add([2*i,2*i+1],1)
    for g,(i,j,mask) in enumerate(tests):
        base=2*W+4*g
        add([base+k for k in range(4)],1)
        add([2*i+1,base+2,base+3],0)
        add([2*j+1,base+1,base+3],0)
        add([base+k for k in range(4) if (mask>>k)&1],1)
    return rows,bs,list(range(2*W,n))

def source_gap_two_bits(pred_masks):
    G=len(pred_masks); best=0
    for x,y in product([0,1],repeat=2):
        idx=2*x+y
        sat=sum((mask>>idx)&1 for mask in pred_masks)
        best=max(best,sat)
    return Fraction(G-best,G)

def source_false_two_bits(pred_masks):
    return source_gap_two_bits(pred_masks)>0

def generic_gap(W,tests):
    G=len(tests); best=0
    for a in product([0,1],repeat=W):
        sat=0
        for i,j,mask in tests:
            idx=2*a[i]+a[j]
            sat += (mask>>idx)&1
        best=max(best,sat)
    return Fraction(G-best,G)

def syndrome_of_coord(basis,j):
    return tuple(v[j] for v in basis)

def xor_tuple(a,b):
    return tuple(x^y for x,y in zip(a,b))

def one_step(H,b,test_idx,p):
    basis=quotient_basis(H,b)
    delta=tuple(v[-1] for v in basis)
    zero=(0,)*len(basis)
    dist=Counter()
    dist[zero]+=1-p
    N=len(test_idx)
    for j in test_idx:
        dist[syndrome_of_coord(basis,j)] += p/Fraction(N)
    return basis,delta,dist

def convolve(a,b):
    out=Counter()
    for x,px in a.items():
        if not px: continue
        for y,py in b.items():
            if py:
                out[xor_tuple(x,y)] += px*py
    return out

def cycle_dist(H,b,test_idx):
    basis,delta,d1=one_step(H,b,test_idx,P1)
    basis2,delta2,d2=one_step(H,b,test_idx,P2)
    assert basis2==basis and delta2==delta
    return basis,delta,convolve(d1,d2)

def tv_shift(dist,delta):
    keys=set(dist)
    keys.update(xor_tuple(x,delta) for x in dist)
    return Fraction(1,2)*sum(abs(dist.get(x,0)-dist.get(xor_tuple(x,delta),0)) for x in keys)

def odd_character_biases(basis,dist):
    d=len(basis)
    delta=tuple(v[-1] for v in basis)
    vals=[]
    for a in product([0,1],repeat=d):
        if sum(x*y for x,y in zip(a,delta))%2 != 1:
            continue
        val=sum(p*((-1)**(sum(x*y for x,y in zip(a,s))%2)) for s,p in dist.items())
        vals.append((a,val))
    return vals

def frac(x):
    return f"{x.numerator}/{x.denominator}" if x.denominator!=1 else str(x.numerator)

def fixture(pred_masks):
    H,b,tidx=csp_system(tuple(pred_masks))
    basis,delta,d=cycle_dist(H,b,tidx)
    tv=tv_shift(d,delta)
    chars=odd_character_biases(basis,d)
    return {
        "predicates": list(pred_masks),
        "source_gap": frac(source_gap_two_bits(tuple(pred_masks))),
        "quotient_dimension": len(basis),
        "support_size": sum(1 for p in d.values() if p),
        "complete_tv": frac(tv),
        "complete_map_success": frac((1+tv)/2),
        "max_odd_character_bias": frac(max(abs(v) for _,v in chars)) if chars else "0",
    }

def true_fixture(pred_masks):
    H,b,tidx=csp_system(tuple(pred_masks))
    basis,delta,d=cycle_dist(H,b,tidx)
    tv=tv_shift(d,delta)
    return {
        "predicates":list(pred_masks),
        "quotient_dimension":len(basis),
        "complete_tv":frac(tv),
        "public_map_success":frac((1+tv)/2),
    }

def fixed_filter_checks():
    # psi(r)=(1/2-r)(3/5-4r/5)
    def psi(r):
        return (Fraction(1,2)-r)*(Fraction(3,5)-Fraction(4,5)*r)
    assert psi(Fraction(0))==Fraction(3,10)
    assert psi(Fraction(1,4))==Fraction(1,10)
    assert psi(Fraction(1,2))==0
    assert psi(Fraction(3,4))==0
    assert psi(Fraction(1))==Fraction(1,10)
    assert psi(Fraction(5,8))==Fraction(-1,80)
    checked=0; worst=Fraction(0); worst_r=None
    for den in range(4,129):
        for num in range(den+1):
            r=Fraction(num,den)
            if r<Fraction(1,4):
                continue
            v=abs(psi(r)); checked+=1
            if v>worst:
                worst=v;worst_r=r
            assert v<=Fraction(1,10)
    return {
        "rational_points_checked":checked,
        "honest_bias":frac(psi(Fraction(0))),
        "false_fixed_mode_bound_for_r_ge_1_4":frac(Fraction(1,10)),
        "worst_grid_value":frac(worst),
        "worst_grid_r":frac(worst_r),
        "roots":[frac(Fraction(1,2)),frac(Fraction(3,4))],
        "vertex_value":frac(psi(Fraction(5,8))),
    }

def exhaustive_small_census():
    total=0; nontrivial=0; no_odd=0
    worst=Fraction(-1); worst_examples=[]
    qdims=Counter(); gaps=Counter()
    for G in (2,3,4):
        for preds in product(range(1,15),repeat=G):
            gap=source_gap_two_bits(preds)
            if gap<Fraction(1,4):
                continue
            total+=1
            H,b,tidx=csp_system(preds)
            basis=quotient_basis(H,b)
            delta=tuple(v[-1] for v in basis)
            if not any(delta):
                no_odd+=1
                continue
            nontrivial+=1
            qdims[len(basis)]+=1; gaps[gap]+=1
            _,_,d=cycle_dist(H,b,tidx)
            tv=tv_shift(d,delta)
            if tv>worst:
                worst=tv; worst_examples=[list(preds)]
            elif tv==worst and len(worst_examples)<12:
                worst_examples.append(list(preds))
    assert total==30874
    assert nontrivial==23680 and no_odd==7194
    assert worst==Fraction(3,20)
    return {
        "qualified_false_gap_ge_1_4":total,
        "nontrivial_odd_mode_cases":nontrivial,
        "no_odd_mode_perfect_hiding_cases":no_odd,
        "worst_complete_tv":frac(worst),
        "worst_complete_map_success":frac((1+worst)/2),
        "sample_worst_predicate_tuples":worst_examples,
        "quotient_dimension_counts":{str(k):v for k,v in sorted(qdims.items())},
        "gap_counts":{frac(k):v for k,v in sorted(gaps.items())},
    }

def larger_stress_fixture():
    tests=[
        (0,2,11),(2,3,4),(2,1,8),(2,0,11),
        (0,3,13),(2,0,1),(1,3,13),(0,3,1),
    ]
    gap=generic_gap(4,tests)
    H,b,tidx=generic_csp_system(4,tests)
    basis,delta,d=cycle_dist(H,b,tidx)
    tv=tv_shift(d,delta)
    assert gap==Fraction(1,4)
    assert tv==Fraction(29,160)
    return {
        "proof_bits":4,
        "tests":[list(t) for t in tests],
        "source_gap":frac(gap),
        "quotient_dimension":len(basis),
        "support_size":sum(1 for p in d.values() if p),
        "complete_tv":frac(tv),
        "complete_map_success":frac((1+tv)/2),
        "note":"deterministic stress fixture; not an exhaustive larger-instance bound",
    }

def repetition_success(n,p_success):
    t=(n-1)//2
    e=1-p_success
    return sum(Fraction(comb(n,k))*e**k*p_success**(n-k) for k in range(t+1))

def outer_map_control():
    honest=Fraction(13,20) # intended witness raw success for one notch cycle
    public_equal=Fraction(13,20) # true predicate mask 1
    public_better=Fraction(7,10) # true predicate mask 7
    rows=[]
    for n in (7,15,31):
        hw=repetition_success(n,honest)
        pe=repetition_success(n,public_equal)
        pb=repetition_success(n,public_better)
        assert pe==hw and pb>=hw
        rows.append({
            "n":n,
            "witness_outer_success":frac(hw),
            "public_map_equal_fixture_outer_success":frac(pe),
            "public_map_better_fixture_outer_success":frac(pb),
            "witness_outer_success_float":float(hw),
            "public_better_float":float(pb),
        })
    return {
        "witness_raw_success":frac(honest),
        "true_mask_1_public_map":frac(public_equal),
        "true_mask_7_public_map":frac(public_better),
        "bounded_distance_repetition_coset_controls":rows,
    }

def logarithmic_handoff():
    rows=[]
    for C in range(1,7):
        ah=Fraction(3,10)**C
        af=Fraction(1,10)**C
        rows.append({
            "cycles":C,
            "steps":2*C,
            "honest_fixed_bias":frac(ah),
            "false_fixed_bias_bound":frac(af),
            "bias_ratio_bound":frac(af/ah),
            "samples_for_unit_inverse_bias_squared_ceiling": (ah.denominator**2 + ah.numerator**2 - 1)//(ah.numerator**2),
        })
    return {
        "per_cycle_honest_bias":"3/10",
        "per_cycle_false_fixed_bound":"1/10",
        "C_equals_c_log2_lambda_exponents":{
            "honest":log2(10/3),
            "false":log2(10),
            "ratio":log2(3),
        },
        "rows":rows,
    }

def main():
    result={
        "run":"38",
        "construction":"two-step notched global block mixture p=(1,4/5), L=4",
        "fixed_mode":fixed_filter_checks(),
        "false_fixtures":{
            "three_singletons":fixture((1,2,4)),
            "multimode_gap_quarter":fixture((1,2,7,7)),
        },
        "true_complete_view":{
            "singleton_accept":true_fixture((1,)),
            "singleton_reject":true_fixture((7,)),
        },
        "small_exhaustive_census":exhaustive_small_census(),
        "larger_stress_fixture":larger_stress_fixture(),
        "outer_map_composition_control":outer_map_control(),
        "logarithmic_handoff":logarithmic_handoff(),
    }
    print(json.dumps(result,indent=2,sort_keys=True))

if __name__=="__main__":
    main()
