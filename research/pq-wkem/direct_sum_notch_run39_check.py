#!/usr/bin/env python3
from fractions import Fraction
from collections import Counter, defaultdict
from itertools import product
from math import comb, ceil, log2
import json

P_OPTIONAL = Fraction(4,5)
PREDS = (1,2,7,7)


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


def gf2_solve(A,b):
    M=[row[:] + [bb] for row,bb in zip(A,b)]
    m=len(M); n=len(A[0]); r=0; piv=[]
    for c in range(n):
        p=next((i for i in range(r,m) if M[i][c]),None)
        if p is None:
            continue
        M[r],M[p]=M[p],M[r]
        for i in range(m):
            if i!=r and M[i][c]:
                M[i]=[x^y for x,y in zip(M[i],M[r])]
        piv.append(c); r+=1
    for i in range(r,m):
        if not any(M[i][:n]) and M[i][-1]:
            return None
    x=[0]*n
    for i,p in enumerate(piv):
        x[p]=M[i][-1]
    return tuple(x)


def rank_gf2(A):
    if not A:
        return 0
    M=[row[:] for row in A]
    m=len(M); n=len(M[0]); r=0
    for c in range(n):
        p=next((i for i in range(r,m) if M[i][c]),None)
        if p is None:
            continue
        M[r],M[p]=M[p],M[r]
        for i in range(r+1,m):
            if M[i][c]:
                M[i]=[x^y for x,y in zip(M[i],M[r])]
        r+=1
        if r==m:
            break
    return r


def csp_system(pred_masks=PREDS):
    W=2; G=len(pred_masks); n=4+4*G
    rows=[]; bs=[]
    def add(ids,rhs=0):
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


def source_gap(pred_masks=PREDS):
    best=0
    for x,y in product([0,1],repeat=2):
        idx=2*x+y
        sat=sum((mask>>idx)&1 for mask in pred_masks)
        best=max(best,sat)
    return Fraction(len(pred_masks)-best,len(pred_masks))


H0,b0,tidx0=csp_system()
K0=gf2_nullspace_basis(H0)
a0=gf2_solve(H0,b0)
assert a0 is not None and len(K0)==2
assert source_gap()==Fraction(1,4)


def local_transition_types():
    out=Counter()
    for j in tidx0:
        syn=tuple(k[j] for k in K0)
        s=syn[0] | (syn[1]<<1)
        out[(s,a0[j])] += 1
    return out


TYPES=local_transition_types()
EXPECTED_TYPES=Counter({(2,0):4,(1,0):3,(3,1):3,(0,1):2,(0,0):2,(3,0):1,(1,1):1})
assert TYPES==EXPECTED_TYPES and sum(TYPES.values())==16


def direct_sum_system(m):
    n0=len(H0[0]); rows=[]; bs=[]; test_idx=[]
    for g in range(m):
        off=g*n0
        for row,bb in zip(H0,b0):
            big=[0]*(m*n0)
            big[off:off+n0]=row
            rows.append(big); bs.append(bb)
        test_idx.extend(off+j for j in tidx0)
    return rows,bs,test_idx


def canonical_nullspace_basis(m):
    n0=len(H0[0]); N=m*n0+1
    basis=[]
    for g in range(m):
        off=g*n0
        for k in K0:
            v=[0]*N
            v[off:off+n0]=k
            basis.append(tuple(v))
    odd=[0]*N
    for g in range(m):
        off=g*n0
        odd[off:off+n0]=a0
    odd[-1]=1
    basis.append(tuple(odd))
    return basis


def direct_augmented_rows(m):
    H,b,_=direct_sum_system(m)
    return [row+[bb] for row,bb in zip(H,b)]


def dot2(a,b):
    return sum(x*y for x,y in zip(a,b))&1


def canonical_basis_checks(max_m=6):
    rows=[]
    for m in range(1,max_m+1):
        A=direct_augmented_rows(m)
        B=canonical_nullspace_basis(m)
        assert all(all(dot2(row,v)==0 for row in A) for v in B)
        nullity=len(A[0])-rank_gf2(A)
        assert nullity==2*m+1==len(B)
        assert rank_gf2([list(v) for v in B])==len(B)
        rows.append({"m":m,"augmented_columns":len(A[0]),"nullity":nullity})
    return rows


def xor_tuple(a,b):
    return tuple(x^y for x,y in zip(a,b))


def quotient_basis(H,b):
    return gf2_nullspace_basis([row+[bb] for row,bb in zip(H,b)])


def syndrome_of_coord(basis,j):
    return tuple(v[j] for v in basis)


def convolve(a,b):
    out=defaultdict(Fraction)
    for x,px in a.items():
        if not px: continue
        for y,py in b.items():
            if py:
                out[xor_tuple(x,y)] += px*py
    return out


def one_step_generic(H,b,test_idx,p):
    basis=quotient_basis(H,b)
    delta=tuple(v[-1] for v in basis)
    zero=(0,)*len(basis)
    dist=defaultdict(Fraction); dist[zero]+=1-p
    for j in test_idx:
        dist[syndrome_of_coord(basis,j)] += p/Fraction(len(test_idx))
    return basis,delta,dist


def generic_cycles(m,C):
    H,b,tidx=direct_sum_system(m)
    basis,delta,d1=one_step_generic(H,b,tidx,Fraction(1))
    _,delta2,d2=one_step_generic(H,b,tidx,P_OPTIONAL)
    assert delta2==delta
    cyc=convolve(d1,d2)
    d={(0,)*len(basis):Fraction(1)}
    for _ in range(C):
        d=convolve(d,cyc)
    return basis,delta,d


def tv_shift(dist,delta):
    keys=set(dist)
    keys.update(xor_tuple(x,delta) for x in dist)
    return Fraction(1,2)*sum(abs(dist.get(x,0)-dist.get(xor_tuple(x,delta),0)) for x in keys)


def histogram_step(dist,m,p_activation):
    out=defaultdict(Fraction)
    if p_activation!=1:
        for st,pr in dist.items():
            out[st]+=pr*(1-p_activation)
    if p_activation==0:
        return out
    for (c1,c2,c3,p),pr in dist.items():
        cs=[m-c1-c2-c3,c1,c2,c3]
        for s,csn in enumerate(cs):
            if csn==0:
                continue
            for (d,dp),mult in TYPES.items():
                ns=s^d
                nc=[c1,c2,c3]
                if s:
                    nc[s-1]-=1
                if ns:
                    nc[ns-1]+=1
                out[(nc[0],nc[1],nc[2],p^dp)] += (
                    pr*p_activation*Fraction(csn,m)*Fraction(mult,16)
                )
    return out


def histogram_cycles(m,C):
    d={(0,0,0,0):Fraction(1)}
    peak=1
    for _ in range(C):
        d=histogram_step(d,m,Fraction(1)); peak=max(peak,len(d))
        d=histogram_step(d,m,P_OPTIONAL); peak=max(peak,len(d))
    return d,peak


def histogram_tv(dist):
    by={}
    for (c1,c2,c3,p),pr in dist.items():
        by.setdefault((c1,c2,c3),[Fraction(0),Fraction(0)])[p]+=pr
    return sum(abs(v[0]-v[1]) for v in by.values())


def histogram_map_success(dist):
    return (1+histogram_tv(dist))/2


def frac(x):
    return f"{x.numerator}/{x.denominator}" if x.denominator!=1 else str(x.numerator)


def direct_generic_crosschecks():
    out=[]
    for m in (1,2,3,4):
        for C in (1,2):
            basis,delta,dg=generic_cycles(m,C)
            tvg=tv_shift(dg,delta)
            dh,peak=histogram_cycles(m,C)
            tvh=histogram_tv(dh)
            assert tvg==tvh
            out.append({
                "m":m,"cycles":C,"quotient_dimension":len(basis),
                "generic_complete_tv":frac(tvg),"histogram_dp_tv":frac(tvh),
                "generic_support":len(dg),"histogram_states":len(dh),"peak_histogram_states":peak,
            })
    return out


def signed_slot_norms():
    # Signed mass d(s)=P(s,p=0)-P(s,p=1).
    mand={}
    opt={}
    for s in range(4):
        n0=TYPES.get((s,0),0); n1=TYPES.get((s,1),0)
        mand[s]=Fraction(n0-n1,16)
        opt[s]=(Fraction(1,5) if s==0 else 0)+Fraction(4,5)*mand[s]
    mnorm=sum(abs(v) for v in mand.values())
    onorm=sum(abs(v) for v in opt.values())
    assert mand=={0:Fraction(0),1:Fraction(1,8),2:Fraction(1,4),3:Fraction(-1,8)}
    assert opt=={0:Fraction(1,5),1:Fraction(1,10),2:Fraction(1,5),3:Fraction(-1,10)}
    assert mnorm==Fraction(1,2) and onorm==Fraction(3,5)
    return {
        "mandatory_signed_mass":{str(k):frac(v) for k,v in mand.items()},
        "optional_signed_mass":{str(k):frac(v) for k,v in opt.items()},
        "mandatory_l1":frac(mnorm),"optional_l1":frac(onorm),
        "per_cycle_collision_free_tv":frac(mnorm*onorm),
    }


def collision_upper_bound(m,C):
    # At most 2C active hits. Union bound over pair collisions.
    return min(Fraction(1),Fraction(comb(2*C,2),m))


def asymptotic_table():
    rows=[]
    for C in range(1,7):
        ideal=Fraction(3,10)**C
        for m in (100,1000,10000):
            if m<2*C:
                continue
            d,peak=histogram_cycles(m,C)
            tv=histogram_tv(d)
            eps=collision_upper_bound(m,C)
            lower=max(Fraction(0),ideal-2*eps)
            upper=min(Fraction(1),ideal+2*eps)
            assert lower<=tv<=upper
            rows.append({
                "cycles":C,"gadgets":m,"exact_tv":frac(tv),"exact_tv_float":float(tv),
                "collision_free_limit":frac(ideal),"limit_float":float(ideal),
                "union_collision_bound":frac(eps),
                "proved_tv_interval_from_coupling":[frac(lower),frac(upper)],
                "peak_dp_states":peak,
            })
    return rows


def polynomial_false_family():
    # Illustrative asymptotic instantiations with c=1/4: C=ceil(log2(lambda)/4).
    # Choose m so 2*collision_bound <= ideal/2, i.e. m >= 4*binom(2C,2)/ideal.
    rows=[]
    for lam in (256,1024,4096,16384,65536):
        C=ceil(log2(lam)/4)
        ideal=Fraction(3,10)**C
        needed=ceil(Fraction(4*comb(2*C,2),1)/ideal) if C else 1
        m=max(2*C,needed)
        d,peak=histogram_cycles(m,C)
        tv=histogram_tv(d)
        eps=collision_upper_bound(m,C)
        assert 2*eps<=ideal/Fraction(2)
        assert tv>=ideal/2
        rows.append({
            "lambda":lam,"cycles":C,"gadgets":m,
            "collision_free_limit":frac(ideal),"exact_false_tv":frac(tv),
            "exact_false_tv_float":float(tv),"proved_lower_bound":frac(ideal/2),
            "map_guess_advantage_over_half":float(tv/2),"peak_dp_states":peak,
        })
    return {
        "choice":"C=ceil(log2(lambda)/4); m>=4*binom(2C,2)/(3/10)^C",
        "asymptotic_note":"m is polynomial because (10/3)^C=lambda^(log2(10/3)/4) up to ceiling constants; exact public DP is polynomial in C and log m arithmetic size",
        "rows":rows,
    }


def main():
    result={
        "run":39,
        "starting_head":"1a772a7bcdb1b3ee8dbdd6e031550f87fe49f58a",
        "false_gadget":{
            "predicates":list(PREDS),"source_gap":frac(source_gap()),
            "local_variables":len(H0[0]),"local_constraints":len(H0),
            "local_kernel_dimension":len(K0),"transition_types":{f"{s}:{p}":n for (s,p),n in sorted(TYPES.items())},
        },
        "canonical_basis_checks":canonical_basis_checks(),
        "signed_slot_analysis":signed_slot_norms(),
        "generic_vs_histogram_crosschecks":direct_generic_crosschecks(),
        "finite_convergence":asymptotic_table(),
        "polynomial_false_family":polynomial_false_family(),
        "claims":{
            "proved":[
                "canonical direct-sum quotient basis has 2m local kernel coordinates plus one global key-parity coordinate",
                "exact histogram likelihood DP computes the complete key-conditioned quotient law in polynomial time for C=O(log lambda)",
                "collision-free direct-sum TV is exactly (3/10)^C by sign-coherent mandatory/optional slot symmetrization",
                "actual direct-sum TV differs from the collision-free value by at most twice the active-hit collision probability",
                "a polynomial-size false direct-sum family therefore has inverse-polynomial complete TV and an explicit polynomial-time MAP distinguisher"
            ],
            "tested":[
                "canonical nullspace identities for m=1..6",
                "exact generic quotient TV equals histogram-DP TV for m=1..4 and C=1,2",
                "finite exact convergence tables for C=1..6 and m=100,1000,10000",
                "illustrative polynomial false-family parameter rows"
            ],
            "not_proved":[
                "security or insecurity of unrelated high-entropy correlated channels outside this direct-sum/notch construction",
                "a generic impossibility theorem for witness encryption",
                "a completed generic-NP PQ witness KEM"
            ]
        }
    }
    print(json.dumps(result,indent=2,sort_keys=True))

if __name__=="__main__":
    main()
