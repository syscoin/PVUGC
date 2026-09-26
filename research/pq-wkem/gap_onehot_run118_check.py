#!/usr/bin/env python3
from __future__ import annotations

import itertools
import json
from fractions import Fraction

CHECKS=[]
def ok(name, cond, detail=None):
    if not cond:
        raise AssertionError(f"{name}: {detail}")
    CHECKS.append({"name":name,"detail":detail})

def sat_clause(clause, a):
    return any((a[i] if pos else 1-a[i]) for i,pos in clause)

def violations(formula,a):
    return sum(1 for c in formula if not sat_clause(c,a))

def local_sat_assignments(clause):
    out=[]
    for bits in itertools.product((0,1),repeat=3):
        good=False
        for p,(i,pos) in enumerate(clause):
            lit=bits[p] if pos else 1-bits[p]
            good |= bool(lit)
        if good: out.append(bits)
    return out

def build_compiler(n, formula):
    groups=[]; col=0; var_cols=[]
    for i in range(n):
        g=[col,col+1]; col+=2
        groups.append(g); var_cols.append(g)
    clause_cols=[]; local_lists=[]
    for c in formula:
        loc=local_sat_assignments(c); local_lists.append(loc)
        g=list(range(col,col+len(loc))); col += len(loc)
        groups.append(g); clause_cols.append(g)
    rows=[]; target=[]
    for g in groups:
        row=[0]*col
        for k in g: row[k]=1
        rows.append(row); target.append(1)
    for j,c in enumerate(formula):
        for p,(i,pos) in enumerate(c):
            row=[0]*col
            for k,bits in zip(clause_cols[j],local_lists[j]):
                if bits[p]==1: row[k]+=1
            row[var_cols[i][1]]-=1
            rows.append(row); target.append(0)
    return rows,target,groups,var_cols,clause_cols,local_lists

def matvec(M,z): return [sum(x*y for x,y in zip(r,z)) for r in M]
def l1(z): return sum(abs(x) for x in z)
def l2sq(z): return sum(x*x for x in z)

def negmass(g):
    assert sum(g)==1
    L=sum(abs(x) for x in g)
    assert L%2==1
    return (L-1)//2

def max_occurrence(n,formula):
    occ=[0]*n
    for c in formula:
        for i,_ in c: occ[i]+=1
    return max(occ) if occ else 1

def bad_rep(forbidden):
    # Base affine identity over integers: 011 + 100 - 111 = 000.
    # Coordinatewise bit-complement is an affine map, so applying complements
    # indicated by `forbidden` preserves coefficients summing to one.
    base=[(0,1,1),(1,0,0),(1,1,1)]
    coeff=[1,1,-1]
    pts=[]
    for x in base:
        pts.append(tuple((1-b if f else b) for b,f in zip(x,forbidden)))
    return list(zip(pts,coeff))

def construct_from_assignment(n,formula,comp,a):
    M,t,groups,var_cols,clause_cols,local_lists=comp
    z=[0]*len(M[0])
    for i in range(n): z[var_cols[i][a[i]]]=1
    for j,c in enumerate(formula):
        induced=tuple(a[i] for i,_ in c)
        if sat_clause(c,a):
            k=local_lists[j].index(induced)
            z[clause_cols[j][k]]=1
        else:
            rep=bad_rep(induced)
            for bits,coef in rep:
                k=local_lists[j].index(bits)
                z[clause_cols[j][k]]+=coef
    return z

def round_and_bound(n,formula,comp,z):
    M,t,groups,var_cols,clause_cols,local_lists=comp
    Nv=[]; Nc=[]; a=[]; bad=[]
    for i,gidx in enumerate(var_cols):
        g=[z[k] for k in gidx]
        Ni=negmass(g); Nv.append(Ni)
        if Ni==0:
            if g==[1,0]: a.append(0)
            elif g==[0,1]: a.append(1)
            else: raise AssertionError((i,g))
            bad.append(False)
        else:
            a.append(0); bad.append(True)
    for j,gidx in enumerate(clause_cols):
        Nc.append(negmass([z[k] for k in gidx]))
    V=violations(formula,a)
    Delta=max_occurrence(n,formula)
    # Clauses touching a bad variable can be charged to variable occurrences.
    touched=sum(1 for c in formula if any(bad[i] for i,_ in c))
    allgood_viol=0
    for j,c in enumerate(formula):
        if not sat_clause(c,a) and not any(bad[i] for i,_ in c):
            allgood_viol+=1
            ok(f"allgood_clause_needs_neg_{len(CHECKS)}",Nc[j]>=1,(j,c,a,Nc[j]))
    ok(f"touch_charge_{len(CHECKS)}",touched <= Delta*sum(1 for x in bad if x),(touched,Delta,bad))
    ok(f"viol_bound_{len(CHECKS)}",V <= Delta*sum(Nv)+sum(Nc),(V,Delta,Nv,Nc))
    Ntot=sum(Nv)+sum(Nc)
    ok(f"norm_excess_{len(CHECKS)}",l1(z)==len(groups)+2*Ntot,(l1(z),len(groups),Ntot))
    ok(f"l2_ge_l1_{len(CHECKS)}",l2sq(z)>=l1(z),(l2sq(z),l1(z)))
    return V,Ntot,Delta,Nv,Nc

# 1. Universal group negative-mass and squared-norm facts.
group_cases=0
for width in range(2,8):
    for g in itertools.product(range(-2,4),repeat=width):
        if sum(g)!=1: continue
        N=negmass(g)
        ok(f"group_formula_{width}_{group_cases}",sum(abs(x) for x in g)==1+2*N,g)
        ok(f"group_square_{width}_{group_cases}",sum(x*x for x in g)>=1+2*N,g)
        if N==0:
            ok(f"group_onehot_{width}_{group_cases}",sum(1 for x in g if x==1)==1 and all(x in (0,1) for x in g),g)
        group_cases+=1

# 2. Exact 3-term affine representation of every forbidden local triple.
local_rep_cases=0
for f in itertools.product((0,1),repeat=3):
    rep=bad_rep(f)
    pts=[p for p,c in rep]; cs=[c for p,c in rep]
    ok(f"rep_coeff_sum_{f}",sum(cs)==1)
    ok(f"rep_excludes_bad_{f}",all(p!=f for p in pts),rep)
    rec=tuple(sum(c*p[j] for p,c in rep) for j in range(3))
    ok(f"rep_recovers_bad_{f}",rec==f,(f,rep,rec))
    ok(f"rep_l1_{f}",sum(abs(c) for c in cs)==3)
    ok(f"rep_l2_{f}",sum(c*c for c in cs)==3)
    local_rep_cases+=1

# 3. Upper construction: every Boolean assignment lifts to exact integer preimage
# with l1=l2^2=B+2*(violated clauses).
formulas=[]
for signs in itertools.product((False,True),repeat=3):
    formulas.append((3,[[(0,signs[0]),(1,signs[1]),(2,signs[2])]],"one-clause"))
formulas += [
    (1,[[(0,True),(0,True),(0,True)],[(0,False),(0,False),(0,False)]],"opposed-repeat"),
    (2,[[(0,True),(1,True),(1,True)],[(0,False),(1,False),(1,False)]],"mixed-repeat"),
    (3,[[(0,True),(1,True),(2,True)],[(0,False),(1,False),(2,False)]],"opposed-3var"),
]
upper_cases=0
for fi,(n,formula,label) in enumerate(formulas):
    comp=build_compiler(n,formula); M,t,groups,*_=comp; B=n+len(formula)
    for a in itertools.product((0,1),repeat=n):
        V=violations(formula,a)
        z=construct_from_assignment(n,formula,comp,a)
        ok(f"upper_eq_{fi}_{a}",matvec(M,z)==t,(label,a,z))
        ok(f"upper_l1_{fi}_{a}",l1(z)==B+2*V,(label,a,V,l1(z),B))
        ok(f"upper_l2_{fi}_{a}",l2sq(z)==B+2*V,(label,a,V,l2sq(z),B))
        upper_cases+=1

# 4. Exhaustive exact-solution check for the smallest contradictory repeated-variable formula.
n=1
formula=[[(0,True),(0,True),(0,True)],[(0,False),(0,False),(0,False)]]
comp=build_compiler(n,formula); M,t,groups,var_cols,clause_cols,local_lists=comp
B=n+len(formula); fixture_Delta=max_occurrence(n,formula)
U=min(violations(formula,a) for a in itertools.product((0,1),repeat=n))
# states with negative mass <=1 are enough to capture the exact optimum here
def group_states(width,maxN=1):
    out=[]
    for g in itertools.product(range(-1,3),repeat=width):
        if sum(g)==1 and negmass(g)<=maxN:
            out.append(g)
    return out
vs=group_states(2,1)
cs1=group_states(len(clause_cols[0]),1)
cs2=group_states(len(clause_cols[1]),1)
exact_solutions=0; minL1=10**9; minL2=10**9
for vg in vs:
    for c1 in cs1:
        for c2 in cs2:
            z=list(vg)+list(c1)+list(c2)
            if matvec(M,z)!=t: continue
            exact_solutions+=1
            V,Ntot,D,_,_=round_and_bound(n,formula,comp,z)
            ok(f"global_unsat_lower_{exact_solutions}",U <= D*Ntot,(U,D,Ntot,z))
            minL1=min(minL1,l1(z)); minL2=min(minL2,l2sq(z))
ok("contradiction_has_solutions",exact_solutions>0,exact_solutions)
ok("contradiction_exact_l1",minL1==B+2*U,(minL1,B,U,fixture_Delta))
ok("contradiction_exact_l2",minL2==B+2*U,(minL2,B,U,fixture_Delta))

# 5. Parameter transfer table for a bounded-occurrence gap formula.
# If every Boolean assignment violates >= eps*m clauses, then any integer affine
# preimage has l1,l2^2 >= B + 2 ceil(eps*m/Delta).
param_rows=[]
for Delta in (3,4,5,8):
    for eps in (Fraction(1,32),Fraction(1,16),Fraction(1,8)):
        for m in (64,256):
            # remove unused variables => n<=3m. Worst-case B<=4m.
            n=3*m; B0=n+m
            u=(eps.numerator*m + eps.denominator-1)//eps.denominator
            Nlb=(u+Delta-1)//Delta
            Llb=B0+2*Nlb
            ratio=Fraction(Llb,B0)
            coarse=Fraction(1,1)+eps/Fraction(2*Delta,1)
            ok(f"ratio_coarse_{Delta}_{eps}_{m}",ratio>=coarse,(ratio,coarse))
            param_rows.append({
                "Delta":Delta,"epsilon":str(eps),"m":m,"B_worst":B0,
                "unsat_floor":u,"negative_mass_floor":Nlb,
                "l1_l2sq_lower":Llb,"ratio":str(ratio),"coarse_ratio":str(coarse)
            })

# 6. Modular no-wrap control for the exact contradictory solutions above.
# For any threshold T, q>2(T+1) and coefficients |M_ij|<=1 imply modular equality
# plus l1<=T unwraps to integer equality.
T=B+2*U
q=2*(T+1)+1
mod_controls=0
for vg in vs:
    for c1 in cs1:
        for c2 in cs2:
            z=list(vg)+list(c1)+list(c2)
            if l1(z)>T: continue
            mz=matvec(M,z)
            modok=all((x-y)%q==0 for x,y in zip(mz,t))
            if modok:
                ok(f"nowrap_{mod_controls}",mz==t,(z,mz,t,q,T))
                mod_controls+=1

out={
    "run":118,
    "status":"PASS",
    "total_assertions":len(CHECKS),
    "group_negative_mass_cases":group_cases,
    "local_forbidden_representations":local_rep_cases,
    "upper_assignment_lifts":upper_cases,
    "contradictory_fixture":{
        "B":B,"Delta":fixture_Delta,"minimum_boolean_violations":U,
        "exact_solutions_with_group_negative_mass_at_most_1":exact_solutions,
        "minimum_l1":minL1,"minimum_l2_squared":minL2,
        "theorem_lower_l1":B+2*((U+fixture_Delta-1)//fixture_Delta),
        "explicit_upper_l1":B+2*U,
    },
    "modular_no_wrap_controls":mod_controls,
    "gap_parameter_rows":param_rows,
    "claims":[
        "For the Run-117 one-hot affine compiler, every integer solution has ||z||_1 = B + 2*N where N is total signed negative mass across variable and clause groups.",
        "If U is the minimum number of violated clauses of the 3CNF and Delta is maximum variable occurrence, every integer affine preimage satisfies ||z||_1 >= B + 2*ceil(U/Delta), and ||z||_2^2 obeys the same lower bound.",
        "Every Boolean assignment violating V clauses has an explicit signed affine preimage with ||z||_1 = ||z||_2^2 = B + 2V, using a 3-term representation of each falsifying local triple.",
        "Therefore bounded-occurrence constant-gap 3SAT transfers to a constant multiplicative l1 and squared-l2 affine-preimage gap. This is a semantic/source-gap theorem, not a standard-LWE carrier or QPT security proof."
    ]
}
print(json.dumps(out,indent=2,sort_keys=True))
