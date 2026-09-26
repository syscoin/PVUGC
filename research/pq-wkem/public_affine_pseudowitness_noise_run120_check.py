#!/usr/bin/env python3
from __future__ import annotations

import itertools
import json
import math
import random

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
        if any((bits[p] if pos else 1-bits[p]) for p,(i,pos) in enumerate(clause)):
            out.append(bits)
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

def bad_rep(forbidden):
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
            z[clause_cols[j][local_lists[j].index(induced)]]=1
        else:
            for bits,coef in bad_rep(induced):
                z[clause_cols[j][local_lists[j].index(bits)]]+=coef
    return z

def matvec(M,z): return [sum(a*b for a,b in zip(row,z)) for row in M]
def transpose_matvec(M,s): return [sum(M[i][j]*s[i] for i in range(len(M))) for j in range(len(M[0]))]
def dot(a,b): return sum(x*y for x,y in zip(a,b))
def l1(z): return sum(abs(x) for x in z)
def l2sq(z): return sum(x*x for x in z)

def center_mod(x,q):
    y=x%q
    if y>q//2: y-=q
    return y

def decode_bit(v,q):
    # centers 0 and floor(q/2), by centered circular distance
    c0=0; c1=q//2
    d0=abs(center_mod(v-c0,q)); d1=abs(center_mod(v-c1,q))
    return 0 if d0<=d1 else 1

# ---------------------------------------------------------------------
# 1. Public pseudowitness theorem for the one-hot affine compiler.
# Every Boolean assignment, satisfying or not, gives an exact integer
# affine preimage. Its l1 and l2^2 norms are B+2V(a).
# ---------------------------------------------------------------------
fixtures=[
    (1,[[(0,True),(0,True),(0,True)],[(0,False),(0,False),(0,False)]],"unsat-repeat"),
    (2,[[(0,True),(0,True),(0,True)],[(0,False),(0,False),(0,False)],[(1,True),(1,True),(1,True)]],"unsat-plus-free"),
    (3,[[(0,True),(0,True),(0,True)],[(0,False),(0,False),(0,False)],[(1,True),(2,True),(2,False)]],"unsat-plus-mixed"),
    (2,[[(0,True),(1,True),(1,True)],[(0,False),(1,False),(1,False)]],"mixed-repeat"),
    (3,[[(0,True),(1,True),(2,True)],[(0,False),(1,False),(2,False)]],"opposed-3var"),
]
# Add all single-clause sign patterns, plus deterministic random multi-clause fixtures.
for signs in itertools.product((False,True),repeat=3):
    fixtures.append((3,[[(0,signs[0]),(1,signs[1]),(2,signs[2])]],"single"))
rng=random.Random(202609260645)
for n in (3,4):
    for _ in range(8):
        formula=[]
        for __ in range(4):
            clause=[]
            for ___ in range(3):
                clause.append((rng.randrange(n),bool(rng.randrange(2))))
            formula.append(clause)
        fixtures.append((n,formula,"random"))

assignment_lifts=0
false_public_lifts=0
for fi,(n,formula,label) in enumerate(fixtures):
    comp=build_compiler(n,formula); M,t,groups,*_=comp
    B=n+len(formula)
    formula_sat=False
    for a in itertools.product((0,1),repeat=n):
        V=violations(formula,a)
        if V==0: formula_sat=True
        z=construct_from_assignment(n,formula,comp,a)
        ok(f"lift_eq_{fi}_{a}",matvec(M,z)==t,(label,a,V))
        ok(f"lift_l1_{fi}_{a}",l1(z)==B+2*V,(label,a,V,l1(z),B))
        ok(f"lift_l2_{fi}_{a}",l2sq(z)==B+2*V,(label,a,V,l2sq(z),B))
        ok(f"lift_lt3B_{fi}_{a}",l2sq(z) < 3*B,(label,a,V,l2sq(z),B))
        assignment_lifts+=1
    if not formula_sat:
        # Public all-zero assignment produces an invalid source witness but exact affine preimage.
        a=(0,)*n; V=violations(formula,a); z=construct_from_assignment(n,formula,comp,a)
        ok(f"false_public_nonwitness_{fi}",V>0,(label,V))
        ok(f"false_public_exact_{fi}",matvec(M,z)==t,(label,z))
        false_public_lifts+=1

# ---------------------------------------------------------------------
# 2. Exact noisy projective-hash identity and explicit false-key attack.
# Public c=M^T s+e, noisy target y=t^T s+f, mask d=c_K-y.
# Any affine preimage z (valid source witness or not) computes
# z^T c+d = c_K + z^T e-f.
# ---------------------------------------------------------------------
identity_checks=0
for fi,(n,formula,label) in enumerate(fixtures[:8]):
    comp=build_compiler(n,formula); M,t,groups,*_=comp
    rows=len(M); cols=len(M[0]); B=n+len(formula)
    q=257
    for rep in range(30):
        s=[rng.randrange(q) for _ in range(rows)]
        e=[rng.randrange(-2,3) for _ in range(cols)]
        f=rng.randrange(-2,3)
        c=[(x+ee)%q for x,ee in zip(transpose_matvec(M,s),e)]
        y=(dot(t,s)+f)%q
        K=rng.randrange(2); center=0 if K==0 else q//2
        d=(center-y)%q
        a=tuple(rng.randrange(2) for _ in range(n))
        z=construct_from_assignment(n,formula,comp,a)
        lhs=(dot(z,c)+d)%q
        rhs=(center+dot(z,e)-f)%q
        ok(f"projective_identity_{identity_checks}",lhs==rhs,(label,rep,a,K,lhs,rhs))
        identity_checks+=1
        # An arbitrary extra standard-LWE-looking anchor is irrelevant to the attack.
        U=[[rng.randrange(q) for _ in range(rows)] for __ in range(3)]
        anchor=[(dot(row,s)+rng.randrange(-2,3))%q for row in U]
        ok(f"anchor_ignored_{identity_checks}",len(anchor)==3 and lhs==rhs)

# ---------------------------------------------------------------------
# 3. Gaussian/subgaussian parameter consequence.
# Honest one-hot witness has ||z_h||_2^2=B. Public assignment lift has
# ||z_a||_2^2=B+2V<=B+2m<3B. With iid N(0,sigma^2) coordinate and target
# noise, projected standard deviations are sigma*sqrt(1+||z||_2^2).
# If honest threshold is T=sigma_h*sqrt(2(lambda+1) ln2), Chernoff gives
# honest rejection <=2^-lambda. The public pseudowitness rejection is
# <=2 exp(-T^2/(2 sigma_f^2)), hence its acceptance is overwhelming.
# ---------------------------------------------------------------------
gaussian_rows=[]
for B in (3,8,32,128,512):
    # Worst explicit assignment lift allowed by V<=m<B is bounded by 3B.
    pseudo_l2=3*B-1
    Ch2=(1+B)
    Cf2=(1+pseudo_l2)
    ratio2=Cf2/Ch2
    ok(f"variance_ratio_lt3_{B}",ratio2<3,(B,ratio2))
    for lam in (32,64,128,256):
        T_over_h=math.sqrt(2*(lam+1)*math.log(2))
        honest_fail_bound=2*math.exp(-(T_over_h**2)/2)
        pseudo_T=T_over_h/math.sqrt(ratio2)
        pseudo_fail_exact=math.erfc(pseudo_T/math.sqrt(2))
        pseudo_fail_bound=2*math.exp(-(pseudo_T**2)/2)
        ok(f"honest_bound_{B}_{lam}",honest_fail_bound <= 2.0**(-lam)*(1+1e-12),(honest_fail_bound,2.0**(-lam)))
        ok(f"pseudo_tail_bound_{B}_{lam}",pseudo_fail_exact <= pseudo_fail_bound*(1+1e-12),(pseudo_fail_exact,pseudo_fail_bound))
        ok(f"pseudo_accepts_overwhelming_{B}_{lam}",1-pseudo_fail_exact>0.999,(B,lam,1-pseudo_fail_exact))
        gaussian_rows.append({
            "B":B,"lambda":lam,"variance_ratio":ratio2,
            "threshold_over_honest_std":T_over_h,
            "honest_rejection_upper":honest_fail_bound,
            "pseudowitness_rejection_exact_gaussian":pseudo_fail_exact,
            "pseudowitness_rejection_chernoff_upper":pseudo_fail_bound,
            "pseudowitness_acceptance_exact_gaussian":1-pseudo_fail_exact,
        })

# ---------------------------------------------------------------------
# 4. Asymptotic constant-factor theorem control.
# If T/sigma_h grows, then T/sigma_f grows whenever sigma_f/sigma_h is
# bounded by a constant. Finite samples show both acceptance probabilities
# converge to 1 for the exact Gaussian model.
# ---------------------------------------------------------------------
asymptotic=[]
for C in (math.sqrt(1.1),math.sqrt(1.5),math.sqrt(2),math.sqrt(3)):
    prev=0.0
    for scale in (2,3,4,5,6,8):
        honest_acc=math.erf(scale/math.sqrt(2))
        false_acc=math.erf((scale/C)/math.sqrt(2))
        ok(f"asym_monotone_{C}_{scale}",false_acc>=prev,(C,scale,false_acc,prev))
        ok(f"asym_honest_ge_false_{C}_{scale}",honest_acc>=false_acc,(C,scale,honest_acc,false_acc))
        prev=false_acc
    asymptotic.append({"std_ratio":C,"false_accept_at_8_honest_std":prev})

out={
    "run":120,
    "status":"PASS",
    "total_assertions":len(CHECKS),
    "assignment_lifts":assignment_lifts,
    "false_formula_public_lifts":false_public_lifts,
    "projective_identity_checks":identity_checks,
    "gaussian_parameter_rows":gaussian_rows,
    "asymptotic_controls":asymptotic,
    "claims":[
        "For the Run-117/118 one-hot affine compiler, every Boolean assignment (even one violating clauses) publicly yields an exact affine preimage z with ||z||_1=||z||_2^2=B+2V(a)<3B.",
        "In the natural noisy projective release c=M^T s+e, y=t^T s+f, d=c_K-y, every such affine preimage computes c_K plus projected noise: z^T c+d=c_K+z^T e-f.",
        "Therefore on false statements the public all-zero assignment already gives a source-invalid decapsulation representation; no source witness search is needed.",
        "For iid centered Gaussian noise, its projected standard deviation is only a constant factor (<sqrt(3), including target noise) larger than an honest one-hot witness. Any threshold sequence that accepts honest Gaussian noise with probability tending to one also accepts this public pseudowitness with probability tending to one.",
        "A separate standard-LWE anchor does not repair this syntactic attack because the attacker ignores it and evaluates the structured affine block directly.",
        "The checker establishes algebra/functionality and exact Gaussian tail controls only; it does not establish or refute unrelated nonlinear carriers, superconstant gaps, or arbitrary QPT reductions."
    ],
    "qpt_status":{
        "attack_model":"classical polynomial-time once the one-hot affine compiler and noisy linear release are public; therefore it refutes QPT security of that composition a fortiori",
        "honest_algorithms":"classical",
        "hardness_assumption":"none for the attack",
        "leaky_lwe_note":"Leaky-LWE can protect a standard LWE challenge in the presence of bounded noisy linear leakage, but it does not randomize the leakage itself; this checker does not treat Leaky-LWE as a QPT theorem."
    }
}
print(json.dumps(out,indent=2,sort_keys=True))
