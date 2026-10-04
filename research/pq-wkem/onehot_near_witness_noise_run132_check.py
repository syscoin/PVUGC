#!/usr/bin/env python3
from __future__ import annotations
import itertools, json, math, random
from fractions import Fraction

CHECKS=[]
def ok(name, cond, detail=None):
    if not cond:
        raise AssertionError(f"{name}: {detail}")
    CHECKS.append((name,detail))

def sat_clause(clause, assignment):
    return any((assignment[i] if pos else 1-assignment[i]) for i,pos in clause)

def formula_sat(formula,a):
    return all(sat_clause(c,a) for c in formula)

def local_sat_assignments(clause):
    out=[]
    for bits in itertools.product((0,1), repeat=3):
        if any((bits[p] if pos else 1-bits[p]) for p,(_,pos) in enumerate(clause)):
            out.append(bits)
    return out

def forbidden_local(clause):
    # Unique local triple falsifying the three literals.
    return tuple(0 if pos else 1 for _,pos in clause)

def build_compiler(n, formula):
    groups=[]; names=[]; col=0; var_cols=[]
    for i in range(n):
        g=[col,col+1]; col+=2
        groups.append(g); var_cols.append(g); names += [f"v{i}=0",f"v{i}=1"]
    clause_cols=[]; local_lists=[]
    for j,c in enumerate(formula):
        loc=local_sat_assignments(c); local_lists.append(loc)
        g=list(range(col,col+len(loc))); col += len(loc)
        groups.append(g); clause_cols.append(g)
        names += [f"c{j}:{''.join(map(str,b))}" for b in loc]
    rows=[]; target=[]
    for g in groups:
        row=[0]*col
        for k in g: row[k]=1
        rows.append(row); target.append(1)
    for j,c in enumerate(formula):
        for p,(i,pos) in enumerate(c):
            row=[0]*col
            for k,bits in zip(clause_cols[j],local_lists[j]):
                if bits[p]: row[k]+=1
            row[var_cols[i][1]]-=1
            rows.append(row); target.append(0)
    return rows,target,groups,var_cols,clause_cols,local_lists,names

def matvec(M,z): return [sum(a*b for a,b in zip(row,z)) for row in M]
def l1(z): return sum(abs(x) for x in z)
def nnz(z): return sum(x!=0 for x in z)

def encode_assignment_pseudowitness(n, formula, comp, a):
    M,t,groups,var_cols,clause_cols,local_lists,*_=comp
    z=[0]*len(M[0]); unsat=[]
    for i in range(n): z[var_cols[i][a[i]]]=1
    for j,c in enumerate(formula):
        bits=tuple(a[i] for i,_ in c)
        if sat_clause(c,a):
            idx=local_lists[j].index(bits)
            z[clause_cols[j][idx]] += 1
        else:
            # For the unique forbidden local triple f, pick two local coordinates.
            # x=f xor e0, y=f xor e1, w=f xor e0 xor e1 satisfy x+y-w=f over Z.
            f=bits
            x=(1-f[0],f[1],f[2])
            y=(f[0],1-f[1],f[2])
            w=(1-f[0],1-f[1],f[2])
            assert x in local_lists[j] and y in local_lists[j] and w in local_lists[j]
            z[clause_cols[j][local_lists[j].index(x)]] += 1
            z[clause_cols[j][local_lists[j].index(y)]] += 1
            z[clause_cols[j][local_lists[j].index(w)]] -= 1
            unsat.append(j)
    return z,unsat

def clause_kernel_vector(comp,j):
    M,t,groups,var_cols,clause_cols,local_lists,*_=comp
    # Choose a cube face opposite the forbidden point in local coordinate 2; all four vertices satisfy.
    # The parallelogram relation p00+p11-p01-p10 has zero affine moments.
    loc=local_lists[j]
    # infer forbidden as the one missing Boolean triple
    allp=set(itertools.product((0,1), repeat=3)); f=next(iter(allp-set(loc)))
    fixed=1-f[2]
    p00=(0,0,fixed); p11=(1,1,fixed); p01=(0,1,fixed); p10=(1,0,fixed)
    for p in (p00,p11,p01,p10): assert p in loc
    c=[0]*len(M[0])
    c[clause_cols[j][loc.index(p00)]] += 1
    c[clause_cols[j][loc.index(p11)]] += 1
    c[clause_cols[j][loc.index(p01)]] -= 1
    c[clause_cols[j][loc.index(p10)]] -= 1
    return c

def transpose(M): return [list(x) for x in zip(*M)]
def moddot(a,b,q): return sum(x*y for x,y in zip(a,b))%q
def centered(x,q):
    x%=q
    return x-q if x>q//2 else x

def matmul(A,B,q):
    BT=transpose(B)
    return [[moddot(row,col,q) for col in BT] for row in A]

def nearest_bit(y,q):
    c0=0; c1=q//2
    def dist(a,b): return abs(centered(a-b,q))
    return 0 if dist(y,c0)<=dist(y,c1) else 1

def rw_dist(n):
    return {2*k-n:Fraction(math.comb(n,k),2**n) for k in range(n+1)}
def tv(d1,d2):
    keys=set(d1)|set(d2)
    return sum(abs(d1.get(k,Fraction(0))-d2.get(k,Fraction(0))) for k in keys)/2

def explicit_false_family(n):
    # False by the first two clauses. a=0^n violates only the all-positive x0 clause.
    formula=[[(0,True),(0,True),(0,True)],[(0,False),(0,False),(0,False)]]
    # fillers are all satisfied by 0^n due to the negative x0 literal
    for i in range(1,n):
        formula.append([(0,False),(i,True),(i,True)])
    return formula

# 1) Exhaust theorem on every sign pattern of one clause and every assignment.
case_count=0
for signs in itertools.product((False,True),repeat=3):
    clause=[(0,signs[0]),(1,signs[1]),(2,signs[2])]
    formula=[clause]; n=3; comp=build_compiler(n,formula); M,t,*_=comp
    for a in itertools.product((0,1),repeat=n):
        z,unsat=encode_assignment_pseudowitness(n,formula,comp,a)
        u=sum(not sat_clause(c,a) for c in formula); B=n+len(formula)
        ok(f"one_clause_eq_{signs}_{a}",matvec(M,z)==t)
        ok(f"one_clause_l1_{signs}_{a}",l1(z)==B+2*u,(l1(z),B,u,z))
        ok(f"one_clause_pm1_{signs}_{a}",all(x in (-1,0,1) for x in z))
        ok(f"one_clause_unsat_{signs}_{a}",len(unsat)==u)
        case_count+=1
    c=clause_kernel_vector(comp,0)
    ok(f"kernel_support_{signs}",nnz(c)==4 and l1(c)==4,c)
    ok(f"kernel_exact_{signs}",matvec(M,c)==[0]*len(M),matvec(M,c))

# 2) Mixed and repeated-variable fixtures, exhaustive assignments.
fixtures=[
 (1,[[(0,True),(0,True),(0,True)],[(0,False),(0,False),(0,False)]]),
 (2,[[(0,True),(1,True),(1,True)],[(0,False),(1,False),(1,False)],[(0,True),(0,True),(0,True)]]),
 (3,[[(0,True),(1,False),(2,True)],[(0,False),(1,True),(2,False)],[(0,True),(0,True),(0,True)]])
]
for fi,(n,formula) in enumerate(fixtures):
    comp=build_compiler(n,formula); M,t,*_=comp; B=n+len(formula)
    for a in itertools.product((0,1),repeat=n):
        z,unsat=encode_assignment_pseudowitness(n,formula,comp,a)
        u=sum(not sat_clause(c,a) for c in formula)
        ok(f"fixture_eq_{fi}_{a}",matvec(M,z)==t)
        ok(f"fixture_norm_{fi}_{a}",l1(z)==B+2*u,(l1(z),B,u))
    for j in range(len(formula)):
        c=clause_kernel_vector(comp,j)
        ok(f"fixture_kernel_{fi}_{j}",matvec(M,c)==[0]*len(M) and l1(c)==4)

# 3) Explicit false family with public u=1 pseudowitness, dimensions grow.
family=[]
for n in range(1,11):
    formula=explicit_false_family(n); m=len(formula); B=n+m
    a=(0,)*n; comp=build_compiler(n,formula); M,t,*_=comp
    z,unsat=encode_assignment_pseudowitness(n,formula,comp,a)
    if n<=8:
        ok(f"family_false_{n}",not any(formula_sat(formula,x) for x in itertools.product((0,1),repeat=n)))
    ok(f"family_one_violation_{n}",len(unsat)==1)
    ok(f"family_eq_{n}",matvec(M,z)==t)
    ok(f"family_Bplus2_{n}",l1(z)==B+2,(l1(z),B))
    family.append({"n":n,"m":m,"B":B,"pseudo_l1":l1(z),"columns":len(M[0]),"rows":len(M)})

# 4) Direct Run-115 wrapper attack after arbitrary left mixing H: A=H M, target Ht.
rng=random.Random(1320132)
attack_trials=0
q=257
for n in range(2,9):
    formula=explicit_false_family(n); comp=build_compiler(n,formula); M,t,*_=comp
    a=(0,)*n; z,unsat=encode_assignment_pseudowitness(n,formula,comp,a); B=n+len(formula)
    rows=len(M); cols=len(M[0]); outdim=4
    # With +/-1 errors and these B, |e^T z|<=B+2<q/4, so recovery is deterministic.
    ok(f"attack_margin_{n}",(B+2)<q/4,(B,q))
    for trial in range(40):
        H=[[rng.randrange(q) for _ in range(rows)] for __ in range(outdim)]
        A=matmul(H,M,q); target=[moddot(h,t,q) for h in H]
        s=[rng.randrange(q) for _ in range(outdim)]
        e=[rng.choice((-1,1)) for _ in range(cols)]
        # hp=A^T s + e
        hp=[(sum(A[i][j]*s[i] for i in range(outdim))+e[j])%q for j in range(cols)]
        K=rng.randrange(2); center=0 if K==0 else q//2
        hidden=moddot(s,target,q); d=(center-hidden)%q
        y=(moddot(hp,z,q)+d)%q
        Khat=nearest_bit(y,q)
        ok(f"attack_recover_{n}_{trial}",Khat==K,(n,trial,K,Khat,centered(y-center,q)))
        # exact identity projected error
        ez=sum(ej*zj for ej,zj in zip(e,z))
        ok(f"attack_error_id_{n}_{trial}",centered(y-center,q)==ez,(centered(y-center,q),ez))
        attack_trials+=1

# 5) Exact random-walk TV: B-term honest projected error vs B+2 false pseudowitness error.
tv_table=[]
for B in [3,5,10,20,50,100,200,500,1000]:
    d=tv(rw_dist(B),rw_dist(B+2))
    tv_table.append({"B":B,"tv_B_vs_Bplus2":float(d),"B_times_tv":B*float(d)})
    ok(f"rw_tv_small_{B}",float(d)<(0.5 if B<10 else 0.06),(B,float(d)))
# exact event-transfer controls over every symmetric interval for modest B
for B in [5,10,20,40]:
    p=rw_dist(B); r=rw_dist(B+2); delta=tv(p,r)
    maxT=B+2
    for T in range(maxT+1):
        ph=sum(v for x,v in p.items() if abs(x)<=T)
        pp=sum(v for x,v in r.items() if abs(x)<=T)
        ok(f"event_transfer_{B}_{T}",pp+delta>=ph,(B,T,float(ph),float(pp),float(delta)))

# 6) 4-sparse kernel gives exact bounded-noise distinguisher for left-mixed carrier.
# Enumerate one clause sign pattern, arbitrary H/s irrelevant because c kills HM exactly.
qk=31; E=1
clause=[(0,True),(1,False),(2,True)]; comp=build_compiler(3,[clause]); M,t,*_=comp
c=clause_kernel_vector(comp,0)
# all four error coordinates in [-E,E] => centered |c^T e|<=4E
coords=[i for i,x in enumerate(c) if x]
for vals in itertools.product(range(-E,E+1),repeat=4):
    e=[0]*len(c)
    for i,v in zip(coords,vals): e[i]=v
    ce=sum(ci*ei for ci,ei in zip(c,e))
    ok(f"kernel_noise_bound_{vals}",abs(ce)<=4*E,ce)
# For uniform transcript y, c^T y is uniform; enumerate by varying one coefficient-1 coordinate.
counts={r:0 for r in range(qk)}
j=next(i for i,x in enumerate(c) if x==1)
base=[0]*len(c)
for val in range(qk):
    y=base[:]; y[j]=val
    counts[moddot(c,y,qk)]+=1
ok("uniform_kernel_functional",all(v==1 for v in counts.values()),counts)
uniform_accept=sum(1 for x in range(qk) if abs(centered(x,qk))<=4*E)/qk
ok("uniform_accept_formula",abs(uniform_accept-(8*E+1)/qk)<1e-12,(uniform_accept,(8*E+1)/qk))

out={
 "run":132,
 "status":"PASS",
 "total_assertions":len(CHECKS),
 "near_witness_theorem":{
   "one_clause_assignment_cases":case_count,
   "claim":"For any Boolean assignment a, the Run-117 one-hot compiler has an explicit integer affine preimage z_a with coefficients in {-1,0,1}, M z_a=t, and ||z_a||_1=B+2*u(a), where B=n+m and u(a) is the number of unsatisfied clauses."
 },
 "explicit_false_family":family,
 "direct_noisy_hps_attack":{
   "q":q,"error":"iid Rademacher +/-1","trials":attack_trials,"recoveries":attack_trials,
   "claim":"On the explicit false u=1 family, the B+2 pseudowitness recovers the Run-115 hidden bit after an arbitrary public left mixing A=H M whenever the projected error is within the normal nearest-center radius. In these finite fixtures the recovery is deterministic from the worst-case bound."
 },
 "projected_error_distance":tv_table,
 "sparse_kernel":{
   "kernel_l1":4,"kernel_support":4,"bounded_error_E":E,"q":qk,
   "real_small_event_probability":1.0,
   "uniform_small_event_probability":uniform_accept,
   "distinguishing_advantage":1-uniform_accept,
   "claim":"Every one-hot clause block contains an explicit four-column +/-1 affine parallelogram dependency. For A=H M it remains a public kernel vector, so the corresponding LWE linear combination cancels the secret and leaves only four errors."
 },
 "scope":[
   "Finite checks validate exact compiler identities, explicit false pseudowitnesses, projected-noise identities, and the sparse-kernel distinguisher. They are not hardness evidence.",
   "The attack is classical PPT, so it also refutes QPT hiding for the attacked parameter/error regimes.",
   "This does not rule out a different source compiler with a multiplicative short-preimage gap, a nonlinear carrier, or a public transform that simultaneously preserves all honest witnesses and destroys short dual dependencies.",
   "No claim is made that generic standard-LWE is insecure; the vulnerable public matrix family A=H M is highly structured and retains short public kernel relations."
 ]
}
print(json.dumps(out,indent=2,sort_keys=True))
