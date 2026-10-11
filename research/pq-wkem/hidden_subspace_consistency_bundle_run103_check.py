#!/usr/bin/env python3
from __future__ import annotations
from itertools import product
from fractions import Fraction
from collections import defaultdict
import json, math

def rank2_vec(vs, n):
    rows=[0]*n
    for j,v in enumerate(vs):
        for i in range(n):
            if (v>>i)&1:
                rows[i] |= 1<<j
    r=0
    cols=len(vs)
    for c in range(cols):
        p=next((i for i in range(r,n) if (rows[i]>>c)&1),None)
        if p is None: continue
        rows[r],rows[p]=rows[p],rows[r]
        for i in range(n):
            if i!=r and ((rows[i]>>c)&1):
                rows[i]^=rows[r]
        r+=1
    return r

def span(vs):
    out={0}
    for v in vs:
        out |= {x^v for x in list(out)}
    return frozenset(out)

def all_subspaces_dim(n,d):
    # Exhaustive via spans of ordered independent generator tuples; deduplicate.
    subs=set()
    vecs=list(range(1,1<<n))
    def rec(gens,start):
        if len(gens)==d:
            subs.add(span(gens)); return
        for v in vecs:
            if v in span(gens): continue
            rec(gens+[v],0)
    rec([],0)
    return sorted(subs,key=lambda s:tuple(sorted(s)))

def orth_subspace(U,n):
    return frozenset(x for x in range(1<<n)
                     if all(((x & u).bit_count() & 1)==0 for u in U))

def mat_from_cols(cols,n):
    # packed n x c matrix, column-major blocks of n bits
    x=0
    for j,v in enumerate(cols):
        x |= v << (j*n)
    return x

def cols_from_mat(M,n,c):
    mask=(1<<n)-1
    return tuple((M>>(j*n))&mask for j in range(c))

def frob(M,N):
    return ((M&N).bit_count() & 1)

def mat_rank(M,n,c):
    return rank2_vec(cols_from_mat(M,n,c),n)

def lin_span_mats(gens):
    return span(gens)

def perp_code(C,ambient_bits):
    return frozenset(x for x in range(1<<ambient_bits)
                     if all(frob(x,y)==0 for y in C))

checks=[]
def ok(name,cond,detail=None):
    if not cond:
        raise AssertionError(f"{name}: {detail}")
    checks.append({"name":name,"detail":detail})

# Tiny fixture: matrices are n x c = 3 x 2 over F2.
n=3; c=2; D=2; m=n-D+1
Us=all_subspaces_dim(n,m)
ok("seven_2d_subspaces",len(Us)==7,len(Us))

# True source: all matrices whose two columns lie in line <e0>.
e0=1
T1=mat_from_cols((e0,0),n)
T2=mat_from_cols((0,e0),n)
C_true=lin_span_mats([T1,T2])
ok("true_dim2",len(C_true)==4)
ok("true_nonzero_rank1",all(mat_rank(y,n,c)==1 for y in C_true if y))

# False source: top 2x2 MRD copy span {I,A}, embedded in 3x2.
# I columns: (1,0,0),(0,1,0); A columns: (0,1,0),(1,1,0)
F1=mat_from_cols((1,2),n)
F2=mat_from_cols((2,3),n)
C_false=lin_span_mats([F1,F2])
ok("false_dim2",len(C_false)==4)
ok("false_nonzero_rank2",all(mat_rank(y,n,c)==2 for y in C_false if y),
   [(y,mat_rank(y,n,c)) for y in C_false if y])

ambient_bits=n*c
allM=range(1<<ambient_bits)

def W_of_U(U):
    return frozenset(mat_from_cols(cols,n) for cols in product(U,repeat=c))

def sum_subspaces(A,B):
    return frozenset(a^b for a in A for b in B)

def K_of(C,U):
    Up=orth_subspace(U,n)
    return frozenset(y for y in C
                     if all(col in Up for col in cols_from_mat(y,n,c)))

# Exact false perfect hiding, conditional on every hidden U.
Cfalse_perp=perp_code(C_false,ambient_bits)
false_records=[]
for idx,U in enumerate(Us):
    W=W_of_U(U)
    K=K_of(C_false,U)
    S=sum_subspaces(Cfalse_perp,W)
    ok(f"false_K_zero_{idx}",len(K)==1,K)
    ok(f"false_sum_full_{idx}",len(S)==1<<ambient_bits,len(S))
    false_records.append({"u_index":idx,"K_size":len(K),"S_size":len(S)})

# True source geometry and rank-one good probability alpha_1.
Ctrue_perp=perp_code(C_true,ambient_bits)
true_records=[]
good=[]
for idx,U in enumerate(Us):
    K=K_of(C_true,U)
    S=sum_subspaces(Ctrue_perp,W_of_U(U))
    codim=round(math.log2((1<<ambient_bits)//len(S)))
    ok(f"duality_size_{idx}",len(K)==(1<<codim),(len(K),codim,len(S)))
    if T1 in K:
        good.append(idx)
    true_records.append({"u_index":idx,"K_size":len(K),"S_size":len(S),"codim":codim})
ok("true_good_count",len(good)==1,good)
alpha=Fraction(len(good),len(Us))
ok("alpha_rank1_formula",alpha==Fraction(1,7),alpha)

# Joint Fourier law for T=3 bundle:
# phi(Y1,Y2,Y3)=fraction of U for which all Yi lie in K_U.
T=3
tuples=list(product(C_true,repeat=T))
phi={}
for Ys in tuples:
    num=sum(1 for U in Us if all(y in K_of(C_true,U) for y in Ys))
    phi[Ys]=Fraction(num,len(Us))
# Any nonzero supported tuple has every nonzero component rank 1 (<D).
for Ys,a in phi.items():
    if a:
        for y in Ys:
            if y:
                ok("supported_mode_extractable",mat_rank(y,n,c)<D,(Ys,a,y))
# In this fixture all nonzero tuples from C_true are supported only by the unique good U.
for Ys,a in phi.items():
    if any(Ys):
        ok("true_phi_1_over_7",a==Fraction(1,7),(Ys,a))

S_T=sum(a*a for Ys,a in phi.items() if any(Ys))
ok("bundle_chi2_exact",S_T==Fraction(4**T-1,49),S_T)

# Intersection enumerator identity: 1+S_T = E_{U,U'} |K_U intersect K_U'|^T.
rhs=Fraction(0)
for U in Us:
    KU=K_of(C_true,U)
    for Up in Us:
        KI=KU.intersection(K_of(C_true,Up))
        rhs += Fraction(len(KI)**T, len(Us)**2)
ok("intersection_enumerator_identity",rhs==1+S_T,(rhs,1+S_T))

# Exact correctness filter probabilities for q=2, same public H shared across T subcapsules.
# Good U: if <H,Y> != 0, all normalized outputs equal b.
# Bad U: conditioned <H,Y> != 0, T residuals are iid uniform bits.
p_h_nonzero=Fraction(1,2)
p_good_correct=alpha*p_h_nonzero
p_bad_wrong=(1-alpha)*p_h_nonzero*Fraction(1,2**T)
ok("good_bundle_probability",p_good_correct==Fraction(1,14),p_good_correct)
ok("bad_wrong_probability",p_bad_wrong==Fraction(3,56),p_bad_wrong)

# Conservative scan bound and parameter ledger for the binary scalar-descended HS interface.
A=128*math.log(2.0)  # e^-A = 2^-128
eps=2.0**-128
ledger=[]
for N in (8,16,32,64):
    R=int(math.floor(math.log2(N)))
    n_hs=N+1
    D_hs=R+1
    m_hs=n_hs-D_hs+1
    alpha_hs=(2**R-1)/(2**(N+1)-1)
    L=math.ceil(A/(alpha_hs*0.5))
    # choose T so A q^-T / alpha <= eps for q=2
    Tneed=math.ceil(math.log2(A/(alpha_hs*eps)))
    log2_total=math.log2(L)+math.log2(Tneed)
    ledger.append({
        "N":N,"R":R,"cutoff_D":D_hs,"hidden_subspace_dim_m":m_hs,
        "alpha_rank1":alpha_hs,"bundles_L":L,"consistency_T":Tneed,
        "log2_total_subcapsules":log2_total
    })
ok("ledger_monotone",all(ledger[i]["log2_total_subcapsules"] < ledger[i+1]["log2_total_subcapsules"]
                         for i in range(len(ledger)-1)),ledger)

# Publishing U attack on the unique good true U:
U=Us[good[0]]
K=K_of(C_true,U); S=sum_subspaces(Ctrue_perp,W_of_U(U))
s=int(round(math.log2(len(K))))
success=Fraction(1,1)-Fraction(1,2)*Fraction(1,2**s)
ok("public_U_attack_codim2",s==2,s)
ok("public_U_attack_success",success==Fraction(7,8),success)

out={
    "run":103,
    "status":"PASS",
    "total_assertions":len(checks),
    "fixture":{"q":2,"n":n,"c":c,"D":D,"m":m,"subspaces":len(Us)},
    "false_perfect_hiding":false_records,
    "true_geometry":true_records,
    "rank1_good_probability":str(alpha),
    "bundle_T":T,
    "bundle_chi_square":str(S_T),
    "intersection_enumerator_total":str(rhs),
    "correctness":{
        "p_good_correct_per_bundle":str(p_good_correct),
        "p_bad_wrong_per_bundle":str(p_bad_wrong)
    },
    "public_U_attack":{"codimension":s,"success_probability":str(success)},
    "hair_sahai_binary_ledger":ledger,
    "scope":[
        "Finite algebra/probability controls only.",
        "Perfect false hiding is proved algebraically in the note, not inferred from tests.",
        "The bundle's Fourier support is source-extractable, but arbitrary-QPT recovery-to-mode extraction still needs a quantitative response-mass theorem.",
        "The Hair-Sahai resource ledger is an interface estimate, not a deployment benchmark."
    ]
}
print(json.dumps(out,indent=2,sort_keys=True))
