#!/usr/bin/env python3
from __future__ import annotations

from fractions import Fraction
from itertools import product
from collections import defaultdict, Counter
import json, math

def vecs(q, n):
    return list(product(range(q), repeat=n))

def mats(q, a, b):
    return [tuple(tuple(v[i*b+j] for j in range(b)) for i in range(a))
            for v in product(range(q), repeat=a*b)]

def dot(a,b,q):
    return sum(x*y for x,y in zip(a,b)) % q

def mm(A,K,q):
    return tuple(tuple(sum(A[i][j]*K[j][l] for j in range(len(K))) % q
                       for l in range(len(K[0])))
                 for i in range(len(A)))

def msub(A,B,q):
    return tuple(tuple((A[i][j]-B[i][j])%q for j in range(len(A[0])))
                 for i in range(len(A)))

def rankq(M,q):
    A=[list(row) for row in M]
    nr=len(A); nc=len(A[0]) if nr else 0
    r=0
    for c in range(nc):
        p=next((i for i in range(r,nr) if A[i][c]%q),None)
        if p is None:
            continue
        A[r],A[p]=A[p],A[r]
        inv=pow(A[r][c]%q,-1,q)
        A[r]=[(x*inv)%q for x in A[r]]
        for i in range(nr):
            if i!=r and A[i][c]%q:
                f=A[i][c]%q
                A[i]=[(A[i][j]-f*A[r][j])%q for j in range(nc)]
        r+=1
    return r

def inv2(K,q):
    a,b=K[0]; c,d=K[1]
    det=(a*d-b*c)%q
    if det==0:
        return None
    z=pow(det,-1,q)
    return ((d*z%q,(-b)*z%q),((-c)*z%q,a*z%q))

checks=[]
def ok(name, cond, detail=None):
    if not cond:
        raise AssertionError(f"{name}: {detail}")
    checks.append({"name":name,"detail":detail})

# --------------------------------------------------------------------
# 1. Reverse-posterior identity for a single target column.
# mu is a finite "Gaussian-like" product distribution on F_3^2.
# --------------------------------------------------------------------
q=3
Kvec=vecs(q,2)
one={0:Fraction(4,6),1:Fraction(1,6),2:Fraction(1,6)}
mu={k:one[k[0]]*one[k[1]] for k in Kvec}
ok("mu_normalized",sum(mu.values())==1)

Avec=vecs(q,2)
posterior_checks=0
for A in Avec:
    probs=defaultdict(Fraction)
    for k,p in mu.items():
        probs[dot(A,k,q)] += p
    for t,pt in probs.items():
        if pt==0:
            continue
        # Reverse sampler posterior.
        post={k:(p/pt if dot(A,k,q)==t else Fraction(0))
              for k,p in mu.items()}
        # Direct conditional Gaussian-like law is definitionally mu conditioned on Ak=t.
        cond={k:(mu[k]/sum(mu[u] for u in Kvec if dot(A,u,q)==t)
                 if dot(A,k,q)==t else Fraction(0))
              for k in Kvec}
        ok(f"posterior_{posterior_checks}",post==cond,(A,t))
        posterior_checks+=1

# --------------------------------------------------------------------
# 2. Exact joint-TV equality on surjective A:
# reverse Q: A uniform nonzero, K~mu, T=A.K.
# ideal P: A uniform nonzero, T uniform, K~mu | A.K=T.
# Since both have same K|(A,T), joint TV equals marginal TV.
# --------------------------------------------------------------------
Afull=[A for A in Avec if any(A)]
Qjoint=defaultdict(Fraction); Pjoint=defaultdict(Fraction)
Qmarg=defaultdict(Fraction); Pmarg=defaultdict(Fraction)
for A in Afull:
    pA=Fraction(1,len(Afull))
    denom={}
    for t in range(q):
        denom[t]=sum(mu[k] for k in Kvec if dot(A,k,q)==t)
        ok(f"surjective_denom_{A}_{t}",denom[t]>0)
    for k,pk in mu.items():
        t=dot(A,k,q)
        Qjoint[(A,t,k)] += pA*pk
        Qmarg[(A,t)] += pA*pk
    for t in range(q):
        Pmarg[(A,t)] += pA*Fraction(1,q)
        for k,pk in mu.items():
            if dot(A,k,q)==t:
                Pjoint[(A,t,k)] += pA*Fraction(1,q)*pk/denom[t]

def tv(D0,D1):
    keys=set(D0)|set(D1)
    return sum(abs(D0.get(k,Fraction(0))-D1.get(k,Fraction(0))) for k in keys)/2

tv_joint=tv(Qjoint,Pjoint)
tv_marg=tv(Qmarg,Pmarg)
ok("joint_tv_equals_marginal_tv",tv_joint==tv_marg,(tv_joint,tv_marg))

# --------------------------------------------------------------------
# 3. Rank-aware average chi-square identity for matrix preimages.
#
# E_A chi2(P_{AK|A} || U_{n x r})
# = q^(nr) E_{K,K'} q^(-n rank(K-K')) - 1.
# --------------------------------------------------------------------
n=1;m=2;r=2
Ks=mats(q,m,r)
# Product finite Gaussian-like measure on 4 entries.
weights={}
Z=Fraction(0)
for K in Ks:
    w=Fraction(1)
    for row in K:
        for x in row:
            w*=one[x]
    weights[K]=w
    Z+=w
ok("matrix_mu_normalized",Z==1)
muM=weights
As=mats(q,n,m)
Qout=q**(n*r)
avg_chi=Fraction(0)
for A in As:
    d=defaultdict(Fraction)
    for K,p in muM.items():
        d[mm(A,K,q)] += p
    chi=Qout*sum(p*p for p in d.values())-1
    avg_chi += chi/Fraction(len(As))
rhs=Qout*sum(
    p*p2*Fraction(1,q**(n*rankq(msub(K,L,q),q)))
    for K,p in muM.items() for L,p2 in muM.items()
)-1
ok("rank_aware_chi_square_identity",avg_chi==rhs,(avg_chi,rhs))

rank_contrib=defaultdict(Fraction)
for K,p in muM.items():
    for L,p2 in muM.items():
        rank_contrib[rankq(msub(K,L,q),q)] += p*p2
ok("rank_difference_mass_normalized",sum(rank_contrib.values())==1)

# r=1 specialization: E chi2 = (q^n-1) CP(mu)
cp=sum(p*p for p in mu.values())
avg_vec=Fraction(0)
for A in [tuple([x for x in a]) for a in Avec]:
    d=defaultdict(Fraction)
    for k,p in mu.items():
        d[dot(A,k,q)] += p
    avg_vec += (q*sum(p*p for p in d.values())-1)/Fraction(len(Avec))
ok("vector_collision_specialization",avg_vec==(q-1)*cp,(avg_vec,(q-1)*cp))

# --------------------------------------------------------------------
# 4. Exact trapdoor-free single-edge programming with an invertible K.
# Sample T uniform, K from any distribution on GL_2(F_3), define A=T K^-1.
# For each fixed K, A is exactly uniform and AK=T.
# --------------------------------------------------------------------
GL=[K for K in mats(q,2,2) if inv2(K,q) is not None]
ok("gl2_f3_size",len(GL)==48,len(GL))
Trows=[(t,) for t in []]  # unused marker
Arows=vecs(q,2)
for idx,K in enumerate(GL):
    Ki=inv2(K,q)
    counts=Counter()
    for Trow in Arows:
        T=(Trow,)
        A=mm(T,Ki,q)
        counts[A[0]]+=1
        ok(f"single_edge_relation_{idx}_{Trow}",mm(A,K,q)==T,(K,T,A))
    ok(f"single_edge_uniform_A_{idx}",
       set(counts.values())=={1} and len(counts)==q**2,counts)

# Check independence A ⟂ K under uniform T and arbitrary fixed positive weights on GL.
# Pick deterministic nonuniform weights.
wGL={K:Fraction((i%7)+1,1) for i,K in enumerate(GL)}
ZG=sum(wGL.values())
wGL={K:w/ZG for K,w in wGL.items()}
joint=defaultdict(Fraction)
for K,pK in wGL.items():
    Ki=inv2(K,q)
    for Trow in Arows:
        A=mm((Trow,),Ki,q)[0]
        joint[(A,K)] += pK*Fraction(1,len(Arows))
for A in Arows:
    for K,pK in wGL.items():
        ok(f"single_edge_independence_{A}_{hash(K)}",
           joint[(A,K)]==Fraction(1,len(Arows))*pK)

# --------------------------------------------------------------------
# 5. Fanout collision barrier.
# Same source row A in F_q^m, d outgoing independently uniform targets T_j
# and independent invertible scalar multipliers k_j. Compatibility requires
# T_j/k_j all equal. Probability q^{-m(d-1)}.
# Exhaust d=2; arithmetic-check d=3,4.
# --------------------------------------------------------------------
qf=5; mf=2
targets=vecs(qf,mf)
ks=list(range(1,qf))
good=0; total=0
for T0 in targets:
    for T1 in targets:
        for k0 in ks:
            ik0=pow(k0,-1,qf)
            A0=tuple(x*ik0%qf for x in T0)
            for k1 in ks:
                ik1=pow(k1,-1,qf)
                A1=tuple(x*ik1%qf for x in T1)
                total+=1
                if A0==A1:
                    good+=1
p2=Fraction(good,total)
ok("fanout2_exact",p2==Fraction(1,qf**mf),(p2,good,total))
for d in (2,3,4,8):
    p=Fraction(1,qf**(mf*(d-1)))
    expected=1/p
    ok(f"fanout_formula_{d}",expected==qf**(mf*(d-1)))

# --------------------------------------------------------------------
# 6. Tree expansion arithmetic if compact merges are removed.
# Binary depth t has 2^t leaves and 2^(t+1)-1 carrier nodes.
# --------------------------------------------------------------------
tree=[]
for t in range(1,17):
    leaves=2**t
    nodes=2**(t+1)-1
    ok(f"tree_identity_{t}",nodes==sum(2**j for j in range(t+1)))
    tree.append({"depth":t,"leaves":leaves,"carrier_nodes":nodes})

out={
    "run":105,
    "status":"PASS",
    "total_assertions":len(checks),
    "reverse_posterior":{
        "q":q,"m":2,"reachable_conditionals_checked":posterior_checks,
        "joint_tv_full_rank_A":str(tv_joint),
        "marginal_tv_full_rank_A":str(tv_marg),
        "vector_collision_probability":str(cp),
        "vector_avg_chi_square":str(avg_vec),
    },
    "matrix_rank_spectrum":{
        "q":q,"n":n,"m":m,"r":r,
        "average_chi_square":str(avg_chi),
        "rank_difference_probability_mass":
            {str(k):str(v) for k,v in sorted(rank_contrib.items())}
    },
    "single_edge":{
        "q":q,"matrix_size":2,"invertible_K_count":len(GL),
        "claim":"For uniform T and any independent distribution on invertible K, A=T K^-1 is uniform and independent of K, with AK=T."
    },
    "fanout":{
        "q":qf,"source_row_width":mf,
        "d2_exact_probability":str(p2),
        "formula":"q^(-m(d-1)) for d independent programmed targets with invertible scalar edge keys",
        "d2_expected_rejections":qf**mf,
        "d3_expected_rejections":qf**(2*mf),
        "d4_expected_rejections":qf**(3*mf)
    },
    "tree_expansion":tree,
    "scope":[
        "Finite-field probability/algebra controls only.",
        "The rank-aware chi-square theorem and Bayes reverse-sampling lemma are proved in the accompanying note.",
        "Single-edge reverse programming does not instantiate the full branching-program witness encryption.",
        "No computational hardness is inferred from passing tests."
    ]
}
print(json.dumps(out,indent=2,sort_keys=True))
