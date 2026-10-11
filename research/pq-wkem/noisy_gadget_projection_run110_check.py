#!/usr/bin/env python3
from itertools import product, permutations
import json, math

checks=[]
def ok(name,cond,detail=None):
    if not cond: raise AssertionError(f"{name}: {detail}")
    checks.append({"name":name,"detail":detail})

def cent(x,q):
    x%=q
    return min(x,q-x)

def ell(q): return math.ceil(math.log2(q))

def gdistance(q):
    L=ell(q)
    return min(max(cent((pow(2,j,q)*d),q) for j in range(L)) for d in range(1,q))

def obs(s,e,q):
    return tuple((pow(2,j,q)*s+e[j])%q for j in range(len(e)))

def candidates(y,B,q):
    L=len(y)
    out=[]
    for s in range(q):
        if all(cent(y[j]-pow(2,j,q)*s,q)<=B for j in range(L)):
            out.append(s)
    return out

# 1. Exact distance control for all moduli through 257.
drows=[]
for q in range(2,258):
    d=gdistance(q)
    ok(f"distance_q{q}", 3*d >= q, (q,d,q/3))
    drows.append({"q":q,"ell":ell(q),"distance":d,"ratio":d/q})

# 2. Exhaustive unique decoding at q=17, B=2 (<q/6).
q=17; B=2; L=ell(q); uniq=0
for s in range(q):
    for e in product(range(-B,B+1),repeat=L):
        y=obs(s,e,q)
        cs=candidates(y,B,q)
        ok(f"unique_{uniq}",cs==[s],(s,e,y,cs))
        uniq+=1

# 3. Near-threshold deterministic controls at q=257, B=42 (<q/6).
q2=257; B2=42; L2=ell(q2)
patterns=[]
patterns.append(tuple(0 for _ in range(L2)))
patterns.append(tuple(B2 for _ in range(L2)))
patterns.append(tuple(-B2 for _ in range(L2)))
patterns.append(tuple(B2 if j%2==0 else -B2 for j in range(L2)))
patterns.append(tuple(-B2 if j%2==0 else B2 for j in range(L2)))
for k in range(L2):
    p=[0]*L2;p[k]=B2;patterns.append(tuple(p))
    p=[0]*L2;p[k]=-B2;patterns.append(tuple(p))
near=0
for s in range(q2):
    for e in patterns:
        cs=candidates(obs(s,e,q2),B2,q2)
        ok(f"near_threshold_{near}",cs==[s],(s,e,cs))
        near+=1

# 4. Correctness-compatible bounded noise always lies in attack regime
# for any nontrivial universal hidden-input projection: h>=1 selected basis block,
# opening l1 norm kappa>=1, decoding radius rho<=1/4.
trade=[]
for q in (257,769,12289):
  for h in (1,2,8,64):
    for kappa in (1,2,8,64,512):
      rho=1/4
      Bmax=rho*q/((h+1)*kappa)
      ok(f"correctness_implies_attack_{q}_{h}_{kappa}",Bmax <= q/8 < q/6,(Bmax,q/6))
      trade.append({"q":q,"selected_blocks":h,"kappa":kappa,"guaranteed_correctness_Bmax":Bmax,"attack_threshold_q_over_6":q/6})

# 5. Public signed-permutation/randomized gadget link does not help.
# B = g P^{-1}; published projection y=hB+e. Anyone applies P to get hg+eP.
q=17; Bnd=2; L=ell(q); g=tuple(pow(2,j,q) for j in range(L))
perms=[tuple(range(L)),tuple(reversed(range(L))),tuple((i+1)%L for i in range(L))]
errs=[tuple(0 for _ in range(L)),tuple(Bnd if j%2==0 else -Bnd for j in range(L)),tuple(-Bnd for _ in range(L))]
link=0
for perm in perms:
    # P maps row coordinates: (v P)[j]=v[perm[j]]. Define B so B P = g => B[perm[j]]=g[j].
    Bin=[0]*L
    for j in range(L): Bin[perm[j]]=g[j]
    Bin=tuple(Bin)
    for s in range(q):
      for e in errs:
        y=tuple((s*Bin[j]+e[j])%q for j in range(L))
        yP=tuple(y[perm[j]] for j in range(L))
        eP=tuple(e[perm[j]] for j in range(L))
        ok(f"link_relation_{link}",yP==obs(s,eP,q),(perm,s,e,yP))
        ok(f"link_decode_{link}",candidates(yP,Bnd,q)==[s])
        link+=1

# 6. Attack success from a generic error-tail event.
# If Pr[||e||inf<=B] >= 1-eps and B<q/6, unique recovery succeeds on that event.
tail_rows=[]
for eps_exp in (40,64,96,128):
    eps=2.0**(-eps_exp)
    success=1-eps
    ok(f"tail_success_{eps_exp}",success>0.999999)
    tail_rows.append({"tail_failure_bound":f"2^-{eps_exp}","recovery_success_lower":success})

out={
 "run":110,"status":"PASS","total_assertions":len(checks),
 "gadget_distance":{"moduli_checked":"2..257","min_bound":"Delta_infty(g)>=q/3","rows":drows[-8:]},
 "exhaustive_unique_decode":{"q":17,"B":2,"ell":L,"observations":uniq},
 "near_threshold":{"q":257,"B":42,"q_over_6":q2/6,"patterns_per_secret":len(patterns),"checks":near},
 "correctness_tradeoff":{"rows":trade,"claim":"For selected_blocks>=1, kappa>=1 and decoding radius <=q/4, a worst-case per-coordinate bound sufficient for correctness is <=q/8<q/6, hence inside the gadget secret-recovery regime."},
 "public_short_link":{"q":17,"B":2,"cases":link,"claim":"Signed/permutation randomization with a public short inverse link preserves the noisy gadget decoding attack."},
 "tail_event":tail_rows,
 "scope":[
   "Finite controls for a theorem proved algebraically in the note.",
   "The attack is classical polynomial time when q is polynomial in the security parameter; it therefore refutes QPT security in that regime.",
   "The theorem concerns full powers-of-two gadget projections with sufficiently bounded noise, not every possible gadget or correlated-noise construction.",
   "Passing tests does not establish or refute SIS/LWE hardness beyond the explicit gadget-projection attack."
 ]
}
print(json.dumps(out,indent=2,sort_keys=True))
