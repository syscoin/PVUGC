#!/usr/bin/env python3
from __future__ import annotations
from itertools import product
import json, math

def dot(a,b,q):
    return sum(x*y for x,y in zip(a,b)) % q

def vadd(a,b,q):
    return tuple((x+y)%q for x,y in zip(a,b))

def vsub(a,b,q):
    return tuple((x-y)%q for x,y in zip(a,b))

def vscale(c,a,q):
    return tuple((c*x)%q for x in a)

checks=[]
def ok(name,cond,detail=None):
    if not cond:
        raise AssertionError(f"{name}: {detail}")
    checks.append({"name":name,"detail":detail})

# --------------------------------------------------------------------
# 1. Powers-of-two gadget decomposition over q=257.
# de Castro-Peikert use g=(1,2,...,2^{ell-1}), ell=ceil(log2 q).
# --------------------------------------------------------------------
q=257
ell=math.ceil(math.log2(q))
g=tuple(pow(2,j,q) for j in range(ell))

def gdecomp(t):
    # canonical representative 0..q-1, least-significant bit first
    return tuple((t>>j)&1 for j in range(ell))

for t in range(q):
    d=gdecomp(t)
    ok(f"gadget_decomp_{t}",dot(g,d,q)==t,(t,d,dot(g,d,q)))

# --------------------------------------------------------------------
# 2. Fixed-public-input PHF correctness versus hidden-input universalization.
#
# Relation: (C - w G) S = t, w in {0,1}.
# For fixed public w, projection hp_M = h(C-wG) and witness S gives h t.
# Natural hidden-input universalization publishes hp_C=hC and hp_G=hG so
# later w can form hp_M. But gadget decomposition makes H=ht public:
# hp_G * g^{-1}(t) = h t.
# --------------------------------------------------------------------
universal_cases=0
S=tuple(1 if j==0 else 0 for j in range(ell))
for t in range(1,q):  # nonzero target makes spurious witness explicit
    d=gdecomp(t)
    for w in (0,1):
        # choose a valid C for this toy relation; only coordinate 0 affects S
        C=list((13*j + 7*t + 3*w) % q for j in range(ell))
        C[0]=(t + w*g[0]) % q
        C=tuple(C)
        M=vsub(C,vscale(w,g,q),q)
        ok(f"relation_valid_{t}_{w}",dot(M,S,q)==t,(M,S,t))
        for h in (1,2,3,5,17,64,128,256):
            hpC=vscale(h,C,q)
            hpG=vscale(h,g,q)
            hpM=vsub(hpC,vscale(w,hpG,q),q)
            H=(h*t)%q
            honest=dot(hpM,S,q)
            attacker=dot(hpG,d,q)
            ok(f"fixed_input_correct_{universal_cases}",honest==H,(t,w,h,honest,H))
            ok(f"universal_projection_leaks_{universal_cases}",attacker==H,(t,w,h,attacker,H))
            universal_cases+=1

# --------------------------------------------------------------------
# 3. Multi-bit hidden-input linearization.
#
# M(w)=C-sum_i w_i G_i over disjoint gadget blocks.
# Honest linearization:
#     C*S - sum_i G_i*Z_i = t,  Z_i=w_i*S.
# Dropping consistency admits S=0 and one gadget-only Z_i=-g^{-1}(t).
# --------------------------------------------------------------------
m=3
L=m*ell
Gs=[]
for i in range(m):
    row=[0]*L
    row[i*ell:(i+1)*ell]=g
    Gs.append(tuple(row))

linearization_cases=0
for t in (1,2,3,7,16,31,64,128,256):
  d=gdecomp(t)
  for w in product((0,1), repeat=m):
    # choose S=e0 in block 0 and C so the hidden relation holds
    Sbig=tuple(1 if j==0 else 0 for j in range(L))
    C=[(11*j+5*t+sum(w))%q for j in range(L)]
    C[0]=(t + w[0]*g[0])%q
    C=tuple(C)
    M=C
    for i in range(m):
        if w[i]:
            M=vsub(M,Gs[i],q)
    ok(f"hidden_relation_{linearization_cases}",dot(M,Sbig,q)==t)
    Zs=[vscale(wi,Sbig,q) for wi in w]
    lhs=dot(C,Sbig,q)
    for i in range(m):
        lhs=(lhs-dot(Gs[i],Zs[i],q))%q
    ok(f"honest_linearization_{linearization_cases}",lhs==t,(w,t,lhs))
    # Spurious gadget-only linearized witness:
    # S=0, Z0=-embedded g^{-1}(t), other Zi=0.
    Z0=[0]*L
    for j,b in enumerate(d):
        Z0[j]=(-b)%q
    Zbad=[tuple(Z0)]+[tuple(0 for _ in range(L)) for _ in range(m-1)]
    lhs_bad=0
    for i in range(m):
        lhs_bad=(lhs_bad-dot(Gs[i],Zbad[i],q))%q
    ok(f"spurious_linear_solution_{linearization_cases}",lhs_bad==t,(t,w,lhs_bad))
    # It cannot satisfy Zi=wi*S when S=0 and t!=0, because Z0!=0.
    ok(f"spurious_breaks_product_consistency_{linearization_cases}",
       any(z!=0 for z in Zbad[0]))
    linearization_cases+=1

# --------------------------------------------------------------------
# 4. Product-consistency set is not affine/linear.
# R={(w,s,z): w in {0,1}, z=w*s}. It contains 0 but isn't closed under
# addition, so no homogeneous linear system characterizes it exactly.
# --------------------------------------------------------------------
for qp in (3,5,7,17):
    a=(0,1,0)  # valid: z=0*s
    b=(1,0,0)  # valid: z=1*0
    c=tuple((a[i]+b[i])%qp for i in range(3))
    def valid(x):
        w,s,z=x
        return w in (0,1) and z%qp==(w*s)%qp
    ok(f"consistency_a_valid_q{qp}",valid(a))
    ok(f"consistency_b_valid_q{qp}",valid(b))
    ok(f"consistency_sum_invalid_q{qp}",not valid(c),(qp,c))

# --------------------------------------------------------------------
# 5. General universal-projection theorem finite control.
#
# If public basis B has a public preimage d of target theta, and universal hp_B=hB
# is published, the true hash h*theta is public as hp_B*d.
# Random toy bases B=[g | random padding] retain the attack.
# --------------------------------------------------------------------
general_cases=0
for t in (1,5,19,63,127,200,256):
    d0=gdecomp(t)
    for pad in (0,1,37,129,256):
        B=g + (pad,)
        d=d0+(0,)
        ok(f"basis_preimage_{t}_{pad}",dot(B,d,q)==t)
        for h in (1,9,33,111,256):
            hp=vscale(h,B,q)
            H=h*t%q
            ok(f"general_projection_attack_{general_cases}",dot(hp,d,q)==H)
            general_cases+=1

# --------------------------------------------------------------------
# 6. Size/norm of the gadget-only pseudowitness.
# --------------------------------------------------------------------
norm_rows=[]
for t in range(1,q):
    d=gdecomp(t)
    hw=sum(d)
    l2=math.sqrt(hw)
    ok(f"gadget_norm_{t}",hw<=ell,(t,hw,ell))
    norm_rows.append({"t":t,"hamming":hw,"l2":l2})
max_hw=max(r["hamming"] for r in norm_rows)

out={
    "run":109,
    "status":"PASS",
    "total_assertions":len(checks),
    "gadget":{"q":q,"ell":ell,"g":list(g),"max_binary_preimage_hamming":max_hw},
    "universal_projection":{
        "cases":universal_cases,
        "claim":"For relation (C-wG)S=t, publishing hC and hG to defer w makes H=h*t publicly computable as (hG) g^{-1}(t)."
    },
    "hidden_input_linearization":{
        "bits":m,
        "cases":linearization_cases,
        "claim":"Linearizing Zi=wi*S yields a public gadget-only solution when product consistency is dropped."
    },
    "product_consistency":{
        "fields":[3,5,7,17],
        "claim":"The set {(w,s,z): w in {0,1}, z=w*s} contains zero but is not closed under addition, hence is not a linear subspace."
    },
    "general_universal_projection":{
        "cases":general_cases,
        "claim":"Any published projection of a basis matrix with a public target preimage reveals the projected target hash."
    },
    "scope":[
        "Finite algebra/functionality controls only.",
        "The attack is on the natural hidden-input universalization of an affine/projective-hash relation, not an impossibility theorem for every nonlinear EPHF.",
        "No pairing, SIS, or LWE security is inferred from these checks.",
        "The cited WEFC extractor in Campanelli-Fiore-Khoshakhlagh is PPT/GGM and extracts a representation Lambda(x,w), not automatically the ORIGINAL NP witness."
    ]
}
print(json.dumps(out,indent=2,sort_keys=True))
