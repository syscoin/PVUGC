#!/usr/bin/env python3
"""Run 705 finite algebra/distribution check; QROM lemma is a mathematical proof, NOT tested here."""
from collections import Counter
from itertools import product
from random import Random
import json

checks = 0

def check(c, message):
    global checks
    assert c, message
    checks += 1

# 1. Exact hybrid reprogramming distribution. The oracle domain and codomain are
# tiny solely to exhaust the abstract coupling; no quantum attack is simulated.
keys=range(4)
values=range(4)
oracles=list(product(values,repeat=4))
real=Counter()
reprogrammed=Counter()
independent_view=Counter()
for key in keys:
    pk=key&1  # deliberately correlated native public key
    for H in oracles:
        real[(pk,H[key],H)] += 4   # scale by |range| for equal denominators
        for tau in values:
            programmed=tuple(tau if j==key else H[j] for j in keys)
            reprogrammed[(pk,tau,programmed)] += 1
            independent_view[(pk,tau)] += 1
check(real==reprogrammed, "joint oracle/programmed tag laws are exactly equal")
check(len(real)>0,"nonempty coupled oracle law")
for pk in (0,1):
    counts=[independent_view[(pk,tau)] for tau in values]
    check(len(set(counts))==1,"tau uniform conditional on correlated pk")

# 2. Run 704's nontrivial certificate: (1-u)+u(1-v)+uv=1,
# with Q1 constant, Q2 constant, Q3(u)=a+b*u and constant public matrix M.
q=101
rng=Random(705)
I=(1,0,0,1)
# coefficient arrays: constant, u, v, uv
r1=(1,-1,0,0)
r2=(0,1,0,-1)
r3=(0,0,1,0)
ur3=(0,0,0,1)

for j in range(4):
    check(r1[j]+r2[j]+ur3[j] == int(j==0),"formal polynomial unit identity")

def arr(x): return tuple(y%q for y in x)
def vector_eval(cs,u,v): return sum(k*a for k,a in zip(cs,(1,u,v,u*v)))%q

def transcript(k,m,mask):
    # mask rows: Q1, Q2, Q3_const, Q3_u, each 2x2 rowmajor
    out=[]
    for j in range(4):
        out.append(tuple((m[j][cell] + (k if j==0 else 0)*I[cell] +
             r1[j]*mask[0][cell]+r2[j]*mask[1][cell]+r3[j]*mask[2][cell]
             +ur3[j]*mask[3][cell])%q for cell in range(4)))
    return tuple(out)

def shift(mask,delta):
    return tuple(tuple((x-delta*I[j])%q for j,x in enumerate(A))
                if i in (0,1,3) else A for i,A in enumerate(mask))

for capsule in range(3):
    m=tuple(tuple(rng.randrange(q) for _ in range(4)) for _ in range(4))
    mask=tuple(tuple(rng.randrange(q) for _ in range(4)) for _ in range(4))
    k0=rng.randrange(q); delta=rng.randrange(q)
    c0=transcript(k0,m,mask)
    c1=transcript((k0+delta)%q,m,shift(mask,delta))
    check(c0==c1,"complete public coefficient transcript exactly coupled")
    for u,v in product(range(4),repeat=2):
        for index in range(4):
            check(vector_eval(tuple(row[index] for row in c0),u,v)==
                  vector_eval(tuple(row[index] for row in c1),u,v),
                  "all public evaluated entries equal, incl invalid/nonboolean")

# 3. Independent masks across capsules permit the same key shift in each.
# The tag is not involved in mask coupling; its oracle proof is external.
print(json.dumps({"run":705,"assertions":checks,"finite_hybrid_domain":4,
                  "finite_hybrid_range":4,"oracle_functions":len(oracles),
                  "exhaustive_reprogramming_law":True,
                  "public_key_tag_correlation_tested":True,
                  "false_capsules_full_matrix_couplings":3,
                  "unit_certificate_degree":1,
                  "quantum_O2H_not_empirically_proved":True},sort_keys=True))
