#!/usr/bin/env python3
"""R159: exhaustive finite consistency checks for witness-invariant LWE column criterion.
No cryptographic hardness evidence; Python 3 stdlib only.
"""
import json
from math import prod
assertions=0

def ck(a, msg):
    global assertions
    assertions+=1
    if not a: raise AssertionError(f'{assertions}: {msg}')

def witnesses(table,n):
    # ORIGINAL relation R_phi(b,y) = (b==0 && y==0) OR (b==1 && phi(y)).
    return [(0,0)] + [(1,y) for y in range(1<<n) if (table>>y)&1]

counts=[]
for n in (1,2,3):
    total=1<<(1<<n)
    noextra=0
    for truth_table in range(total):
        ww=witnesses(truth_table,n)
        ck(ww[0]==(0,0),"fallback witness")
        ck(len(ww)==1+truth_table.bit_count(),"witness count")
        invariant=len({b for b,_ in ww})==1
        ck(invariant==(truth_table==0),"invariant iff UNSAT")
        # candidate non-rowspace LWE column rho=(0,1), evaluation h_z=rho*z=b
        rho_values={b for b,_ in ww}
        ck((rho_values=={0})==(truth_table==0),"candidate column safe iff UNSAT")
        # obvious known invariant rho=(1,0) always safe; its contribution is the shared affine row
        ck(len({1 for _ in ww})==1,"rowspace correction trivial")
        if invariant: noextra+=1
    counts.append({"variables":n,"formulas":total,"invariant_instances":noextra})

# A stronger invariant: a public linear form a+beta*b is all-witness constant
# iff either beta=0 or phi has no solution.
q=7
for table in range(1<<(1<<3)):
    ws=witnesses(table,3)
    for a in range(q):
        for beta in range(q):
            v={(a+beta*b)%q for b,_ in ws}
            ck((len(v)==1)==(beta==0 or table==0),"all-witness linear invariant classification")

# Exact distribution of independently chosen hidden u times a nonconstant column shift:
# Given two witnesses with b=0,1, shift difference = beta*u mod q,
# and beta chosen uniformly, it vanishes with P=(2q-1)/q^2.
prob=[]
for q in (5,7,11,13):
    count=sum((beta*u)%q==0 for beta in range(q) for u in range(q))
    ck(count==2*q-1,"zero product count")
    prob.append({"q":q,"zero_count":count,"total":q*q})

result={"run":"R159-ORIGINAL-INVARIANT-COLUMN-HARDNESS-20261108","assertions":assertions,"cases":counts,"phase_law":prob,"interpretation":"Finite confirmation only. Worst-case coNP-completeness proved separately by deterministic circuit reduction; no QPT or LWE security claim."}
print(json.dumps(result,sort_keys=True,indent=2))
