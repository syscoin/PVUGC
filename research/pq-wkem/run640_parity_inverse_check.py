#!/usr/bin/env python3
"""Run 640: exact finite tests for uniform-binary right inverse sparsity bound.
Public standard library only. Not a cryptographic security test.
"""
import hashlib
import json
import math
from itertools import product
from fractions import Fraction

checks = 0

def check(condition, label="assertion"):
    global checks
    checks += 1
    if not condition:
        raise AssertionError(label)

def parity(x):
    return x.bit_count() & 1

def full_column_rank(cols, t):
    basis={}
    for x in cols:
        while x:
            b=x.bit_length()-1
            if b in basis:
                x ^= basis[b]
            else:
                basis[b]=x
                break
        if x==0:
            return False
    return True

def is_right_inverse(rows, cols, m):
    return all(parity(rows[i]&cols[j])==int(i==j)
               for i in range(m) for j in range(m))

def finite_test(m,t):
    size_d=1<<(m*t)
    rows_all=list(product(range(1<<t), repeat=m))
    cols_all=list(product(range(1<<t), repeat=m))
    check(len(rows_all)==size_d, 'D count')
    subset_counts=[]
    for cols in cols_all:
        if not full_column_rank(cols,t):
            continue
        # Fixed full-column-rank U: DU=I imposes m^2 independent fair equations.
        solutions=sum(is_right_inverse(rows,cols,m) for rows in rows_all)
        check(solutions==2**(m*(t-m)),f'fixed U image law for {cols}')
        subset_counts.append((sum(c.bit_count() for c in cols),cols))
    R_values=range(0,m*t+1)
    results=[]
    for R in R_values:
        union_event=0
        for rows in rows_all:
            if any(wt<=R and is_right_inverse(rows,cols,m) for wt,cols in subset_counts):
                union_event+=1
        bound_num=sum(math.comb(m*t,j) for j in range(R+1))
        bound=Fraction(bound_num,2**(m*m))
        exact=Fraction(union_event,len(rows_all))
        check(exact<=bound,f'actual union <= count for R={R}')
        results.append({'R':R,'event_numerator':exact.numerator,
                        'event_denominator':exact.denominator,
                        'union_bound_num':bound.numerator,
                        'union_bound_den':bound.denominator})
    return {'m':m,'t':t,'matrices_D':size_d,
            'full_rank_candidate_U':len(subset_counts),
            'fixed_U_solutions':2**(m*(t-m)),
            'thresholds':results}

# Exact exhaustive data for manageable dimensions; distinct U and D pairs checked.
models=[finite_test(1,2),finite_test(2,4)]

# The literal binary matrices U of small Hamming weight may be rank deficient;
# using all such U remains a safe overcount, even for adversarial algorithms.
for M in range(1,20):
    for R in range(M//2+1):
        s=sum(math.comb(M,j) for j in range(R+1))
        if 0<R<M//2:
            p=R/M
            h=-p*math.log2(p)-(1-p)*math.log2(1-p)
            check(math.log2(s)<=M*h+1e-10,'entropy bound')

# A discrete mixture with a target-dependent point mass has TV<=delta from U.
# The inverse-existence event changes by at most delta, even when the point is
# adversarially selected to maximize success. This checks the TV transfer only.
m,t=2,4
rows_all=list(product(range(1<<t),repeat=m))
U_cols=[c for c in product(range(1<<t),repeat=m) if full_column_rank(c,t)]
for R in (2,3,4,5):
    event={d for d in rows_all if any(sum(c.bit_count() for c in u)<=R and is_right_inverse(d,u,m) for u in U_cols)}
    p0=Fraction(len(event),len(rows_all))
    for delta in (Fraction(1,100),Fraction(1,10),Fraction(1,2)):
        for preferred in (rows_all[0],tuple(1<<i for i in range(m))):
            p_mix=(1-delta)*p0+delta*int(preferred in event)
            check(p_mix<=p0+delta,'TV transfer')

# At m=256, t=512 and R=floor(.10*t*m), show entropy bound without
# substituting 2^k-uniform D for the genuine integer-Gaussian SOURCE.
m,t=256,512
M=m*t
R=M//10
rho=R/M
h=-rho*math.log2(rho)-(1-rho)*math.log2(1-rho)
log2_bound=-m*m+M*h
check(log2_bound < -4000,'illustrative binary failure exponent')
check(R+1==13108,'illustrative norm threshold')

result={
 'run':640,'checker':'run640_parity_inverse_check.py',
 'models':models,
 'illustration':{
   'm':m,'t':t,'binary_entries':M,'R':R,'rho':rho,
   'union_log2_upper_bound':log2_bound,
   'mandatory_J_Frob_norm_lower_bound':math.sqrt(R+1),
   'mandatory_J_operator_norm_lower_bound':math.sqrt((R+1)/m)
 },
 'assertions':checks,
 'conclusion':'finite identities verified; no cryptographic security inference'
}
print(json.dumps(result,indent=2,sort_keys=True))
