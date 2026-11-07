#!/usr/bin/env python3
"""Run 641: small exact uniform 2^a residue checks and analytic theta bound.
Not a cryptographic security experiment. Standard library only.
"""
import itertools, math, json, hashlib
from fractions import Fraction
from functools import lru_cache

checks=0

def check(cond,msg):
    global checks
    checks += 1
    if not cond: raise AssertionError(msg)

@lru_cache(None)
def small_ball(t,R):
    limit=math.isqrt(R)
    return tuple(z for z in itertools.product(range(-limit,limit+1),repeat=t)
                 if sum(a*a for a in z)<=R)

def image(D,z,r):
    return tuple(sum(a*b for a,b in zip(row,z))%r for row in D)

def finite(m,t,r,R):
    zs=small_ball(t,R)
    primitive=[z for z in zs if any(v&1 for v in z)]
    allrows=list(itertools.product(range(r),repeat=t))
    desired=[tuple(int(i==j) for i in range(m)) for j in range(m)]
    total=r**(m*t)
    target=total//(r**m)
    exact_individual=0
    for z in primitive:
        cnt=0
        for rows in itertools.product(allrows,repeat=m):
            if image(rows,z,r)==desired[0]:cnt+=1
        check(cnt==target,f'uniform image law {m,t,r,z}')
        exact_individual+=1
    union=0
    for rows in itertools.product(allrows,repeat=m):
        if any(image(rows,z,r) in desired for z in primitive):union+=1
    p=Fraction(union,total)
    bound=Fraction(m*len(primitive),r**m)
    check(p<=bound,'exact union bound')
    check(all((sum(x*x for x in z)<=R) for z in zs),'ball radius')
    return {'m':m,'t':t,'r':r,'R':R,'D_count':total,'short_vectors':len(zs),
            'primitive_short_vectors':len(primitive), 'fixed_primitive_image_cases':exact_individual,
            'union_probability':str(p),'union_bound':str(bound)}

models=[finite(1,2,2,2),finite(1,2,4,4),finite(1,2,8,6),
        finite(2,4,2,2),finite(2,4,4,1)]
# Compare theta counting with exact finite integer ball sizes and with the integral majorant.
for t in (2,4,6):
    for R in range(0,10):
        exact=len(small_ball(t,R))
        for u in (0.2,0.4,1.0,2.0):
            theta=sum(math.exp(-u*n*n) for n in range(-250,251))
            check(theta <= 1+math.sqrt(math.pi/u)+1e-13,'theta integral')
            check(exact<=math.exp(u*R)*theta**t*(1+1e-12),'Chernoff count')

kappas={}
for r in (16,32,64,128,256,1024):
    kappa=math.e*(math.sqrt(math.pi/32)+1/math.sqrt(r))**2
    check(kappa<1,'exponential reference bound')
    kappas[str(r)]=kappa

# Explicit illustration only; not a certified full Gaussian SOURCE instantiation.
lam=128;N=128;k=128;m=2*N*k;t=2*m
s_E=512;s_D=32768;q=2**k
allowed=[2**a for a in range(1,15) if 2**a <=q and s_E/2**a >=math.sqrt(lam) and s_D/2**a>=max(8,lam)]
r=max(allowed)
check(r==32,'illustrative residue admissibility')
R=m*r//32
kappa=kappas[str(r)]
check(R==32768,'illustrative norm')
log2_ref=math.log2(m)+m*math.log2(kappa)
check(log2_ref < -1000,'reference negligible')

out={'run':641,'checker':'run641_primepower_inverse_check.py','models':models,
     'analytic':{'kappas':kappas,
                 'formula':'Pr_actual[exists short column of a q-right-inverse] <= delta_slice(r)+m*kappa(r)^m, r=2^a>=16, t=2m, R=floor(m*r/32)',
                 'theta_inequality':'sum_Z exp(-u z^2) <= 1+sqrt(pi/u)'},
     'illustration_only':{'lambda':lam,'N':N,'k':k,'m':m,'t':t,
                          's_E':s_E,'s_D':s_D,'largest_r_meeting_A07_sufficient_width_ratios':r,
                          'R':R,'operator_norm_floor':math.sqrt(R+1),
                          'Frobenius_norm_floor':math.sqrt(m*(R+1)),
                          'log2_reference_failure_bound':log2_ref,
                          'note':'No delta_slice or actual parameter certification'},
     'assertions':checks, 'conclusion':'exact modular-image identities and finite counting checks only; no PQ security inference'}
print(json.dumps(out,sort_keys=True,indent=2))
