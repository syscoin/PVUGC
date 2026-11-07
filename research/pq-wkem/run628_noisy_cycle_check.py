#!/usr/bin/env python3
"""Exact finite checks for Run 628's noisy local gauge-cycle model.
Standard library only; not a cryptographic implementation."""
from collections import defaultdict
from fractions import Fraction
from itertools import product
from math import comb, exp, log2
import json

CHECKS = 0

def check(condition, label):
    global CHECKS
    CHECKS += 1
    if not condition:
        raise AssertionError(f"check {CHECKS}: {label}")

def parity(bits):
    return sum(bits) % 2

def cycle_law(t, p, secret):
    """Exhaustively average independent vertex frames and edge Bernoulli noise."""
    out = defaultdict(Fraction)
    for frames in product(range(2), repeat=t):
        for noise in product(range(2), repeat=t):
            weight = p ** sum(noise) * (1-p) ** (t-sum(noise)) / (2 ** t)
            z = tuple(frames[j] ^ frames[(j+1) % t] ^ noise[j] ^ (secret if j == t-1 else 0) for j in range(t))
            out[z] += weight
    return dict(out)

def marginal(law, keep):
    out = defaultdict(Fraction)
    for z, p in law.items():
        out[tuple(z[j] for j in keep)] += p
    return dict(out)

def tv(law0, law1):
    return sum(abs(law0.get(z, 0) - law1.get(z, 0)) for z in set(law0)|set(law1)) / 2

def majority_success(delta, copies):
    """Exact optimum: fair secret bit, independent parity-observations."""
    delta = abs(delta)
    p = (1-delta)/2
    ok = sum(Fraction(comb(copies,j)) * p**j * (1-p)**(copies-j)
             for j in range((copies-1)//2+1))
    if copies % 2 == 0:
        h = copies//2
        ok += Fraction(1,2)*comb(copies,h)*p**h*(1-p)**h
    return ok

def run():
    models = 0
    for t in (3,4,5):
        for p in (Fraction(1,8), Fraction(1,4), Fraction(3,8), Fraction(1,2)):
            d0, d1 = cycle_law(t,p,0),cycle_law(t,p,1)
            delta = (1-2*p)**t
            check(sum(d0.values()) == 1 and sum(d1.values()) == 1, 'normalized worlds')
            for z in product(range(2),repeat=t):
                wanted0 = Fraction(1,2**t)*(1+(-1)**parity(z)*delta)
                wanted1 = Fraction(1,2**t)*(1-(-1)**parity(z)*delta)
                check(d0[z] == wanted0, 'exact world-zero law')
                check(d1[z] == wanted1, 'exact world-one law')
            check(tv(d0,d1) == abs(delta), 'exact full transcript statistical distance')
            for subset_mask in range((1<<t)-1):
                keep=tuple(j for j in range(t) if (subset_mask>>j)&1)
                a,b=marginal(d0,keep),marginal(d1,keep)
                check(a==b, 'proper capsule subset identical')
                check(all(v==Fraction(1,2**len(keep)) for v in a.values()), 'proper subset uniform')
                check(len(a)==2**len(keep), 'all proper-subset outcomes supported')
            models += 1
    cochains = 0
    for t in range(3,9):
        for eta in product(range(2),repeat=t):
            vertices=[0]
            for e in eta[:-1]:
                vertices.append(vertices[-1]^e)
            closure = (vertices[-1]^vertices[0]) == eta[-1]
            check(closure == (parity(eta)==0), 'zero-cycle-noise iff coboundary')
            if closure:
                for j in range(t):
                    check(vertices[j]^vertices[(j+1)%t] == eta[j], 'explicit potential')
            cochains+=1
    p=Fraction(1,4); ell=3
    delta=(1-2*p)**ell
    majority=[]
    for copies in (1,2,3,7,15,31,63,127,255,511,1024):
        success=majority_success(delta,copies)
        check(success>=Fraction(1,2), 'optimal decoder beats chance')
        check(float(1-success) <= exp(-copies*float(delta)**2/2)+1e-14, 'Hoeffding bound')
        majority.append({'cycles':copies,'success':round(float(success),15)})
    # Explicit total-variation formula for independent cycle channels.
    for copies in (1,2,3,4):
        prob0,prob1={},{}
        for z in product(range(2),repeat=copies):
            prob0[z]=Fraction(1,2)**0
            prob1[z]=Fraction(1,2)**0
            for bit in z:
                prob0[z] *= (1+delta)/2 if bit==0 else (1-delta)/2
                prob1[z] *= (1-delta)/2 if bit==0 else (1+delta)/2
        check(tv(prob0,prob1)==2*majority_success(delta,copies)-1,'joint total variation equals ML bias')
    key_bits=128; copies=16384
    error_union=key_bits*exp(-copies*float(delta)**2/2)
    check(error_union<2**-128,'illustrative key-recovery failure below 2^-128')
    out={
      'research_id':628,
      'model':'independent binary vertex frames and Bernoulli edge noise, t public capsule groups',
      'exact_models':models,
      'coboundary_assignments':cochains,
      'checks_passed':CHECKS,
      'single_cycle_t3_pquarter_tv':str(delta),
      'majority_exact_pquarter_t3':majority,
      'key_illustration':{'bits':key_bits,'cycles_per_bit':copies,'edges_total':key_bits*copies*ell,
                          'packed_edge_bytes':key_bits*copies*ell//8,
                          'union_error_upper':format(error_union,'.17e'),
                          'security_note':'classical PPT key recovery on a TOY noisily frame-masked bit carrier; not a WKEM'},
      'quantum_scope':'full transcript is classical; trace distance equals classical TV for common independent quantum advice',
      'claim_scope':'exact toy counterexample; not CCMR/RIO, Gaussian SOURCE, or full relation-gated WKEM security'
    }
    print(json.dumps(out,indent=2,sort_keys=True))

if __name__=='__main__':
    run()
