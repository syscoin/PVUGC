import cmath
import itertools
import json
import math
import random
from collections import Counter
from fractions import Fraction


def vectors(q,d):
    return list(itertools.product(range(q), repeat=d))


def add(a,b,q):
    return tuple((x+y)%q for x,y in zip(a,b))


def scale(a,x,q):
    return tuple((a*t)%q for t in x)


def qform(x,q):
    return sum(t*t for t in x)%q


def sphere(q,d,k):
    return [x for x in vectors(q,d) if qform(x,q)==k%q]


def convolution(q,d,k,h,coeffs=None):
    S=sphere(q,d,k)
    if coeffs is None:
        coeffs=[1]*h
    assert len(coeffs)==h and all(a%q for a in coeffs)
    dist=Counter({(0,)*d:1})
    den=1
    for a in coeffs:
        nd=Counter()
        for x,c in dist.items():
            for y in S:
                nd[add(x,scale(a,y,q),q)] += c
        dist=nd
        den*=len(S)
    return dist,den


def tv_uniform(q,d,dist,den):
    N=q**d
    total=Fraction(0,1)
    for x in vectors(q,d):
        total += abs(Fraction(dist.get(x,0),den)-Fraction(1,N))
    return total/2


def tv_pair(q,d,A,denA,B,denB):
    total=Fraction(0,1)
    for x in vectors(q,d):
        total += abs(Fraction(A.get(x,0),denA)-Fraction(B.get(x,0),denB))
    return total/2


def fourier_bound(q,d,h):
    a=q**(1-d/2)
    beta=a/(1-a)
    return 0.5*(q**(d/2))*(beta**h)


def check_complete_fiber():
    q,d,k=3,2,1
    S=sphere(q,d,k)
    allv=vectors(q,d)
    out=Counter()
    sum_reps=Counter()
    for v1 in S:
      for v2 in S:
        z=add(v1,v2,q)
        sum_reps[z]+=1
        for r1 in allv:
          for r2 in allv:
            y1=add(v1,add(r1,scale(-1,r2,q),q),q)
            y2=add(v2,add(r2,scale(-1,r1,q),q),q)
            out[(y1,y2)]+=1
    for y1 in allv:
      for y2 in allv:
        z=add(y1,y2,q)
        assert out[(y1,y2)] == (q**d)*sum_reps[z]
    return {
      "q":q,"d":d,"sphere_size":len(S),
      "public_pairs":len(out),
      "fiber_factor":q**d,
      "checked_pairs":len(allv)**2,
    }


def check_fixed_point():
    rng=random.Random(2201)
    q,d=101,8
    trials=250
    ok=0
    for _ in range(trials):
        k=rng.randrange(1,q)
        while True:
            v=tuple(rng.randrange(q) for _ in range(d))
            if qform(v,q)==k:
                break
        r=tuple(rng.randrange(q) for _ in range(d))
        y=add(v,add(r,scale(-1,r,q),q),q)
        ok += (qform(y,q)==k)
    assert ok==trials
    return {"q":q,"d":d,"trials":trials,"correct":ok}


def check_small_convolutions():
    rows=[]
    for q,d in [(3,4),(5,4),(3,6)]:
        ks=list(range(1,q))
        cache={}
        for k in ks:
            S=sphere(q,d,k)
            for h in (2,3):
                D,den=convolution(q,d,k,h)
                tv=tv_uniform(q,d,D,den)
                bound=fourier_bound(q,d,h)
                assert float(tv) <= bound + 1e-12
                cache[k,h]=(D,den)
                rows.append({
                    "q":q,"d":d,"k":k,"h":h,
                    "sphere_size":len(S),
                    "tv_uniform":f"{tv.numerator}/{tv.denominator}",
                    "tv_uniform_float":float(tv),
                    "fourier_bound":bound,
                })
        if len(ks)>=2:
            for h in (2,3):
                A,da=cache[ks[0],h]; B,db=cache[ks[1],h]
                pair=tv_pair(q,d,A,da,B,db)
                assert float(pair) <= 2*fourier_bound(q,d,h)+1e-12
    return rows


def check_23_pair():
    q,d=3,4
    D12,n12=convolution(q,d,1,2)
    D13,n13=convolution(q,d,1,3)
    D22,n22=convolution(q,d,2,2)
    D23,n23=convolution(q,d,2,3)
    pts=vectors(q,d)
    total=Fraction(0,1)
    for a in pts:
      for b in pts:
        p=Fraction(D12.get(a,0),n12)*Fraction(D13.get(b,0),n13)
        r=Fraction(D22.get(a,0),n22)*Fraction(D23.get(b,0),n23)
        total += abs(p-r)
    tv=total/2
    assert tv==Fraction(73,512)
    return {
      "q":q,"d":d,
      "joint_key1_vs_key2_tv":f"{tv.numerator}/{tv.denominator}",
      "joint_key1_vs_key2_tv_float":float(tv),
    }


def check_nonunit_coefficients():
    q,d,k=5,4,1
    base,den=convolution(q,d,k,2,[1,1])
    base_tv=tv_uniform(q,d,base,den)
    vals=[]
    for a,b in [(1,2),(2,3),(4,2),(3,4)]:
        D,n=convolution(q,d,k,2,[a,b])
        tv=tv_uniform(q,d,D,n)
        assert float(tv) <= fourier_bound(q,d,2)+1e-12
        vals.append({"coeffs":[a,b],"tv_uniform":f"{tv.numerator}/{tv.denominator}","float":float(tv)})
    return {"q":q,"d":d,"key":k,"unit_coeff_tv":f"{base_tv.numerator}/{base_tv.denominator}","variants":vals}


def check_sampler_weights():
    rows=[]
    for q,d,k in [(3,4,1),(7,4,1),(7,4,3)]:
        assert q%4==3
        counts={}
        for r in range(q):
            c=sum(1 for a in range(q) for b in range(q) if (a*a+b*b-r)%q==0)
            counts[r]=c
            assert c==(1 if r==0 else q+1)
        weights=[]
        for prefix in itertools.product(range(q), repeat=d-2):
            r=(k-sum(x*x for x in prefix))%q
            N=counts[r]
            accept=Fraction(N,q+1)
            sols=[(a,b) for a in range(q) for b in range(q) if (a*a+b*b-r)%q==0]
            for a,b in sols:
                weights.append(accept*Fraction(1,N))
        assert weights and len(set(weights))==1 and weights[0]==Fraction(1,q+1)
        assert len(weights)==len(sphere(q,d,k))
        rows.append({
            "q":q,"d":d,"k":k,"sphere_size":len(weights),
            "pair_counts":counts,
            "scaled_point_weight":f"{weights[0].numerator}/{weights[0].denominator}",
        })
    return rows


def check_fourier_coefficients():
    rows=[]
    for q,d,k in [(3,4,1),(5,4,2),(3,6,1)]:
        S=sphere(q,d,k)
        beta=(q**(1-d/2))/(1-q**(1-d/2))
        maxabs=0.0
        arg=None
        for xi in vectors(q,d):
            if all(t==0 for t in xi):
                continue
            s=0j
            for x in S:
                dot=sum(a*b for a,b in zip(xi,x))%q
                s += cmath.exp(2j*math.pi*dot/q)
            val=abs(s/len(S))
            if val>maxabs:
                maxabs=val; arg=xi
        assert maxabs <= beta+1e-10
        rows.append({"q":q,"d":d,"k":k,"max_nontrivial_fourier":maxabs,"beta":beta,"argmax":arg})
    return rows


def parameter_examples():
    rows=[]
    for bits in (64,128,192):
        q=2**bits
        d=8
        beta=(q**(1-d/2))/(1-q**(1-d/2))
        eps=0.5*(q**(d/2))*beta**2
        rows.append({"field_bits_lower_bound":bits,"d":d,"per_false_orbit_eps_upper_approx":eps})
    return rows


def main():
    out={
      "status":"PASS",
      "fixed_point":check_fixed_point(),
      "complete_fiber":check_complete_fiber(),
      "small_convolutions":check_small_convolutions(),
      "false_2_plus_3":check_23_pair(),
      "nonunit_coefficients":check_nonunit_coefficients(),
      "sampler_weights":check_sampler_weights(),
      "fourier_coefficients":check_fourier_coefficients(),
      "parameter_examples":parameter_examples(),
      "scope":"finite algebra/statistical validation only; not a generic-NP WKEM security test",
    }
    print(json.dumps(out,indent=2,sort_keys=True))

if __name__=="__main__":
    main()
