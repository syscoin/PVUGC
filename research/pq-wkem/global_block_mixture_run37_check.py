#!/usr/bin/env python3
from fractions import Fraction
from itertools import product
import json, math, random


def dot(a,b):
    return sum((x & y) for x,y in zip(a,b)) & 1


def xor(a,b):
    return tuple(x ^ y for x,y in zip(a,b))


def gf2_rank(rows):
    vals=[]
    for r in rows:
        v=0
        for i,b in enumerate(r):
            v |= (b & 1) << i
        vals.append(v)
    rank=0
    bit=max((v.bit_length() for v in vals), default=0)-1
    while bit>=0:
        pivot=None
        for j in range(rank,len(vals)):
            if (vals[j]>>bit)&1:
                pivot=j; break
        if pivot is not None:
            vals[rank],vals[pivot]=vals[pivot],vals[rank]
            for j in range(len(vals)):
                if j!=rank and ((vals[j]>>bit)&1):
                    vals[j] ^= vals[rank]
            rank += 1
        bit -= 1
    return rank


def span(basis):
    if not basis:
        return [tuple()]
    out=[(0,)*len(basis[0])]
    for v in basis:
        old=list(out)
        out.extend(xor(x,v) for x in old)
    return out


def one_step_noise(N, coords, p):
    zero=(0,)*N
    d={zero: Fraction(1)-p}
    if p:
        share=p/Fraction(len(coords))
        for i in coords:
            e=[0]*N; e[i]=1; e=tuple(e)
            d[e]=d.get(e,Fraction(0))+share
    return d


def fourier_bias(noise,z):
    return sum(prob * (1 if dot(e,z)==0 else -1) for e,prob in noise.items())


def convolve(d1,d2):
    out={}
    for x,px in d1.items():
        for y,py in d2.items():
            z=xor(x,y)
            out[z]=out.get(z,Fraction(0))+px*py
    return out


def in_span(x,basis):
    return gf2_rank(basis+[x]) == gf2_rank(basis)


def public_likelihood(x,K,basis,Delta,noise):
    kd=Delta if K else (0,)*len(Delta)
    total=Fraction(0)
    for e,pe in noise.items():
        candidate=xor(xor(x,kd),e)
        if in_span(candidate,basis):
            total += pe
    return total / (2**len(basis))


def capsule_dist(R, Delta, noise, K):
    N=len(Delta)
    kd=Delta if K else (0,)*N
    out={}
    for r in R:
        for e,pe in noise.items():
            x=xor(xor(r,kd),e)
            out[x]=out.get(x,Fraction(0))+pe/Fraction(len(R))
    return out


def map_success(P0,P1):
    keys=set(P0)|set(P1)
    return sum(max(P0.get(x,Fraction(0)),P1.get(x,Fraction(0))) for x in keys)/2


def witness_success(P0,P1,z):
    s=Fraction(0)
    for K,P in enumerate((P0,P1)):
        for x,px in P.items():
            if dot(z,x)==K:
                s += px/2
    return s


def run():
    checks={}

    ex=0
    for G,L in [(2,2),(2,4),(3,2)]:
        N=G*L
        coords=list(range(N))
        for p in [Fraction(1,4),Fraction(1,2),Fraction(1,1)]:
            noise=one_step_noise(N,coords,p)
            for z in product([0,1], repeat=N):
                w=sum(z)
                got=fourier_bias(noise,z)
                want=Fraction(1)-2*p*Fraction(w,G*L)
                assert got==want, (G,L,p,z,got,want)
                ex += 1
    checks['one_step_fourier_cases']=ex

    G,L=8,4
    p=Fraction(1,2)
    delta=Fraction(1,4)
    honest_w=G
    false_w=G + 2*(delta*G)
    a=Fraction(1)-2*p*Fraction(honest_w,G*L)
    b=Fraction(1)-2*p*Fraction(false_w,G*L)
    assert a==Fraction(3,4)
    assert b==Fraction(5,8)
    checks['gap_control']={
        'G':G,'L':L,'p':str(p),'delta':str(delta),
        'honest_bias':str(a),'false_min_gap_bias':str(b)
    }

    N=8
    Delta=(0,0,0,0,0,0,0,1)
    z=(1,0,0,0,0,0,0,1)
    coords=[0,1,2,3]
    noise=one_step_noise(N,coords,Fraction(1,2))

    fixtures=[
        [
            (1,1,0,1,0,0,1,1),
            (1,0,1,0,0,1,0,1),
            (1,1,0,0,0,0,0,1),
            (0,0,0,0,1,0,1,0),
        ],
        [
            (0,0,0,1,0,1,1,0),
            (0,0,1,1,1,1,1,0),
            (0,1,1,1,1,1,0,0),
        ],
    ]
    map_rows=[]
    for basis in fixtures:
        assert all(dot(z,v)==0 for v in basis)
        R=span(basis)
        P0=capsule_dist(R,Delta,noise,0)
        P1=capsule_dist(R,Delta,noise,1)
        ms=map_success(P0,P1)
        ws=witness_success(P0,P1,z)
        assert ws==Fraction(7,8)
        assert ms>=ws
        map_rows.append({'rowspace_dim':len(basis),'map_success':str(ms),'witness_success':str(ws)})
    assert map_rows[0]['map_success']=='7/8'
    assert map_rows[1]['map_success']=='1'
    checks['map_fixtures']=map_rows

    rng=random.Random(370037)
    random_checks=0
    strict_map_wins=0
    for _ in range(128):
        basis=[]
        target_dim=rng.choice([2,3,4,5])
        while len(basis)<target_dim:
            v=tuple(rng.randrange(2) for _ in range(N))
            if dot(z,v):
                continue
            if gf2_rank(basis+[v])>len(basis):
                basis.append(v)
        R=span(basis)
        P0=capsule_dist(R,Delta,noise,0)
        P1=capsule_dist(R,Delta,noise,1)
        for K,P in enumerate((P0,P1)):
            for x,px in P.items():
                assert public_likelihood(x,K,basis,Delta,noise)==px
                random_checks += 1
        ms=map_success(P0,P1)
        ws=witness_success(P0,P1,z)
        assert ms>=ws
        if ms>ws:
            strict_map_wins += 1
    checks['random_public_likelihood_coordinates']=random_checks
    checks['random_fixtures_with_map_strictly_better_than_witness']=strict_map_wins

    N=4
    coords=list(range(N))
    base=one_step_noise(N,coords,Fraction(1,2))
    conv={(0,)*N:Fraction(1)}
    conv_cases=0
    for T in range(1,7):
        conv=convolve(conv,base)
        for z in product([0,1], repeat=N):
            one=fourier_bias(base,z)
            got=fourier_bias(conv,z)
            assert got==one**T
            conv_cases += 1
    checks['convolution_fourier_cases']=conv_cases

    a=Fraction(3,4); b=Fraction(5,8)
    table=[]
    for lam in [64,128,256,512,1024,4096]:
        T=math.ceil(math.log2(lam))
        ah=float(a**T); bh=float(b**T)
        amp=1/(ah*ah)
        table.append({
            'lambda':lam,'T':T,
            'honest_bias':ah,'false_fixed_mode_bound':bh,
            'honest_constant_snr_samples_approx':amp,
            'false_to_honest_bias_ratio':bh/ah,
        })
    checks['log_walk_table']=table
    checks['exponents']={
        'honest_lambda_exponent_per_c': math.log2(4/3),
        'false_lambda_exponent_per_c': math.log2(8/5),
        'false_over_honest_exponent_gap_per_c': math.log2((8/5)/(4/3)),
    }

    return checks

if __name__=='__main__':
    out=run()
    print(json.dumps(out,indent=2,sort_keys=True))
