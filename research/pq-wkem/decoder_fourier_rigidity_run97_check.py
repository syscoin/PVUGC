#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import math
from fractions import Fraction
from itertools import product


def parity(x):
    return sum(x) & 1


def dot2(a, b):
    return sum(x*y for x, y in zip(a, b)) & 1


def mat_vec2(P, y):
    return tuple(dot2(row, y) for row in P)


def wt(v):
    return sum(1 for x in v if x)


def walsh_coeff_bool(fvals, y):
    # normalized Walsh coefficient E_x f(x)(-1)^{<y,x>}
    n = int(round(math.log2(len(fvals))))
    assert 2**n == len(fvals)
    acc = 0
    for x, fv in zip(all_vectors(n), fvals):
        acc += fv * (-1 if dot2(x, y) else 1)
    return Fraction(acc, 2**n)


def walsh_all_bool(fvals):
    # normalized fast Walsh-Hadamard transform using lexicographic product order.
    # itertools.product order corresponds binary integer with first coordinate most significant.
    a = list(fvals)
    n = len(a)
    h = 1
    while h < n:
        for i in range(0,n,2*h):
            for j in range(i,i+h):
                x=a[j]; y=a[j+h]
                a[j]=x+y; a[j+h]=x-y
        h*=2
    return [Fraction(v,n) for v in a]

def idx_to_vec_lex(idx, m):
    return tuple((idx >> (m-1-j)) & 1 for j in range(m))

def all_vectors(n):
    return list(product((0, 1), repeat=n))


def rowspace(P):
    if not P:
        return {(0,) * 0}
    r = len(P)
    m = len(P[0])
    out = set()
    for a in product((0, 1), repeat=r):
        v = [0]*m
        for i, ai in enumerate(a):
            if ai:
                for j in range(m):
                    v[j] ^= P[i][j]
        out.add(tuple(v))
    return out


def kernel(P, m):
    return [y for y in all_vectors(m) if all(v == 0 for v in mat_vec2(P, y))]


def qsym_prob_bit(e, beta: Fraction):
    # q=2: P(0)=(1+beta)/2, P(1)=(1-beta)/2
    return (1 + beta)/2 if e == 0 else (1 - beta)/2


def channel_prob_bit(x, b, P, h, beta):
    m = len(h)
    rs = rowspace(P)
    if P:
        # uniform over distinct rowspace elements, equivalent to P^T s when full row-rank;
        # checker fixtures use full row-rank P.
        denom = len(rs)
    else:
        rs = {(0,)*m}
        denom = 1
    total = Fraction(0, 1)
    for rvec in rs:
        e = tuple(x[j] ^ rvec[j] ^ (b & h[j]) for j in range(m))
        p = Fraction(1, denom)
        for ej in e:
            p *= qsym_prob_bit(ej, beta)
        total += p
    return total


def check_response_identity():
    # Exhaustively verify the q=2, L=1 specialization of Eq. (2) on deterministic decoders.
    cases = []
    fixtures = [
        ((), (1,0,0)),
        (((1,1,0),), (1,0,1)),
        (((1,0,1),(0,1,1)), (1,1,1)),
    ]
    betas = [Fraction(1,3), Fraction(1,2), Fraction(2,3)]
    decoder_masks = [0b00000000, 0b10110110, 0b01101001, 0b11110000, 0b01010101]
    for P0, h in fixtures:
        P = [tuple(r) for r in P0]
        m = len(h)
        xs = all_vectors(m)
        C = kernel(P, m)
        for beta in betas:
            for mask in decoder_masks:
                fvals = []
                succ = Fraction(0,1)
                for idx, x in enumerate(xs):
                    abit = (mask >> idx) & 1
                    fvals.append(-1 if abit else 1)
                    for b in (0,1):
                        pr = Fraction(1,2) * channel_prob_bit(x,b,P,h,beta)
                        if abit == b:
                            succ += pr
                eps2 = 2*succ - 1  # 2 epsilon = correlation
                rhs = Fraction(0,1)
                for y in C:
                    hf = dot2(h, y)
                    if hf == 0:
                        continue
                    # q=2 => (1-(-1)^sigma)/2 = 1 for sigma=1
                    hat = walsh_coeff_bool(fvals, y)
                    rhs += hat * (beta ** wt(y))
                assert eps2 == rhs, (P,h,beta,mask,eps2,rhs)
                cases.append({"m":m,"rank_rows":len(P),"beta":str(beta),"mask":mask,"correlation":str(eps2)})
    return cases


def bent_decoder_value(x, r):
    # x=(x0, z_1..z_r, u1,v1,..,ur,vr)
    a = x[0]
    for j in range(r):
        a ^= x[1+j]
    off = 1+r
    for i in range(r):
        a ^= x[off+2*i] & x[off+2*i+1]
    return a


def check_bent_spectra():
    rows = []
    for r in range(1,5):
        m = 3*r+1
        xs = all_vectors(m)
        fvals = [(-1 if bent_decoder_value(x,r) else 1) for x in xs]
        coeffs=walsh_all_bool(fvals)
        nonzero=[]
        for idx,c in enumerate(coeffs):
            if c:
                y=idx_to_vec_lex(idx,m)
                nonzero.append((y,c))
        assert len(nonzero) == 4**r
        mags={abs(c) for _,c in nonzero}
        assert mags == {Fraction(1,2**r)}
        minw=min(wt(y) for y,_ in nonzero)
        assert minw == r+1
        e0=(1,)+(0,)*(m-1)
        e0_idx=1 << (m-1)
        assert coeffs[e0_idx]==0
        # support coordinates x0 and all z_j must be 1
        for y,c in nonzero:
            assert y[0]==1
            assert all(y[1+j]==1 for j in range(r))
        rows.append({"r":r,"m":m,"support":len(nonzero),"coeff_abs":str(Fraction(1,2**r)),"min_weight":minw})
    return rows


def kappa2(beta):
    return 1 - (1-beta)*(1-beta)/2


def exact_bent_success(r, beta):
    # exhaustive over all binary noise vectors; b cancels from A(X)+b
    m=3*r+1
    total=Fraction(0,1)
    for e in all_vectors(m):
        p=Fraction(1,1)
        for ej in e:
            p*=qsym_prob_bit(ej,beta)
        phase = -1 if bent_decoder_value(e,r) else 1
        total += p*phase
    formula=(beta**(r+1))*(kappa2(beta)**r)
    assert total==formula, (r,beta,total,formula)
    succ=(1+total)/2
    return total,succ


def check_success_and_asymptotics():
    exact=[]
    for r in range(1,5):
        beta=Fraction(r+1, r+2)  # nondegenerate rational
        corr,succ=exact_bent_success(r,beta)
        exact.append({"r":r,"beta":str(beta),"correlation":str(corr),"success":str(succ)})
    table=[]
    for r in [2,4,8,16,32,64,128,256]:
        beta=1.0-1.0/r
        kap=1.0-((1.0-beta)**2)/2.0
        corr=(beta**(r+1))*(kap**r)
        table.append({
            "r":r,
            "beta":beta,
            "correlation":corr,
            "success":0.5*(1+corr),
            "coeff_abs":2.0**(-r),
            "min_fourier_weight":r+1,
            "limit_success_a1":0.5*(1+math.e**-1),
        })
    return exact,table


def check_sparse_thresholds():
    rows=[]
    # purely arithmetic checks of Theorem 2 bounds.
    for beta in [0.25,0.5,0.75,0.9]:
        for M in [4,16,256,4096]:
            eps=1/16
            gamma=2*eps/M
            Wmax=math.log(M/(2*eps))/math.log(1/beta)
            # Any product >= gamma with coefficient <=1 forces beta^W >= gamma.
            for w in range(0, max(1,int(math.floor(Wmax))+4)):
                if (beta**w) >= gamma - 1e-15:
                    assert w <= Wmax + 1e-12
            rows.append({"beta":beta,"M":M,"epsilon":eps,"heavy_coeff_floor":gamma,"weight_bound":Wmax})
    return rows


def main():
    response=check_response_identity()
    spectra=check_bent_spectra()
    exact,asym=check_success_and_asymptotics()
    sparse=check_sparse_thresholds()
    out={
        "run":97,
        "status":"PASS",
        "checks":{
            "arbitrary_decoder_identity_cases":len(response),
            "bent_spectrum_exact_r_cases":len(spectra),
            "bent_success_exact_cases":len(exact),
            "asymptotic_rows":len(asym),
            "sparse_threshold_rows":len(sparse),
        },
        "response_identity_sample":response[:8],
        "bent_spectrum":spectra,
        "bent_success_exact":exact,
        "bent_asymptotic":asym,
        "sparse_threshold_sample":sparse[:8],
        "scope":"Exact finite algebra/probability checks only; no cryptographic hardness or arbitrary-source extraction is inferred.",
    }
    blob=(json.dumps(out,sort_keys=True,indent=2)+"\n").encode()
    print(blob.decode(),end="")

if __name__=="__main__":
    main()
