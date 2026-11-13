#!/usr/bin/env python3
"""Independent offline algebra/certificate checker, no external packages."""
import math, json, itertools
checks=0
def assert_(ok,what):
    global checks
    checks+=1
    if not ok: raise AssertionError(f'{checks}: {what}')

def near(y,q,g,m):
    return min(range(m), key=lambda t:(min((y-g*t)%q,(g*t-y)%q),t))

def recover(ys,q,g,m,k,D,V,pk,tau):
    a=[near(y,q,g,m) for y in ys]
    for t in range(tau+1):
        for slots in itertools.combinations(range(len(a)),t):
            for directions in itertools.product((-1,1),repeat=t):
                z=a.copy()
                for j,delta in zip(slots,directions):z[j]=(z[j]+delta)%m
                Z=sum(v*m**j for j,v in enumerate(z))
                if Z>=2**k:continue
                K=V^D^Z
                if (K*5+3)%17==pk:return K
    return None

def main():
    q=32;g=6;h=2;n=4;m=q//g;B=(1,31,2,30)
    witnesses=[]
    for mask in range(1<<n):
        w=tuple((mask>>j)&1 for j in range(n))
        if sum(w)==h and sum(w[i]*B[i] for i in range(n))%q==0:witnesses.append(w)
    assert_(len(witnesses)==2,'source has two accepted witnesses')
    count=0;fixed=0
    for w in witnesses:
      for Z in range(16):
        ts=(Z%m,Z//m)
        for K in range(16):
          pk=(5*K+3)%17
          for U in range(0,16,4):
            V=K^U;D=U^Z
            for err0 in range(-8,9):
              for err1 in range(-8,9):
                ys=((g*ts[0]+err0)%q,(g*ts[1]+err1)%q)
                wrong=sum(near(ys[j],q,g,m)!=ts[j] for j in range(2))
                if wrong>1:continue
                assert_(recover(ys,q,g,m,4,D,V,pk,1)==K,'same precommitted toy seed from list')
                fixed+=bool(wrong);count+=1
    assert_(count==368896 and fixed==280832,'independent enumerator case count')
    for fixedK in range(16):
        pairs={(U^Z, fixedK^U) for U in range(16) for Z in range(16)}
        assert_(len(pairs)==256,'exact jointly uniform zero-hybrid')
    Q=1<<20;N=4096;H=128;d=32;G=640;L=24;T=5;M=Q//G
    assert_(Q%G==256 and G%H==0 and G//H*N<Q,'new source parameters')
    assert_(M==1638 and M**23<2**256<=M**24,'radix capacity')
    assert_(math.comb(24,6)==134596,'bad-six tuples')
    assert_(sum(math.comb(L,j)*2**j for j in range(T+1))==1547489,'PPT candidate cap')
    assert_(2**816<math.comb(N,H)<2**817,'exact kernel count')
    assert_(G*G*25*16==625*8*H*256,'exact tail exponent')
    assert_(56*694*16<625*1000 and 506*694*16<5625*1000,'strict rational exp certificates')
    from fractions import Fraction
    a=Fraction(694,1000)
    lower=sum((a**j/math.factorial(j) for j in range(5)),Fraction())
    assert_(lower>2,'strict exp lower Taylor bound')
    assert_(177+18-6*55==-135 and 177+6-506==-323,'Gaussian subgaussian union exponents')
    assert_(N*L<2**17 and 2**-157+2**-313<2**-156,'global dyadic coupling budget')
    assert_(L*N*20//8==245760 and 28*N*20//8-L*N*20//8==40960,'packed 20-bit vectors')
    return {'status':'ok','checks':checks,'toy_cases':count,'toy_corrected':fixed,
        'baseline_columns':28,'list_columns':24,'bytes_saved':40960,
        'max_candidate_checks_per_witness':1547489,
        'global_honest_all_witness_failure':'<2^-134',
        'QPT_hardness':'not tested or certified; restricted reference only'}

if __name__=='__main__':print(json.dumps(main(),sort_keys=True,separators=(',',':')))
