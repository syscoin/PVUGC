#!/usr/bin/env python3
import json, random, hashlib, sys
from collections import Counter

SEED = 0x29C0FFEE
rng = random.Random(SEED)


def inv(a,q):
    return pow(a%q, q-2, q)


def peval(c,x,q):
    acc=0
    for a in reversed(c):
        acc=(acc*x+a)%q
    return acc


def rref_nullspace(A,q):
    A=[[(x%q) for x in row] for row in A]
    m=len(A); n=len(A[0]) if m else 0
    piv=[]; r=0
    for c in range(n):
        p=next((i for i in range(r,m) if A[i][c]%q),None)
        if p is None: continue
        A[r],A[p]=A[p],A[r]
        z=inv(A[r][c],q)
        A[r]=[(z*x)%q for x in A[r]]
        for i in range(m):
            if i!=r and A[i][c]%q:
                z=A[i][c]%q
                A[i]=[(A[i][j]-z*A[r][j])%q for j in range(n)]
        piv.append(c); r+=1
        if r==m: break
    free=[c for c in range(n) if c not in piv]
    basis=[]
    for f in free:
        v=[0]*n; v[f]=1
        for i,c in enumerate(piv):
            v[c]=(-A[i][f])%q
        basis.append(v)
    return basis, len(piv)


def rational_interpolate(points, values, d, q):
    # Find A,B deg<=d with A(x_i)=y_i B(x_i). Any nonzero solution
    # equals the true rational function if len(points)>=2d+1 and true poles are absent.
    rows=[]
    for x,y in zip(points,values):
        pw=[1]
        for _ in range(d): pw.append((pw[-1]*x)%q)
        rows.append(pw + [(-y*t)%q for t in pw])
    ns,rank=rref_nullspace(rows,q)
    if not ns:
        raise AssertionError('no nullspace')
    # choose a vector with nonzero denominator polynomial
    for v in ns:
        A=v[:d+1]; B=v[d+1:]
        if any(B):
            return A,B,len(ns),rank
    raise AssertionError('only zero denominators in nullspace')


def rat_eval(A,B,x,q):
    den=peval(B,x,q)
    if den==0: return None
    return peval(A,x,q)*inv(den,q)%q


def sample_den_nonzero(q,d,points):
    while True:
        D=[rng.randrange(q) for _ in range(d)] + [rng.randrange(1,q)]
        if all(peval(D,x,q)!=0 for x in points):
            return D


def sample_instance(q,d,K,points0,points1):
    pts=points0+points1
    D=sample_den_nonzero(q,d,pts)
    N=[rng.randrange(q) for _ in range(d+1)]
    k0=rng.randrange(q); k1=(K-k0)%q
    def R(x): return peval(N,x,q)*inv(peval(D,x,q),q)%q
    y0=[(k0+R(x))%q for x in points0]
    y1=[(k1-R(x))%q for x in points1]
    return D,N,k0,k1,y0,y1


def recover_key(q,d,points0,points1,y0,y1):
    A0,B0,n0,r0=rational_interpolate(points0,y0,d,q)
    A1,B1,n1,r1=rational_interpolate(points1,y1,d,q)
    zstar=None; g0=g1=None
    for z in range(q):
        g0=rat_eval(A0,B0,z,q); g1=rat_eval(A1,B1,z,q)
        if g0 is not None and g1 is not None:
            zstar=z; break
    if zstar is None: raise AssertionError('no common evaluation point')
    return (g0+g1)%q, {'zstar':zstar,'nullity0':n0,'nullity1':n1,'rank0':r0,'rank1':r1}


def test_common_correctness():
    q=101; d=5; ok=0
    for _ in range(2000):
        D=sample_den_nonzero(q,d,[7])
        N=[rng.randrange(q) for _ in range(d+1)]
        K=rng.randrange(q); k0=rng.randrange(q); k1=(K-k0)%q
        z=7; R=peval(N,z,q)*inv(peval(D,z,q),q)%q
        assert (k0+R+k1-R)%q==K
        ok+=1
    return {'trials':ok}


def exact_single_pair_hiding():
    # q=5,d=1, enumerate every denominator nonzero at u=0,v=1.
    q=5; d=1; u=0; v=1
    Ds=[[d0,d1] for d0 in range(q) for d1 in range(q)
        if peval([d0,d1],u,q)!=0 and peval([d0,d1],v,q)!=0]
    supports={}
    counts={}
    for K in [0,1,2]:
        C=Counter()
        for D in Ds:
            for n0 in range(q):
                for n1 in range(q):
                    N=[n0,n1]
                    Ru=peval(N,u,q)*inv(peval(D,u,q),q)%q
                    Rv=peval(N,v,q)*inv(peval(D,v,q),q)%q
                    for k0 in range(q):
                        y0=(k0+Ru)%q
                        y1=(K-k0-Rv)%q
                        C[(y0,y1)]+=1
        counts[K]=sorted(C.values())
        supports[K]=set(C)
        assert len(C)==q*q
        assert len(set(C.values()))==1
    assert supports[0]==supports[1]==supports[2]
    return {'q':q,'d':d,'admissible_denominators':len(Ds),'outputs':q*q,
            'count_per_output':counts[0][0],'support_equal_for_keys':[0,1,2]}


def random_false_recovery():
    stats=[]
    for q,d,trials in [(101,1,500),(101,2,500),(101,3,500),(101,5,500),(257,8,500),(1009,12,300)]:
        m=2*d+1
        assert 2*m<q
        p0=list(range(m)); p1=list(range(m,2*m))
        ok=0; maxnull=0; zhist=Counter()
        for _ in range(trials):
            K=rng.randrange(q)
            D,N,k0,k1,y0,y1=sample_instance(q,d,K,p0,p1)
            Kr,meta=recover_key(q,d,p0,p1,y0,y1)
            assert Kr==K
            ok+=1; maxnull=max(maxnull,meta['nullity0'],meta['nullity1']); zhist[meta['zstar']]+=1
        stats.append({'q':q,'degree':d,'samples_per_side':m,'trials':trials,'recovered':ok,
                      'max_interpolation_nullity':maxnull,'most_common_zstar':zhist.most_common(1)[0][0]})
    return stats


def exhaustive_complete_support():
    # Full q=5,d=1 rational family conditioned on no poles at the four false-set points.
    q=7; d=1; p0=[0,1,2]; p1=[3,4,5]; pts=p0+p1
    Ds=[[d0,d1] for d0 in range(q) for d1 in range(q)
        if any([d0,d1]) and all(peval([d0,d1],x,q)!=0 for x in pts)]
    supports={}
    recoveries={}
    for K in [0,1]:
        S=set(); rec=0
        for D in Ds:
            for n0 in range(q):
                for n1 in range(q):
                    N=[n0,n1]
                    for k0 in range(q):
                        k1=(K-k0)%q
                        def R(x): return peval(N,x,q)*inv(peval(D,x,q),q)%q
                        y0=tuple((k0+R(x))%q for x in p0)
                        y1=tuple((k1-R(x))%q for x in p1)
                        tr=y0+y1
                        S.add(tr)
                        Kr,_=recover_key(q,d,p0,p1,list(y0),list(y1))
                        assert Kr==K; rec+=1
        supports[K]=S; recoveries[K]=rec
    inter=supports[0]&supports[1]
    assert not inter
    return {'q':q,'degree':d,'set0':p0,'set1':p1,'admissible_denominators':len(Ds),
            'setups_per_key':recoveries[0], 'support_sizes':{str(k):len(v) for k,v in supports.items()},
            'cross_key_support_intersection':len(inter),'pairwise_tv':'1'}


def meta_linear_space_control():
    # Public M-dimensional function space over q, basis 1,z,...,z^(M-1).
    # Reconstruct two shifted functions on disjoint unisolvent sets and sum at z=0.
    q=101; out=[]
    for M in [2,3,5,8,12]:
        trials=100
        p0=list(range(M)); p1=list(range(M,2*M))
        ok=0
        for _ in range(trials):
            coeff=[rng.randrange(q) for _ in range(M)]
            K=rng.randrange(q); k0=rng.randrange(q); k1=(K-k0)%q
            def P(x): return peval(coeff,x,q)
            y0=[(k0+P(x))%q for x in p0]
            y1=[(k1-P(x))%q for x in p1]
            # degree M-1 rational interpolation with denominator 1 would need 2M-1; use Vandermonde linear solve instead.
            def interp(xs,ys):
                A=[]
                for x,y in zip(xs,ys):
                    row=[]; t=1
                    for _ in range(M): row.append(t); t=t*x%q
                    A.append(row+[y])
                # Gauss solve square system
                for c in range(M):
                    p=next(i for i in range(c,M) if A[i][c]%q)
                    A[c],A[p]=A[p],A[c]
                    z=inv(A[c][c],q); A[c]=[(z*v)%q for v in A[c]]
                    for i in range(M):
                        if i!=c and A[i][c]:
                            z=A[i][c]; A[i]=[(A[i][j]-z*A[c][j])%q for j in range(M+1)]
                return [A[i][-1] for i in range(M)]
            c0=interp(p0,y0); c1=interp(p1,y1)
            # polynomial identity g0+g1=K, so all nonconstant coeffs cancel and constants sum to K
            assert (c0[0]+c1[0])%q==K
            assert all((c0[i]+c1[i])%q==0 for i in range(1,M))
            ok+=1
        out.append({'dimension':M,'trials':trials,'recovered':ok})
    return out


def main():
    result={
        'seed':SEED,
        'common_correctness':test_common_correctness(),
        'single_pair_exact_hiding':exact_single_pair_hiding(),
        'false_rational_interpolation_recovery':random_false_recovery(),
        'exhaustive_complete_support':exhaustive_complete_support(),
        'linear_space_meta_control':meta_linear_space_control(),
    }
    print(json.dumps(result,sort_keys=True,indent=2))

if __name__=='__main__': main()
