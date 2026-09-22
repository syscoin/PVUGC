#!/usr/bin/env python3
import json, random, hashlib
from collections import Counter

SEED = 202609220930
rng = random.Random(SEED)


def inv(a,q):
    return pow(a % q, q-2, q)


def solve_linear(A,b,q):
    """Return one solution if consistent; None otherwise. A may be overdetermined."""
    if not A:
        return [] if all((x % q)==0 for x in b) else None
    m=len(A); n=len(A[0])
    M=[[x%q for x in A[i]]+[b[i]%q] for i in range(m)]
    row=0; piv=[]
    for col in range(n):
        p=next((r for r in range(row,m) if M[r][col]%q),None)
        if p is None: continue
        M[row],M[p]=M[p],M[row]
        z=inv(M[row][col],q)
        M[row]=[(x*z)%q for x in M[row]]
        for r in range(m):
            if r!=row and M[r][col]%q:
                f=M[r][col]%q
                M[r]=[(M[r][c]-f*M[row][c])%q for c in range(n+1)]
        piv.append(col); row+=1
        if row==m: break
    for r in range(row,m):
        if all(M[r][c]%q==0 for c in range(n)) and M[r][n]%q:
            return None
    x=[0]*n
    for r,c in enumerate(piv): x[c]=M[r][n]%q
    # verify
    for i in range(m):
        if sum((A[i][j]%q)*x[j] for j in range(n))%q != b[i]%q:
            return None
    return x


def learn_recurrence(block, R, q):
    """Find minimum ell<=R recurrence y[t+ell]=sum c[j] y[t+j] from >=2R consecutive terms."""
    N=len(block)
    assert N>=2*R
    if all(x%q==0 for x in block):
        return []
    for ell in range(1,R+1):
        A=[]; b=[]
        for t in range(N-ell):
            A.append([block[t+j]%q for j in range(ell)])
            b.append(block[t+ell]%q)
        sol=solve_linear(A,b,q)
        if sol is not None:
            return sol
    raise AssertionError("no recurrence <=R")


def extrapolate(block, coeff, steps, q):
    y=[x%q for x in block]
    L=len(coeff)
    if L==0:
        return [0]*steps
    out=[]
    for _ in range(steps):
        nxt=sum(coeff[j]*y[-L+j] for j in range(L))%q
        y.append(nxt); out.append(nxt)
    return out


def exp_sum(lams, amps, t, q):
    return sum(a*pow(l,t,q) for l,a in zip(lams,amps))%q


def sample_lams(q,r):
    pool=list(range(2,q)) # excludes 0,1
    rng.shuffle(pool)
    return pool[:r]


def make_transcript(q,r,K,lams=None,amps=None,k0=None):
    R=r+1
    if lams is None: lams=sample_lams(q,r)
    if amps is None: amps=[rng.randrange(q) for _ in range(r)]
    if k0 is None: k0=rng.randrange(q)
    k1=(K-k0)%q
    def p(t): return exp_sum(lams,amps,t,q)
    def f0(t): return (k0+p(t))%q
    def f1(t): return (k1-p(t))%q
    S0=list(range(0,2*R))
    S1=list(range(2*R,4*R))
    out0=[f0(t) for t in S0]
    out1=[f1(t) for t in S1]
    return {"q":q,"r":r,"K":K,"lams":lams,"amps":amps,"k0":k0,"k1":k1,
            "S0":S0,"S1":S1,"out0":out0,"out1":out1,"f0":f0,"f1":f1}


def attack(tr,T=None):
    q=tr["q"]; r=tr["r"]; R=r+1
    if T is None: T=4*R+7
    c0=learn_recurrence(tr["out0"],R,q)
    c1=learn_recurrence(tr["out1"],R,q)
    # out0 ends at 2R-1, out1 ends at 4R-1
    n0=T-(2*R-1)
    n1=T-(4*R-1)
    assert n0>=1 and n1>=1
    v0=extrapolate(tr["out0"],c0,n0,q)[-1]
    v1=extrapolate(tr["out1"],c1,n1,q)[-1]
    return (v0+v1)%q, len(c0), len(c1), v0, v1


def test_honest():
    n=0
    for q,r,trials in [(101,1,400),(101,3,400),(101,8,400),(257,12,400)]:
        for _ in range(trials):
            K=rng.randrange(q); l=sample_lams(q,r); a=[rng.randrange(q) for _ in range(r)]; k0=rng.randrange(q); t=rng.randrange(0,100)
            p=exp_sum(l,a,t,q)
            if (k0+p + (K-k0-p))%q != K: raise AssertionError
            n+=1
    return n


def test_pair_exact():
    q=7; r=2; lams=[2,3]; u=0; v=1
    result={}
    for K in [0,1,2,6]:
        C=Counter()
        for a0 in range(q):
            for a1 in range(q):
                for k0 in range(q):
                    pu=(a0*pow(lams[0],u,q)+a1*pow(lams[1],u,q))%q
                    pv=(a0*pow(lams[0],v,q)+a1*pow(lams[1],v,q))%q
                    y0=(k0+pu)%q
                    y1=(K-k0-pv)%q
                    C[(y0,y1)]+=1
        vals=set(C.values())
        assert len(C)==q*q and vals=={q}
        result[str(K)]={"support":len(C),"multiplicity":next(iter(vals))}
    return result


def test_random_attack():
    configs=[(101,1,500),(101,2,500),(101,3,500),(101,5,500),(101,8,500),(257,12,350),(1009,20,250)]
    out=[]
    for q,r,trials in configs:
        ok=0; orders=[]
        for _ in range(trials):
            K=rng.randrange(q)
            tr=make_transcript(q,r,K)
            got,l0,l1,_,_=attack(tr)
            if got!=K:
                raise AssertionError((q,r,K,got,l0,l1,tr))
            ok+=1; orders.append((l0,l1))
        out.append({"q":q,"r":r,"trials":trials,"recovered":ok,
                    "min_order0":min(x[0] for x in orders),"max_order0":max(x[0] for x in orders),
                    "min_order1":min(x[1] for x in orders),"max_order1":max(x[1] for x in orders)})
    return out


def test_zero_degeneracies():
    q=101; r=6; lams=[2,3,5,7,11,13]
    cases=0
    # force many zero amplitudes and zero shares, including identically-zero shifted sequences.
    amp_cases=[[0]*r,[1,0,0,0,0,0],[0,2,0,3,0,0],[4,0,5,0,6,0]]
    for K in [0,1,17,100]:
        for amps in amp_cases:
            for k0 in [0,K,1,33]:
                tr=make_transcript(q,r,K,lams=lams,amps=amps,k0=k0)
                got,l0,l1,_,_=attack(tr)
                assert got==K and l0<=r+1 and l1<=r+1
                cases+=1
    return cases


def test_exhaustive_support():
    # Keep all queried/extrapolated integer indices below the multiplicative period q-1.
    q=23; r=1; R=r+1
    keys=[0,1,2]
    supports={K:set() for K in keys}
    setups=0
    lpool=list(range(2,q))
    for K in keys:
        count=0
        for lam in lpool:
            for a0 in range(q):
                for k0 in range(q):
                    tr=make_transcript(q,r,K,lams=[lam],amps=[a0],k0=k0)
                    got,*_=attack(tr)
                    assert got==K
                    supports[K].add(tuple(tr["out0"]+tr["out1"]))
                    count+=1
        if setups==0: setups=count
        else: assert setups==count
    inter={}
    for i in range(len(keys)):
        for j in range(i+1,len(keys)):
            a,b=keys[i],keys[j]
            z=len(supports[a]&supports[b]); assert z==0
            inter[f"{a}-{b}"]=z
    return {"q":q,"r":r,"setups_per_key":setups,"support_sizes":{str(K):len(supports[K]) for K in keys},"intersections":inter,
            "max_attack_index":4*R+7,"multiplicative_period":q-1}


def test_recurrence_identity():
    # Verify that learned recurrence predicts a long continuation, not just one attack point.
    total=0
    for q,r,trials in [(101,4,300),(257,9,200)]:
        R=r+1
        for _ in range(trials):
            K=rng.randrange(q); tr=make_transcript(q,r,K)
            c0=learn_recurrence(tr["out0"],R,q); c1=learn_recurrence(tr["out1"],R,q)
            p0=extrapolate(tr["out0"],c0,50,q)
            p1=extrapolate(tr["out1"],c1,50,q)
            for j,x in enumerate(p0):
                t=2*R+j
                assert x==tr["f0"](t)
            for j,x in enumerate(p1):
                t=4*R+j
                assert x==tr["f1"](t)
            total+=1
    return total


def main():
    result={
        "seed":SEED,
        "candidate":"hidden exponential-sum / finite-Hankel-rank zero-sum binder",
        "honest_same_key_decodes":test_honest(),
        "exact_one_pair_uniformity":test_pair_exact(),
        "random_false_recovery":test_random_attack(),
        "forced_zero_degeneracy_cases":test_zero_degeneracies(),
        "exhaustive_false_support":test_exhaustive_support(),
        "long_recurrence_prediction_trials":test_recurrence_identity(),
        "claim_scope":"finite-field algebra/reconstruction validation only; no security claim"
    }
    print(json.dumps(result,sort_keys=True,indent=2))

if __name__=='__main__': main()
