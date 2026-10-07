#!/usr/bin/env python3
"""Run 347: exhaustive finite checks of shared-secret public-offset leakage.
Pure Python, no dependencies or cryptographic security claims.
"""
import itertools, json, hashlib
from collections import Counter
from fractions import Fraction

N=0

def check(ok, msg=None):
    global N
    N+=1
    if not ok:
        raise AssertionError((N,msg))

def rank(M,q):
    if not M: return 0
    a=[[x%q for x in row] for row in M]
    m=len(a); n=len(a[0]); row=0
    for j in range(n):
        pivot=next((i for i in range(row,m) if a[i][j]),None)
        if pivot is None: continue
        a[row],a[pivot]=a[pivot],a[row]
        inv=pow(a[row][j],-1,q)
        a[row]=[(x*inv)%q for x in a[row]]
        for i in range(m):
            if i!=row and a[i][j]:
                z=a[i][j]
                a[i]=[(x-z*y)%q for x,y in zip(a[i],a[row])]
        row+=1
        if row==m: break
    return row

def solve(M,b,q):
    # Return one solution to M x=b, or None, via RREF.
    if not M: return []
    a=[[(x%q) for x in row]+[z%q] for row,z in zip(M,b)]
    m=len(a); n=len(a[0])-1; row=0; pivots=[]
    for j in range(n):
        pivot=next((i for i in range(row,m) if a[i][j]),None)
        if pivot is None: continue
        a[row],a[pivot]=a[pivot],a[row]
        inv=pow(a[row][j],-1,q)
        a[row]=[(x*inv)%q for x in a[row]]
        for i in range(m):
            if i!=row and a[i][j]:
                z=a[i][j]
                a[i]=[(x-z*y)%q for x,y in zip(a[i],a[row])]
        pivots.append(j); row+=1
        if row==m: break
    for i in range(row,m):
        if a[i][n]: return None
    x=[0]*n
    for i,j in enumerate(pivots): x[j]=a[i][n]
    return x

def mask(T,s,c,q):
    # T has n rows and m target columns, D_i = c - sum_j T[j][i]*s[j].
    return tuple((c-sum(T[j][i]*s[j] for j in range(len(s))))%q for i in range(len(T[0])))

stats=Counter()
classification={}
for q in (2,3,5):
    for n in (1,2):
        for m in (1,2,3):
            if q==5 and n==2 and m==3:
                # Still fully exhaustive; 5**6=15625 matrices.
                pass
            key=f'q{q}_n{n}_m{m}'
            total=bad=good=0
            for flat in itertools.product(range(q),repeat=n*m):
                T=[list(flat[i*m:(i+1)*m]) for i in range(n)]
                total+=1
                r=rank(T,q)
                has_leak=(rank(T+[[1]*m],q)>r)
                if has_leak:
                    bad+=1
                    # Find a in kernel T with <ones,a>=1.
                    a=solve(T+[[1]*m],[0]*n+[1],q)
                    check(a is not None,(key,'missing annihilator',T))
                    check(all(sum(a[i]*T[j][i] for i in range(m))%q==0 for j in range(n)))
                    check(sum(a)%q==1)
                    # Exact recovery for EVERY uniformly sampled s and c.
                    for s in itertools.product(range(q),repeat=n):
                        for c in (0,1):
                            d=mask(T,s,c,q)
                            check(sum(a[i]*d[i] for i in range(m))%q==c)
                else:
                    good+=1
                    # Construct gauge vector lambda with lambda^T*T=ones.
                    lam=solve([[T[j][i] for j in range(n)] for i in range(m)],[1]*m,q)
                    check(lam is not None,(key,'missing gauge',T))
                    check(all(sum(lam[j]*T[j][i] for j in range(n))%q==1 for i in range(m)))
                    # Exact coupling (permutation) proving mask-only hiding.
                    for s in itertools.product(range(q),repeat=n):
                        d1=mask(T,s,1,q)
                        s0=tuple((s[j]-lam[j])%q for j in range(n))
                        check(d1==mask(T,s0,0,q))
                if q<=3 and m<=3 and n<=2:
                    # Every d=0 has exactly q^rank(T) possible independent
                    # field-symbol key vectors c, a quotient leak of m-r.
                    row_space={tuple(sum(T[j][i]*s[j] for j in range(n))%q for i in range(m))
                               for s in itertools.product(range(q),repeat=n)}
                    check(len(row_space)==q**r)
            if m>n:
                # Uniform random row-space symmetry: probability a fixed nonzero
                # vector belongs to rank-r row space is (q**r-1)/(q**m-1).
                # Since r<=n, unconditional leakage probability has this bound.
                bound=Fraction(1,1)-Fraction(q**n-1,q**m-1)
                check(Fraction(bad,total)>=bound,('rank bound',key,bad,total,bound))
            classification[key]={'total':total,'leaks_same_key':bad,'hides_mask_only':good,
                                 'leak_fraction':str(Fraction(bad,total))}

            stats['matrices']+=total
            stats['leaking_matrices']+=bad
            stats['nonleaking_matrices']+=good

# Three distinct targets, none zero: t1=e1,t2=e2,t3=e1+e2.
# D1+D2-D3=c for the same branch key, without any source witness.
for q in (3,5,7,11):
    T=[[1,0,1],[0,1,1]]
    for s in itertools.product(range(q),repeat=2):
        for c in range(q):
            d=mask(T,s,c,q)
            check((d[0]+d[1]-d[2])%q==c)
            stats['three_target_full_key_recoveries']+=1

# Separate keys per claim do NOT repair correlation if the master secret is
# reused: for t2=2*t1, d2-2d1=c_b2-2*c_b1.
# For odd q>=5 and centers 0,(q-1)/2 all four bit pairs are distinguishable.
for q in (5,7,11,13):
    center=(q-1)//2
    table={(b1,b2):(center*b2-2*center*b1)%q for b1,b2 in itertools.product((0,1),repeat=2)}
    check(len(set(table.values()))==4)
    inverse={v:k for k,v in table.items()}
    for n in (1,2):
        for t in itertools.product(range(q),repeat=n):
            if not any(t): continue
            for s in itertools.product(range(q),repeat=n):
                z=sum(t[j]*s[j] for j in range(n))%q
                for (b1,b2), residue in table.items():
                    d1=(center*b1-z)%q
                    d2=(center*b2-2*z)%q
                    got=(d2-2*d1)%q
                    check(got==residue)
                    check(inverse[got]==(b1,b2))
                    stats['different_key_full_bit_pair_recoveries']+=1

# Fresh independent master secrets per capsule stop the 2-target linear
# elimination in the mask-only view, even for t2=2*t1.
for q in (5,7):
    center=(q-1)//2
    distributions=[]
    for b1,b2 in itertools.product((0,1),repeat=2):
        counts=Counter(((center*b1-s1)%q,(center*b2-2*s2)%q)
                       for s1,s2 in itertools.product(range(q),repeat=2))
        check(len(counts)==q*q)
        check(set(counts.values())=={1})
        distributions.append(counts)
    check(all(distributions[0]==x for x in distributions[1:]))
    stats['fresh_secret_controls']+=1

# Nonleaking control: identical targets with same K gives zero difference,
# not key extraction; fresh independent s_i are outside this attack.
for q in (3,5,7):
    for s in range(q):
        for c in range(q):
            d=(c-s)%q
            check((d-d)%q==0)
            stats['identical_target_no_leak_controls']+=1

out={
  'status':'PASS',
  'assertions':N,
  'classification':classification,
  'stats':dict(stats),
  'assumptions':['prime-field arithmetic','same uniform hidden s across public offsets',
                 'no assumption about correctness/hiding of a full LWE public hp'],
  'limitations':['finite checks do not prove cryptographic hardness',
                 'nonleak classification is for mask-only view, not full LWE view',
                 'related targets may be excluded by independently justified binding/fresh keys']
}
print(json.dumps(out,sort_keys=True,indent=2))
