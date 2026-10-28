#!/usr/bin/env python3
"""Offline deterministic checker for exact l1-sphere LWE encryption sampling.

Build must use a cryptographic unbiased RNG; this deterministic RNG is only for repeatable tests.
Tests prove finite integer/algebraic identities, not quantum hardness.
"""
from collections import Counter
from hashlib import sha256
from itertools import combinations, product
from math import comb, ceil, log2
from random import Random
import json

seed=0x20261028
rng=Random(seed)
checks=0

def check(condition, message):
    global checks
    checks+=1
    if not condition:
        raise AssertionError(message)

def count_sphere(m,h):
    if h==0: return 1
    return sum((1<<k)*comb(m,k)*comb(h-1,k-1) for k in range(1,min(m,h)+1))

def count_weights(m,h):
    return [0]+[(1<<k)*comb(m,k)*comb(h-1,k-1) for k in range(1,min(m,h)+1)]

def sample_r(m,h,weights,total,rng):
    # Exact uniform sampling on {r in Z^m : ||r||_1=h}; choose k by its combinatorial weight.
    x=rng.randrange(total)
    cumulative=0
    k=None
    for j,w in enumerate(weights):
        cumulative+=w
        if x<cumulative:
            k=j
            break
    assert k and k<=min(m,h)
    support=sorted(rng.sample(range(m),k))
    cuts=sorted(rng.sample(range(1,h),k-1))
    parts=[b-a for a,b in zip([0]+cuts,cuts+[h])]
    out=[0]*m
    for pos,val in zip(support,parts):
        out[pos]=val if rng.getrandbits(1) else -val
    return out

def small_enumeration(m,h):
    found=Counter()
    for k in range(1,min(m,h)+1):
        for support in combinations(range(m),k):
            for cuts in combinations(range(1,h),k-1):
                parts=[b-a for a,b in zip((0,)+cuts,cuts+(h,))]
                for signs in product((-1,1),repeat=k):
                    r=[0]*m
                    for loc,v,sgn in zip(support,parts,signs):r[loc]=v*sgn
                    found[tuple(r)]+=1
    actual={r for r in product(range(-h,h+1),repeat=m) if sum(abs(x) for x in r)==h}
    check(len(found)==count_sphere(m,h),"exact l1-sphere count")
    check(set(found)==actual,"support/composition/sign representation complete")
    check(all(v==1 for v in found.values()),"unique encoding per sphere vector")
    return list(found)

def dot(a,b): return sum(x*y for x,y in zip(a,b))
def centered(z,q): return min(z%q,(-z)%q)
def decode(y,q,g,base):
    return min(range(base),key=lambda a:centered(y-g*a,q))

def encrypt(A,b,a,q,g,r):
    n=len(A[0])
    c=[sum(A[i][j]*r[i] for i in range(len(r)))%q for j in range(n)]
    d=(dot(b,r)+g*a)%q
    return c,d

def release(c,d,s,q,g,base):
    return decode((d-dot(s,c))%q,q,g,base)

def digits(value,base,count):
    out=[]
    for _ in range(count):
        value,di=divmod(value,base)
        out.append(di)
    check(value==0,'radix fits seed bits')
    return out

# Finite EXACT enumeration validates the construction of the sphere distribution.
r_small=small_enumeration(4,3)
r_collider=small_enumeration(3,2)
# Whole ciphertext-vector 2-universality check for one output coordinate.
qtoy=7; mtoy=3;htoy=2; N=len(r_collider)
sum_coll=0
for H in product(range(qtoy),repeat=mtoy):
    bins=Counter(dot(H,r)%qtoy for r in r_collider)
    sum_coll+=sum(v*v for v in bins.values())
check(sum_coll==qtoy**mtoy*N+qtoy**(mtoy-1)*N*(N-1),'exact whole-vector two-universal collision identity')

# Exhaustive toy decoding with arbitrary valid witnesses and every sphere r.
qt=101;mt=3;nt=2;ht=2;gt=2*ht+1;bt=qt//gt
A=[[0,1],[0,4],[0,7]]
e=[-1,0,1]
s0=[2,3];s1=[8,3]
b=[(dot(row,s0)+err)%qt for row,err in zip(A,e)]
for s in [s0,s1]:
    check(all((dot(row,s)+ei-bi)%qt==0 for row,ei,bi in zip(A,e,b)),'two distinct original valid witnesses')
for r in r_collider:
    check(sum(abs(v) for v in r)==ht,'toy l1 radius')
    check(abs(dot(e,r))<=ht,'worst-case error bound')
    for a in range(bt):
        c,d=encrypt(A,b,a,qt,gt,r)
        for s in [s0,s1]:check(release(c,d,s,qt,gt,bt)==a,'all-witness same-digit decoding')

# Exact integer entropy comparison - no floating precision in the security comparison.
q=65537;n=128;m=1600;h=696;kappa=256;g=2*h+1;base=q//g
weights=count_weights(m,h);N=sum(weights)
check(N==count_sphere(m,h),'reconstruct exact sphere cardinality')
check(N>3**m,'statistical extractor entropy strictly GREATER than predecessor ternary r')
check(2*h<q,'r!=rprime gives nonzero modular difference')
check(g==1393 and base==47,'expected source parameters')
# Keep exactly 47 columns, integer exact comparison base**46 < 2**256 <= base**47.
check(base**46 < 2**kappa<=base**47,'minimal radix column count')
ell=47;oldell=60
check(ell<oldell,'strict ciphertext field saving')
# Exact comparison of squared statistical bounds including ell columns.
check(ell*ell*(3**m)<oldell*oldell*N,'complete-capsule bound no weaker')

# Deterministic full-source two-original-witness trials at the actual proposed dimensions.
# This A has one zero column deliberately, for correctness testing only (not LWE hardness).
A=[[rng.randrange(q) for _ in range(n-1)]+[0] for _ in range(m)]
s0=[rng.randrange(q) for _ in range(n)]
s1=s0[:];s1[-1]=(s1[-1]+1)%q
e=[rng.choice([-1,0,1]) for _ in range(m)]
b=[(dot(row,s0)+ei)%q for row,ei in zip(A,e)]
for j in range(4):
    K=rng.getrandbits(kappa);U=rng.getrandbits(kappa);Z=rng.getrandbits(kappa)
    D=U^Z;V=K^U
    rd=digits(Z,base,ell)
    recovered={id(s):[] for s in (s0,s1)}
    for a in rd:
        r=sample_r(m,h,weights,N,rng)
        check(sum(abs(v) for v in r)==h,'large sphere radius')
        check(all(abs(v)<q//2 for v in r),'unique field representation')
        check(abs(dot(e,r))<=h,'large all-witness noise bound')
        c,d=encrypt(A,b,a,q,g,r)
        for s in (s0,s1):
            dec=release(c,d,s,q,g,base)
            check(dec==a,'all-witness same-digit large release')
            recovered[id(s)].append(dec)
    for s in (s0,s1):
        zrec=sum(di*base**i for i,di in enumerate(recovered[id(s)]))
        krec=V^D^zrec
        check(krec==K,'two valid ORIGINAL witnesses recover same 256-bit K')
        check(sha256(krec.to_bytes(32,'big')).digest()==sha256(K.to_bytes(32,'big')).digest(),'mock checking digest identical')

# Finite-uniform sampling check for k distribution; no probabilistic security conclusion.
for _ in range(200):
    r=sample_r(m,h,weights,N,rng)
    check(sum(abs(v) for v in r)==h,'random sphere samples valid')

# Certified arithmetic / resource estimates (log2 values are reporting-only).
log2N=log2(N); log2q=log2(q)
log2delta=-1+.5*((n+1)*log2q-log2N)
log2full=log2delta+log2(ell)
log2orig=-1+.5*((n+1)*log2q-m*log2(3))+log2(oldell)
expected_nonzero=sum(k*w for k,w in enumerate(weights) if k)/N
report={
    'record':'l1-sphere-lwe-source-20261028-turn11','status':'PASS','checks':checks,
    'test_rng':'Python Random fixed seed; Build requires unbiased CSPRNG',
    'security':'finite algebra and exact collision/count comparison only, not QPT evaluation',
    'parameters':{'q':q,'m':m,'n':n,'h':h,'g':g,'base':base,'seed_bits':kappa,'columns':ell},
    'exact_sphere_more_than_ternary':N>3**m,
    'source_entropy_bits_approx':round(log2N,6),
    'original_source_entropy_bits_approx':round(m*log2(3),6),
    'log2_complete_stat_bound_new':round(log2full,6),
    'log2_complete_stat_bound_original':round(log2orig,6),
    'expected_nonzero_r_coordinates':round(expected_nonzero,6),
    'two_original_256bit_full_key_trials':4,
    'finite_toy_collision_matrices':qtoy**mtoy,
    'finite_toy_sphere_size':N if m<8 else len(r_collider),
    'ciphertext_field_elements_new':ell*(n+1),
    'ciphertext_field_elements_original':oldell*(n+1),
    'packed_17bit_new_bytes':ceil(ell*(n+1)*17/8),
    'packed_17bit_original_bytes':ceil(oldell*(n+1)*17/8)
}
print(json.dumps(report,sort_keys=True,indent=2))
