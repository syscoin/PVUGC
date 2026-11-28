#!/usr/bin/env python3
"""Run 706: amplified spectral SOURCE-binding from uniform residual masks.
Research arithmetic tests, NOT a WKEM hiding/extraction proof.
"""
import itertools, json, math
from fractions import Fraction
import numpy as np

q=101
rng=np.random.default_rng(706)
assertions=0
def require(x,message):
    global assertions
    assert bool(x), message
    assertions+=1

def rank_mod(a,prime):
    a=[[int(c)%prime for c in row] for row in np.asarray(a).tolist()]
    rows=len(a);cols=len(a[0]);r=0
    for j in range(cols):
        pivot=next((i for i in range(r,rows) if a[i][j]),None)
        if pivot is None:continue
        a[r],a[pivot]=a[pivot],a[r]
        inv=pow(a[r][j],-1,prime)
        a[r]=[(x*inv)%prime for x in a[r]]
        for k in range(rows):
            if k!=r and a[k][j]:
                t=a[k][j]
                a[k]=[(v-t*u)%prime for v,u in zip(a[k],a[r])]
        r+=1
        if r==rows:break
    return r

def src(u,v):
    # Clauses (u OR v) and (NOT u OR v)
    h11=u+v-u*v; h12=h11+v-h11*v
    h21=(1-u)+v-(1-u)*v; h22=h21+v-h21*v
    return (u,v,h11,h12,h21,h22)

def gates(z):
    """Complete typed SOURCE gates on z=(1,u,v,h11,h12,h21,h22)."""
    o,u,v,h11,h12,h21,h22=z
    clauses=[(u,v,v,h11,h12),(o-u,v,v,h21,h22)]
    g=[(u,u,u,o),(v,v,v,o)]
    for l1,l2,l3,h1,h2 in clauses:
        g.extend([(l1,l2,l1+l2-h1,o),(h1,l3,h1+l3-h2,o),(h2-o,o,0,o)])
    return g

m=8
p=7 # z0 fixed to 1, six independent SOURCE coordinates
s=3 # s^2=9 > p-1=6, for uniform full matrices
N=2*m+s
K=27
L=[rng.integers(0,q,size=(N,4),dtype=np.int64) for _ in range(m)]
R=[rng.integers(0,q,size=(4,N),dtype=np.int64) for _ in range(m)]
X=[rng.integers(0,q,size=p,dtype=np.int64) for _ in range(m)]
Q=[rng.integers(0,q,size=(N,N),dtype=np.int64) for _ in range(m)]
I=np.eye(N,dtype=np.int64)

def private_eval(y):
    z=(1,)+tuple(int(x) for x in y)
    mat=K*I.copy()
    gg=gates(z)
    for i,(a,b,c,d) in enumerate(gg):
        x=int(sum(int(v)*int(w) for v,w in zip(X[i],z))%q)
        G=np.array([[a,c,-x,0],[d,b,0,x],[0,0,b,c],[0,0,d,a]],dtype=np.int64)%q
        residual=(a*b-c*d)%q
        mat=(mat+L[i]@G@R[i]+residual*Q[i])%q
    return mat

# A degree-two coefficient array of the FULL PUBLIC OPERATOR, reconstructed
# by interpolation from private setup (no factors/mask coin output).
n=p-1
Z=np.zeros(n,dtype=np.int64)
e=[np.eye(n,dtype=np.int64)[i] for i in range(n)]
const=private_eval(Z)
lin=[];sq=[]
for i in range(n):
    d1=(private_eval(e[i])-const)%q
    d2=(private_eval(2*e[i])-const)%q
    aii=((d2-2*d1)*pow(2,-1,q))%q
    ai=(d1-aii)%q
    lin.append(ai);sq.append(aii)
cross={}
for i in range(n):
    for j in range(i+1,n):
        cross[i,j]=(private_eval(e[i]+e[j])-const-lin[i]-lin[j]-sq[i]-sq[j])%q

def public_eval(y):
    y=[int(v)%q for v in y]
    out=const.copy()
    for i in range(n):out=(out+y[i]*lin[i]+(y[i]**2)*sq[i])%q
    for (i,j),A in cross.items():out=(out+y[i]*y[j]*A)%q
    return out

true=[]
for u,v in itertools.product((0,1),repeat=2):
    y=src(u,v)
    z=(1,)+y
    rs=[(a*b-c*d)%q for (a,b,c,d) in gates(z)]
    if any(rs):continue
    true.append(y)
require(len(true)==2,'two satisfying originals')
for y in true:
    require(np.array_equal(public_eval(y),private_eval(y)), 'honest public/private exact equality')
    require(rank_mod((public_eval(y)-K*I)%q,q)<=N-s, 'valid source has >=s eigen-nullity')
    require(all((a*b-c*d)%q==0 for a,b,c,d in gates((1,)+y)), 'valid all gates')

# Invalid inputs: random full-field pseudowitnesses, incorrect aux, and
# INVALID Boolean originals with canonically completed aux.
invalid=[]
for u,v in itertools.product((0,1),repeat=2):
    y=src(u,v)
    if y not in true: invalid.append(y)
for i in range(6):
    y=list(true[0]);y[i]=(y[i]+1)%q;invalid.append(tuple(y))
for _ in range(50):
    y=tuple(int(v) for v in rng.integers(0,q,size=n)); invalid.append(y)
invalid=[y for y in invalid if any((a*b-c*d)%q for a,b,c,d in gates((1,)+y))]
for y in invalid:
    require(any((a*b-c*d)%q for a,b,c,d in gates((1,)+y)), 'invalid SOURCE has nonzero residual')
    require(np.array_equal(public_eval(y),private_eval(y)), 'public complete coefficients interpolate invalid too')
    require(rank_mod((public_eval(y)-K*I)%q,q)>N-s, 'sample has no spurious accepted invalid SOURCE')
# Independent ANY-scalar soundness spot check from the same public coefficient array.
for y in invalid[:12]:
    CY=public_eval(y)
    for alpha in range(q):
        require(rank_mod((CY-alpha*I)%q,q)>N-s, 'no invalid SOURCE/any scalar has rank deficit s')
for _ in range(30):
    y=tuple(int(v) for v in rng.integers(0,q,size=n))
    require(np.array_equal(public_eval(y),private_eval(y)), 'all-source degree-two public polynomial')

# Exact finite probability bound: count s-dimensional subspaces of F_q^N
# times q^(-N*s), followed by union over all q^(p-1) source inputs.
def gaussian_binom(N,s,q):
    out=1
    for i in range(s):
        num=q**(N-i)-1;den=q**(s-i)-1
        # Fraction avoids intermediate divisibility assumptions.
        out=out*Fraction(num,den)
    require(out.denominator==1,'Gaussian binomial is integer')
    return out.numerator
num=gaussian_binom(N,s,q)
fixed=Fraction(num,q**(N*s))
global_bound=min(Fraction(1),q**n*fixed)
any_scalar_bound=min(Fraction(1),q**(n+1)*fixed)
require(any_scalar_bound < Fraction(1,10**3),'arbitrary field candidate bound nontrivial')
require(global_bound < Fraction(1,10**5),'global post-setup bound nontrivial')

# Independent census of uniform N=3, q=3 matrices with deficiency >=2;
# confirms exact event is below Gaussian-subspace union bound.
smallq=3;dim=3;kern=2
count=0
for entries in itertools.product(range(smallq),repeat=dim*dim):
    A=np.array(entries,dtype=np.int64).reshape(dim,dim)
    if rank_mod(A,smallq)<=dim-kern:count+=1
census=Fraction(count,smallq**(dim*dim))
upper=Fraction(gaussian_binom(dim,kern,smallq),smallq**(dim*kern))
require(census<=upper,'Gaussian kernel-union bound')
require(count==339,'rank<=1 exact q=3 N=3 count')

print(json.dumps({
    'run':706,'checks':assertions,'field_q':q,'source_coordinates_normalized':n,
    'typed_gates':m,'matrix_dimension':N,'amplified_nullity':s,
    'valid_originals':len(true),'invalid_sources_tested':len(invalid),
    'full_public_coefficient_matrices':1+2*n+n*(n-1)//2,
    'pointwise_invalid_probability_union_upper':float(fixed),
    'all_invalid_adaptive_bad_setup_union_upper':float(global_bound),
    'any_scalar_adaptive_bad_setup_union_upper':float(any_scalar_bound),
    'small_uniform_rank_census':{'q':3,'N':3,'s':2,'count_rank_at_most_1':count,
                                  'total':3**9,'probability':float(census),
                                  'gaussian_union_bound':float(upper)},
    'qpt_conclusion':'information-theoretic adaptive soundness of supplied (alpha,z) spectral rank predicate, ANY alpha in field; not key-only extraction',
    'hard_true_key_only_extraction_proved':False,
    'false_instance_hiding_proved_by_this_checker':False
},sort_keys=True))
