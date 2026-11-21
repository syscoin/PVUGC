#!/usr/bin/env python3
"""Bounded finite algebraic checks of an adaptive invertible-left LWE action.
No simulation here is evidence of QPT hardness or ORIGINAL-W release.
"""
import collections, hashlib, itertools, json, random
Q = 7
assertions = 0

def check(cond, msg=''):
    global assertions
    assertions += 1
    if not cond: raise AssertionError(f'{assertions}: {msg}')

def mm(T, H, q):
    return [tuple(sum(T[i][k]*H[k][j] for k in range(len(H)))%q for j in range(len(H[0]))) for i in range(len(T))]

def row_dot(H, r, q):
    return tuple(sum(H[i][j]*r[i] for i in range(len(H)))%q for j in range(len(H[0])))

def add(y,e,q):
    return tuple((a+b)%q for a,b in zip(y,e))

def distribution(H,q):
    d=collections.Counter()
    for r in itertools.product(range(q), repeat=len(H)):
        hr=row_dot(H,r,q)
        for e in itertools.product([-1,0,1], repeat=len(H[0])):
            d[add(hr,e,q)]+=1
    return d

def adaptive_T(H, q):
    # T depends on every public field element of H, including target columns.
    h=hashlib.sha256(bytes(sum([list(row) for row in H],[]))).digest()
    a,b,c = h[0]%q, h[1]%q, h[2]%q
    # T = diag(1+c,1+b) * shear(a), with nonzero diagonal elements.
    u=1+c;v=1+b
    if u%q==0: u=1
    if v%q==0: v=1
    return ((u%q,u*a%q),(0,v%q))

rng=random.Random(202610300143)
result={'run':'adaptive_left_action_20261030','status':'restricted_joint_law_only',
        'q':Q,'n':2,'d':3,'chi':[-1,0,1],'samples':0,'key_releases':0}

# Test EXACT output histograms for distinct uniform secrets r and noise eta.
# T is allowed to depend on all public H entries, but not on either hidden r or eta.
for t in range(72):
    H = tuple(tuple(rng.randrange(Q) for _ in range(3)) for _ in range(2))
    T=adaptive_T(H,Q)
    check((T[0][0]*T[1][1]-T[0][1]*T[1][0])%Q != 0)
    M=mm(T,H,Q)
    direct=distribution(M,Q)
    simulated=distribution(H,Q)
    check(direct==simulated,f'adaptive left action exact distribution {t}')
    check(sum(direct.values())==Q**2*3**3)
    # Complete y-vector distribution includes all correlated output coordinates,
    # not just coordinatewise marginals. Test the public shift to true key digits.
    shift=(0,0,3*(t%8))
    direct_shift=collections.Counter({add(y,shift,Q):count for y,count in direct.items()})
    simulated_shift=collections.Counter({add(y,shift,Q):count for y,count in simulated.items()})
    check(direct_shift==simulated_shift)
    result['samples']+=1

# Explicit source-opening invariance, and SAME capability across two distinct z,
# two different related capsules, and nontrivial invertible left action.
P=97
Acols=((5,11),(9,17),(8,14),(6,14)) # A0+A1 == A2+A3 mod P
U=(14,28)
H=tuple(tuple(Acols[j][i] for j in range(4))+(U[i],) for i in range(2))
T=((3,5),(0,7))
M=mm(T,H,P)
z1=(1,1,0,0);z2=(0,0,1,1)
for z in [z1,z2]:
    check(tuple(sum(H[i][j]*z[j] for j in range(4))%P for i in range(2)) == U)
    check(tuple(sum(M[i][j]*z[j] for j in range(4))%P for i in range(2)) == tuple(M[i][-1] for i in range(2)))

def circ_nearest(v, q, g, count):
    centers=[(g*i)%q for i in range(count)]
    return min(range(count), key=lambda k:min((v-centers[k])%q,(centers[k]-v)%q))

for j in range(2):
    r=(rng.randrange(P),rng.randrange(P))
    e=tuple(rng.choice([-1,0,1]) for _ in range(5))
    secret_digit=(3+4*j)%8
    y=add(row_dot(M,r,P),e,P)
    y=list(y); y[-1]=(y[-1]+12*secret_digit)%P
    for z in [z1,z2]:
        residue=(y[-1]-sum(z[k]*y[k] for k in range(4)))%P
        recovered=circ_nearest(residue,P,12,8)
        check(recovered==secret_digit)
        result['key_releases']+=1
    # With a SOURCE opening, the same payload is usable on original H too.
    r_orig=((T[0][0]*r[0]+T[1][0]*r[1])%P,(T[0][1]*r[0]+T[1][1]*r[1])%P)
    check(row_dot(H,r_orig,P)==row_dot(M,r,P))

# Negative control: non-invertible T gives a trivial public SOURCE opening.
Tbad=((0,0),(0,0))
Mbad=mm(Tbad,H,P)
check(all(x==0 for row in Mbad for x in row))
check(all(sum(Mbad[i][k]*z1[k] for k in range(4))%P==Mbad[i][-1] for i in range(2)))

result['assertions']=assertions
result['complete_vector_distribution_count_per_instance']=Q**2*3**3
print(json.dumps(result,sort_keys=True,indent=2))
