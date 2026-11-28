#!/usr/bin/env python3
"""Small falsifier for PUBLIC global noncommutative masked-word capsule.
Only toy algebra; NOT SHA/AuxPoW admission, FE, bridge, or a positive security test.
"""
import hashlib, json, random
P=101
I=((1,0),(0,1))
A=((1,1),(0,1))
B=((1,0),(1,1))
def mul(a,b):
    return tuple(tuple(sum(a[i][k]*b[k][j] for k in range(2))%P for j in range(2)) for i in range(2))
def inv(a):
    a0,b=a[0]; c,d=a[1]; determinant=(a0*d-b*c)%P
    assert determinant
    z=pow(determinant,-1,P)
    return (((d*z)%P,(-b*z)%P),((-c*z)%P,(a0*z)%P))
def prod(*args):
    o=I
    for a in args: o=mul(o,a)
    return o
def rand_mat(rng):
    while True:
        a=tuple(tuple(rng.randrange(P) for _ in range(2)) for _ in range(2))
        if (a[0][0]*a[1][1]-a[0][1]*a[1][0])%P: return a
def enc(m):return bytes(x for row in m for x in row)
def digest(m):return hashlib.sha256(b'SAI115-mask-v1'+enc(m)).digest()
def xor(a,b):return bytes(x^y for x,y in zip(a,b))
assert mul(A,B)!=mul(B,A)
steps=[{0:A,1:I},{0:B,1:B},{0:inv(B),1:mul(inv(A),inv(B))}]
assert prod(steps[0][0],steps[1][0],steps[2][0])!=I
assert prod(steps[0][1],steps[1][1],steps[2][1])!=I
assert prod(steps[0][1],steps[1][0],steps[2][0])==I  # invalid mixed x=(1,0)
rng=random.Random(20261122)
records=[]
for trial in range(12):
    R=[rand_mat(rng) for _ in range(4)]
    X=[{b:prod(R[j],steps[j][b],inv(R[j+1])) for b in [0,1]} for j in range(3)]
    K=digest(prod(R[0],inv(R[3])))
    S=hashlib.sha256(f'SAI115-TEST-SECRET-{trial}'.encode()).digest()
    D=xor(S,K)
    # Prescribed Open can evaluate only a consistent x, and never obtains K in this FALSE instance.
    consistent=[prod(X[0][x],X[1][x],X[2][x]) for x in [0,1]]
    assert all(digest(m)!=K for m in consistent)
    # Full-public adversary mixes the same variable's local occurrences.
    target_from_inconsistent_public_word=prod(X[0][1],X[1][0],X[2][0])
    K_observed=digest(target_from_inconsistent_public_word)
    S_observed=xor(D,K_observed)
    assert target_from_inconsistent_public_word==prod(R[0],inv(R[3]))
    assert S_observed==S
    records.append({'trial':trial,'consistent_false':True,'public_inconsistent_recovers_secret':S_observed==S})
print(json.dumps({'scope':'toy finite-field global masked-word failure; no ORIGINAL witness/FE',
 'field':101,'dimension':2,'noncommuting_AB':mul(A,B)!=mul(B,A),
 'actual_source_tests':False,'original_release_construction':False,
 'trials':records},sort_keys=True,indent=2))
