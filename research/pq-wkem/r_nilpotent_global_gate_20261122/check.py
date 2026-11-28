#!/usr/bin/env python3
"""R-global nilpotent gate algebra; synthetic prime-field only. No cryptographic FE."""
import json, hashlib, random
Q=101
rng=random.Random(20261122)
def eye(n):return [[int(i==j) for j in range(n)] for i in range(n)]
def mul(A,B):
    n=len(A); m=len(B[0]); mid=len(B)
    return [[sum(A[i][k]*B[k][j] for k in range(mid))%Q for j in range(m)] for i in range(n)]
def scale(A,k):return [[(k*x)%Q for x in row] for row in A]
def inv(A):
    n=len(A); M=[[(x%Q) for x in row]+eye(n)[i] for i,row in enumerate(A)]
    for col in range(n):
        pivot=next((i for i in range(col,n) if M[i][col]),None)
        if pivot is None:raise ValueError('singular')
        M[col],M[pivot]=M[pivot],M[col]
        p=pow(M[col][col],-1,Q); M[col]=[v*p%Q for v in M[col]]
        for i in range(n):
            if i==col:continue
            t=M[i][col]
            M[i]=[(a-t*b)%Q for a,b in zip(M[i],M[col])]
    return [row[n:] for row in M]
def random_gl(n):
    while True:
        M=[[rng.randrange(Q) for _ in range(n)] for __ in range(n)]
        try:return M,inv(M)
        except ValueError:pass

def calculate(allowed):
    d=len(allowed); n=2*d
    J=[[0]*n for _ in range(n)]
    for w,ok in enumerate(allowed):J[w][d+w]=int(ok)
    R,Ri=random_gl(n)
    a,b=17,59
    A=mul(mul(Ri,scale(J,a)),R)
    D=eye(n); factor=b*pow(a,-1,Q)%Q
    for u in range(d):D[u][u]=factor
    Rp=mul(D,R); Rpi=mul(Ri,inv(D))
    Aprime=mul(mul(Rpi,scale(J,b)),Rp)
    assert A==Aprime
    assert mul(A,A)==[[0]*n for _ in range(n)]
    hits=[]; cross=[]
    for w in range(d):
        ell=mul([[int(i==w) for i in range(n)]],R)
        right=mul(Ri,[[int(i==d+w)] for i in range(n)])
        val=mul(mul(ell,A),right)[0][0]
        assert val == a*allowed[w]%Q
        hits.append(val)
    for u in range(d):
        for v in range(d):
            left=mul([[int(i==u) for i in range(n)]],R)
            right=mul(Ri,[[int(i==d+v)] for i in range(n)])
            z=mul(mul(left,A),right)[0][0]
            assert z == (a*allowed[u] if u==v else 0)%Q
            if u!=v:cross.append(z)
    # Even when the complete A transcript is exactly the same across a,b,
    # the witness-specific left-frame vectors are different across coupled tapes.
    u=next((i for i,x in enumerate(allowed) if x),0)
    left=mul([[int(i==u) for i in range(n)]],R)
    left_prime=mul([[int(i==u) for i in range(n)]],Rp)
    right=mul(Ri,[[int(i==d+u)] for i in range(n)])
    right_prime=mul(Rpi,[[int(i==d+u)] for i in range(n)])
    assert right==right_prime
    assert left_prime==scale(left,factor)
    assert mul(mul(left_prime,Aprime),right_prime)[0][0]==b*allowed[u]%Q
    return {'d':d,'valid_count':sum(allowed),'A_zero':not any(any(row) for row in A),
            'nilpotent_A2_zero':True,'conjugate_full_public_A_same_for_K_17_and_59':A==Aprime,
            'honest_diagonal_openings':hits,'cross_witness_outputs_all_zero':all(z==0 for z in cross),
            'witness_boundary_hint_changes_under_coupling':left!=left_prime,
            'same_public_A_with_different_K_requires_correlated_boundary_hints':True}

def main():
    cases=[calculate([0]*4),calculate([0,1,0,1]),calculate([1,0,1,0])]
    assert cases[0]['A_zero']
    assert cases[1]['honest_diagonal_openings']==[0,17,0,17]
    result={'field':Q,'construction':'nilpotent_global_gate','meaning':'source-independent synthetic algebra, NOT FE or source evidence','cases':cases}
    print(json.dumps(result,sort_keys=True,indent=2))
if __name__=='__main__':main()
