#!/usr/bin/env python3
import json, random, math
from itertools import product

Q = 101
PHASE = 25
SEED = 480048

def center(x):
    x %= Q
    return x if x <= Q//2 else x-Q

def mat_vec(A, x):
    return [sum(a*b for a,b in zip(row,x)) % Q for row in A]

def mat_t_vec(A, s):
    return [sum(A[i][j]*s[i] for i in range(len(A))) % Q for j in range(len(A[0]))]

def dot(a,b):
    return sum(x*y for x,y in zip(a,b)) % Q

def mat_mul(L,A):
    return [[sum(L[i][k]*A[k][j] for k in range(len(A))) % Q
             for j in range(len(A[0]))]
            for i in range(len(L))]

def rank_mod(M):
    if not M: return 0
    A=[row[:] for row in M]
    nr,nc=len(A),len(A[0])
    r=0
    for c in range(nc):
        piv=next((i for i in range(r,nr) if A[i][c] % Q), None)
        if piv is None:
            continue
        A[r],A[piv]=A[piv],A[r]
        inv=pow(A[r][c] % Q,-1,Q)
        A[r]=[(v*inv)%Q for v in A[r]]
        for i in range(nr):
            if i != r and A[i][c] % Q:
                f=A[i][c] % Q
                A[i]=[(A[i][j]-f*A[r][j])%Q for j in range(nc)]
        r+=1
        if r==nr: break
    return r

def random_invertible(rng,n):
    while True:
        M=[[rng.randrange(Q) for _ in range(n)] for __ in range(n)]
        if rank_mod(M)==n:
            return M

def mat_inv(M):
    n=len(M)
    A=[[(M[i][j]%Q) for j in range(n)] +
       [1 if i==j else 0 for j in range(n)] for i in range(n)]
    for c in range(n):
        piv=next(i for i in range(c,n) if A[i][c] % Q)
        A[c],A[piv]=A[piv],A[c]
        inv=pow(A[c][c] % Q,-1,Q)
        A[c]=[(v*inv)%Q for v in A[c]]
        for i in range(n):
            if i!=c and A[i][c] % Q:
                f=A[i][c] % Q
                A[i]=[(A[i][j]-f*A[c][j])%Q for j in range(2*n)]
    return [row[n:] for row in A]

# Coordinates: (m0,mx,my,mxx,mxy,myy).
X_PSEUDO = [1,-1,-1,-1,0,-1]
W10 = [1,1,0,1,0,0]
W01 = [1,0,1,0,0,1]

def relation_false(weights=(1,1,1)):
    rx,ry,rg=weights
    # Boolean rows mxx-mx=0, myy-my=0, false equation x+y+2=0 mod 101.
    return [
        [1,0,0,0,0,0],
        [0,-rx,0,rx,0,0],
        [0,0,-ry,0,0,ry],
        [(2*rg)%Q,rg,rg,0,0,0],
    ], [1,0,0,0]

def relation_true(weights=(1,1,1)):
    rx,ry,rg=weights
    # True comparison equation x+y-1=0.
    return [
        [1,0,0,0,0,0],
        [0,-rx,0,rx,0,0],
        [0,0,-ry,0,0,ry],
        [(-rg)%Q,rg,rg,0,0,0],
    ], [1,0,0,0]

def circular_distance(a,b):
    d=(a-b)%Q
    return min(d,Q-d)

def decode_bit(r):
    return 0 if circular_distance(r,0) < circular_distance(r,PHASE) else 1

def capsule(A,u,x,K,s,e,e0):
    a=[(v+err)%Q for v,err in zip(mat_t_vec(A,s),e)]
    b=(dot(u,s)+e0+PHASE*K)%Q
    res=(b-dot([xx%Q for xx in x],a))%Q
    return a,b,res,decode_bit(res)

def nonlinear_feature(z,L=4,true_eq=True):
    x,y=z
    g=x+y-1 if true_eq else x+y+2
    return [1,x,y,L*x*(x-1),L*y*(y-1),L*g]

def norm2(v):
    return sum(x*x for x in v)

def residuals_pseudomoment(X):
    m0,mx,my,mxx,mxy,myy=X
    return [mxx-mx, myy-my, mx+my+2*m0]

def monomial_count_zero(residuals,max_degree):
    # Number of nonconstant monomials in len(residuals) variables up to degree max_degree.
    # Every one evaluates to zero at the all-zero residual vector.
    n=len(residuals)
    count=0
    for total in range(1,max_degree+1):
        # weak compositions via recursion
        def rec(pos,left):
            nonlocal count
            if pos==n-1:
                exps=prefix+[left]
                val=1
                for r,e in zip(residuals,exps):
                    val*=r**e
                assert val==0
                count+=1
                return
            for e in range(left+1):
                prefix.append(e)
                rec(pos+1,left-e)
                prefix.pop()
        prefix=[]
        rec(0,total)
    return count

def main():
    rng=random.Random(SEED)
    report={"seed":SEED,"q":Q,"phase":PHASE}

    # 1) Nonlinear actual-trace metric gap.
    rows=[]
    for L in [2,3,4,8,16]:
        vals=[]
        for z in product(range(-4,5), repeat=2):
            valid=z in [(1,0),(0,1)]
            vals.append((z,valid,norm2(nonlinear_feature(z,L,True))))
        max_valid=max(v for _,valid,v in vals if valid)
        min_invalid=min(v for _,valid,v in vals if not valid)
        assert max_valid==2
        assert min_invalid >= L*L
        rows.append({"L":L,"max_valid_norm2":max_valid,
                     "min_invalid_norm2_in_box":min_invalid,
                     "ratio":min_invalid/max_valid})
    report["nonlinear_metric_gap"]=rows

    # 100 random integer verifier systems; exhaustive local box confirms the simple theorem.
    gap_checks=0
    for _ in range(100):
        n=3
        w=[rng.randrange(2) for _ in range(n)]
        m=3
        coeffs=[]
        for __ in range(m):
            a=[rng.randint(-3,3) for _ in range(n)]
            c=-sum(ai*wi for ai,wi in zip(a,w))
            coeffs.append((a,c))
        L=8
        for z in product(range(-2,4), repeat=n):
            bool_res=[zi*(zi-1) for zi in z]
            gs=[sum(ai*zi for ai,zi in zip(a,z))+c for a,c in coeffs]
            valid=all(zi in (0,1) for zi in z) and all(g==0 for g in gs)
            feat=[1,*z,*[L*r for r in bool_res],*[L*g for g in gs]]
            if not valid:
                assert any(bool_res) or any(gs)
                # Nonzero integer verifier residual has magnitude >=1; nonboolean residual >=2.
                assert norm2(feat) >= L*L
            gap_checks += 1
    report["random_integer_gap_checks"]=gap_checks

    # 2) Universal zero pseudomoment for the false mod-101 relation.
    pseudo=[v%Q for v in X_PSEUDO]
    weighted_preimage_checks=0
    for _ in range(2000):
        weights=[rng.randrange(1,Q) for _ in range(3)]
        A,u=relation_false(weights)
        assert mat_vec(A,pseudo)==u
        weighted_preimage_checks+=1
    report["weighted_pseudopreimage_checks"]=weighted_preimage_checks
    report["pseudo_centered"]=X_PSEUDO
    report["pseudo_linearized_residuals"]=residuals_pseudomoment(X_PSEUDO)

    # Every residual-only polynomial/tensor feature with zero constant term vanishes.
    residuals=residuals_pseudomoment(X_PSEUDO)
    poly_zero_count=monomial_count_zero(residuals,6)
    report["residual_monomials_zero_through_degree_6"]=poly_zero_count

    # 3) Arbitrary secret left row mixing/reweighting does not remove the pseudopreimage.
    mix_checks=0
    hidden_capsule_checks=0
    max_abs_noise=0
    for _ in range(1000):
        weights=[rng.randrange(1,Q) for _ in range(3)]
        A,u=relation_false(weights)
        L=random_invertible(rng,4)
        Ap=mat_mul(L,A)
        up=mat_vec(L,u)
        assert mat_vec(Ap,pseudo)==up
        mix_checks+=1

        K=rng.randrange(2)
        s=[rng.randrange(Q) for _ in range(4)]
        e=[rng.choice([-1,0,1]) for _ in range(6)]
        e0=rng.choice([-1,0,1])
        a,b,res,dec=capsule(Ap,up,X_PSEUDO,K,s,e,e0)
        # The attacker needs only public (a,b) and X_PSEUDO, not L, Ap, or the erased setup secrets.
        assert dec==K
        hidden_capsule_checks+=1
        noise=center((res-PHASE*K)%Q)
        max_abs_noise=max(max_abs_noise,abs(noise))
    report["secret_invertible_left_mix_checks"]=mix_checks
    report["hidden_relation_false_capsule_recoveries"]=hidden_capsule_checks
    report["max_abs_false_residual_noise"]=max_abs_noise

    # Rectangular left transformations (repetition/compression) also preserve the pseudozero.
    rect_checks=0
    rect_caps=0
    for _ in range(500):
        A,u=relation_false([rng.randrange(1,Q) for _ in range(3)])
        r=rng.randint(1,8)
        L=[[rng.randrange(Q) for _ in range(4)] for __ in range(r)]
        Ap=mat_mul(L,A)
        up=mat_vec(L,u)
        assert mat_vec(Ap,pseudo)==up
        rect_checks+=1
        K=rng.randrange(2)
        s=[rng.randrange(Q) for _ in range(r)]
        e=[rng.choice([-1,0,1]) for _ in range(6)]
        e0=rng.choice([-1,0,1])
        _,_,_,dec=capsule(Ap,up,X_PSEUDO,K,s,e,e0)
        assert dec==K
        rect_caps+=1
    report["rectangular_left_transform_checks"]=rect_checks
    report["rectangular_transform_false_capsule_recoveries"]=rect_caps

    # Five independent N-of-N operators applying secret invertible left mixes.
    non_checks=0
    non_caps=0
    for _ in range(300):
        A,u=relation_false([rng.randrange(1,Q) for _ in range(3)])
        for __ in range(5):
            L=random_invertible(rng,4)
            A=mat_mul(L,A)
            u=mat_vec(L,u)
        assert mat_vec(A,pseudo)==u
        non_checks+=1
        K=rng.randrange(2)
        s=[rng.randrange(Q) for _ in range(4)]
        e=[rng.choice([-1,0,1]) for _ in range(6)]
        e0=rng.choice([-1,0,1])
        _,_,_,dec=capsule(A,u,X_PSEUDO,K,s,e,e0)
        assert dec==K
        non_caps+=1
    report["five_operator_left_mix_checks"]=non_checks
    report["five_operator_false_capsule_recoveries"]=non_caps

    # 4) Exhaustive bounded-error correctness: false pseudo and true witnesses.
    exhaustive={}
    for label,relation,xs in [
        ("false_pseudo",relation_false,[X_PSEUDO]),
        ("true_witnesses",relation_true,[W10,W01]),
    ]:
        A,u=relation()
        s=[7,11,13,17]
        ok=total=0
        for x in xs:
            for K in [0,1]:
                for vals in product([-1,0,1], repeat=7):
                    e=list(vals[:6]); e0=vals[6]
                    _,_,_,dec=capsule(A,u,x,K,s,e,e0)
                    total+=1
                    ok += int(dec==K)
        assert ok==total
        exhaustive[label]={"success":ok,"total":total}
    report["exhaustive_bounded_error_decapsulation"]=exhaustive

    # 5) Secret right/column reweighting boundary.
    # If the helper exposing X -> D X is public, the pseudo transforms too and noiselessly decapsulates.
    # If D is erased and no helper exists, this test deliberately makes no completeness claim.
    col_checks=0
    for _ in range(300):
        A,u=relation_false([rng.randrange(1,Q) for _ in range(3)])
        D=random_invertible(rng,6)
        Dinv=mat_inv(D)
        AD=mat_mul(A,Dinv)
        xd=mat_vec(D,pseudo)
        assert mat_vec(AD,xd)==u
        K=rng.randrange(2)
        s=[rng.randrange(Q) for _ in range(4)]
        _,_,_,dec=capsule(AD,u,[center(v) for v in xd],K,s,[0]*6,0)
        assert dec==K
        col_checks+=1
    report["public_linear_column_helper_noiseless_false_recoveries"]=col_checks

    print(json.dumps(report,sort_keys=True,indent=2))

if __name__=="__main__":
    main()
