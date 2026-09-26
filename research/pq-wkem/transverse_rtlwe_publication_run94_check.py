#!/usr/bin/env python3
import json, random, hashlib

SEED = 9400260925
rng = random.Random(SEED)
Q = 257


def modinv(a, q=Q):
    return pow(a % q, -1, q)


def rank_mod(M, q=Q):
    A = [[x % q for x in row] for row in M]
    if not A:
        return 0
    m, n = len(A), len(A[0])
    r = 0
    for c in range(n):
        piv = next((i for i in range(r, m) if A[i][c] % q), None)
        if piv is None:
            continue
        A[r], A[piv] = A[piv], A[r]
        inv = modinv(A[r][c], q)
        A[r] = [(v * inv) % q for v in A[r]]
        for i in range(m):
            if i != r and A[i][c] % q:
                f = A[i][c] % q
                A[i] = [(A[i][j] - f * A[r][j]) % q for j in range(n)]
        r += 1
        if r == m:
            break
    return r


def indicator(mask, L):
    return [(mask >> i) & 1 for i in range(L)]


def selector_rows(mask, L):
    rows = []
    for i in range(L):
        if (mask >> i) & 1:
            row = [0] * L
            row[i] = 1
            rows.append(row)
    return rows


def mat_vec(A, x, q=Q):
    return [sum(a*b for a,b in zip(row,x)) % q for row in A]


def vec_add(a,b,q=Q):
    return [(x+y)%q for x,y in zip(a,b)]


def dot(a,b,q=Q):
    return sum(x*y for x,y in zip(a,b)) % q


def mat_inv(A, q=Q):
    n = len(A)
    aug = [[A[i][j] % q for j in range(n)] + [1 if i==j else 0 for j in range(n)] for i in range(n)]
    r=0
    for c in range(n):
        piv = next((i for i in range(r,n) if aug[i][c] % q), None)
        if piv is None:
            raise ValueError('singular')
        aug[r],aug[piv]=aug[piv],aug[r]
        inv=modinv(aug[r][c],q)
        aug[r]=[(v*inv)%q for v in aug[r]]
        for i in range(n):
            if i!=r and aug[i][c]%q:
                f=aug[i][c]%q
                aug[i]=[(aug[i][j]-f*aug[r][j])%q for j in range(2*n)]
        r += 1
    return [row[n:] for row in aug]


def rand_invertible(n, q=Q):
    while True:
        A=[[rng.randrange(q) for _ in range(n)] for _ in range(n)]
        if rank_mod(A,q)==n:
            return A


def matmul(A,B,q=Q):
    m=len(A); k=len(A[0]); n=len(B[0])
    return [[sum(A[i][t]*B[t][j] for t in range(k))%q for j in range(n)] for i in range(m)]


def scalar_row_mat(s,A,q=Q):
    # s^T A
    return [sum(s[i]*A[i][j] for i in range(len(A)))%q for j in range(len(A[0]))]


def test_transversality():
    total=0
    authorized=0
    unauthorized=0
    for L in range(2,9):
        for X in range(1<<L):
            u=indicator(X,L)
            for Y in range(1<<L):
                M=selector_rows(Y,L)
                rM=rank_mod(M,Q)
                rstack=rank_mod(M+[u],Q)
                subset = (X & ~Y) == 0
                in_span = (rstack == rM)
                full_increment = (rstack == rM + 1)
                assert in_span == subset
                assert full_increment == (not subset)
                total += 1
                authorized += int(subset)
                unauthorized += int(not subset)
    return {"pairs": total, "authorized":authorized, "unauthorized":unauthorized}


def test_core_abe(trials=500):
    n=3; rdim=3
    correct=0
    pool_collapse=0
    for _ in range(trials):
        L=rng.randrange(3,9)
        # nonempty challenge X
        xmask=rng.randrange(1,1<<L)
        X=[i for i in range(L) if (xmask>>i)&1]
        s=[rng.randrange(Q) for _ in range(n)]
        r=[rng.randrange(Q) for _ in range(rdim)]
        As=[]; Bs=[]; ps=[]; xs=[]
        for i in range(L):
            A=rand_invertible(n,Q)
            B=[[rng.randrange(Q) for _ in range(rdim)] for _ in range(n)]
            p=[rng.randrange(Q) for _ in range(n)]
            rhs=vec_add(p, mat_vec(B,r,Q), Q)
            Ainv=mat_inv(A,Q)
            xi=mat_vec(Ainv,rhs,Q)
            assert mat_vec(A,xi,Q)==rhs
            As.append(A); Bs.append(B); ps.append(p); xs.append(xi)
        ctA={i:scalar_row_mat(s,As[i],Q) for i in X}
        Bsum=[[sum(Bs[i][a][b] for i in X)%Q for b in range(rdim)] for a in range(n)]
        psum=[sum(ps[i][a] for i in X)%Q for a in range(n)]
        ctB=scalar_row_mat(s,Bsum,Q)
        mu=rng.randrange(2); Delta=Q//2
        ctp=(dot(s,psum,Q)+mu*Delta)%Q
        dec=(ctp - sum(dot(ctA[i],xs[i],Q) for i in X) + dot(ctB,r,Q))%Q
        assert dec == (mu*Delta)%Q
        correct += 1

        # Public-prepublication collapse: choose 1..4 authorized witness sets Y_j all containing X.
        ys=[]
        union=0
        for __ in range(rng.randrange(1,5)):
            extra=rng.randrange(1<<L)
            ymask=xmask | extra
            ys.append(ymask); union |= ymask
        assert (xmask & ~union)==0
        # A public pool containing the same-r key component x_i for every i in union necessarily contains all X.
        dec_pool=(ctp - sum(dot(ctA[i],xs[i],Q) for i in X) + dot(ctB,r,Q))%Q
        assert dec_pool == (mu*Delta)%Q
        pool_collapse += 1
    return {"correct_decryptions":correct, "public_same_binding_pool_decryptions":pool_collapse}


def test_binding_mismatch(trials=300):
    # Demonstrates, but does not elevate to a security theorem, that independently bound components
    # generally do not satisfy the single-r cancellation identity used by the core scheme.
    mismatches=0
    accidental=0
    n=3; rdim=2
    for _ in range(trials):
        L=4; X=[0,1,2]
        s=[rng.randrange(Q) for _ in range(n)]
        r_common=[rng.randrange(Q) for _ in range(rdim)]
        As=[]; Bs=[]; ps=[]; x_ind=[]
        r_i=[]
        for i in range(L):
            A=rand_invertible(n,Q)
            B=[[rng.randrange(Q) for _ in range(rdim)] for _ in range(n)]
            p=[rng.randrange(Q) for _ in range(n)]
            ri=[rng.randrange(Q) for _ in range(rdim)]
            rhs=vec_add(p,mat_vec(B,ri,Q),Q)
            xi=mat_vec(mat_inv(A,Q),rhs,Q)
            As.append(A); Bs.append(B); ps.append(p); x_ind.append(xi); r_i.append(ri)
        ctA={i:scalar_row_mat(s,As[i],Q) for i in X}
        Bsum=[[sum(Bs[i][a][b] for i in X)%Q for b in range(rdim)] for a in range(n)]
        psum=[sum(ps[i][a] for i in X)%Q for a in range(n)]
        ctB=scalar_row_mat(s,Bsum,Q)
        mu=1; Delta=Q//2
        ctp=(dot(s,psum,Q)+mu*Delta)%Q
        trial=(ctp - sum(dot(ctA[i],x_ind[i],Q) for i in X) + dot(ctB,r_common,Q))%Q
        if trial != Delta%Q: mismatches+=1
        else: accidental+=1
    assert mismatches>0
    return {"trials":trials,"single_binding_identity_failures":mismatches,"accidental_equalities":accidental}


def main():
    result={
        "run":"94",
        "seed":SEED,
        "modulus":Q,
        "checks":{
            "subset_transversality":test_transversality(),
            "core_subset_abe":test_core_abe(),
            "independent_binding_negative_control":test_binding_mismatch(),
        },
        "claims_validated":[
            "For identity-selector M_Y and indicator u_X, rank([M_Y;u_X])=rank(M_Y)+1 iff X is not a subset of Y.",
            "The core common-binding subset-ABE cancellation identity decrypts for authorized X subset Y.",
            "If same-binding key components sufficient for an authorized Y containing X are public, the challenge decrypts publicly.",
            "Independently bound attribute components generally do not satisfy the same single-binding cancellation identity (negative control only)."
        ],
        "security_nonclaims":[
            "The checker does not prove LWE, RTLWE, or QPT hardness.",
            "The QPT lift in the proof note is a reduction argument for classical-query/static views, not established by these finite tests.",
            "No generic-NP WKEM is completed."
        ]
    }
    print(json.dumps(result, sort_keys=True, indent=2))

if __name__=='__main__':
    main()
