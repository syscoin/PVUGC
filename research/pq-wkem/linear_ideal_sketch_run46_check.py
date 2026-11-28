#!/usr/bin/env python3
import json, random, math
from fractions import Fraction

Q = 5
SEED = 460045001
rng = random.Random(SEED)


def inv(a, q=Q):
    a %= q
    if a == 0:
        raise ZeroDivisionError
    return pow(a, q-2, q)


def rref_aug(M, q=Q):
    A = [[x % q for x in row] for row in M]
    rows = len(A)
    cols = len(A[0]) if rows else 0
    pivots = []
    r = 0
    for c in range(cols):
        p = next((i for i in range(r, rows) if A[i][c] % q), None)
        if p is None:
            continue
        A[r], A[p] = A[p], A[r]
        z = inv(A[r][c], q)
        A[r] = [(z*x) % q for x in A[r]]
        for i in range(rows):
            if i != r and A[i][c] % q:
                f = A[i][c] % q
                A[i] = [(A[i][j] - f*A[r][j]) % q for j in range(cols)]
        pivots.append(c)
        r += 1
        if r == rows:
            break
    return A, pivots


def rank(M, q=Q):
    if not M:
        return 0
    _, piv = rref_aug(M, q)
    return len(piv)


def transpose(M):
    return [list(c) for c in zip(*M)] if M else []


def mat_vec(M, v, q=Q):
    return [sum(a*b for a,b in zip(row,v)) % q for row in M]


def dot(a,b,q=Q):
    return sum(x*y for x,y in zip(a,b)) % q


def solve_linear(M, rhs, q=Q):
    # solve M x = rhs, one solution with free vars 0; None if inconsistent
    aug = [list(row)+[rhs[i] % q] for i,row in enumerate(M)]
    R, piv = rref_aug(aug, q)
    n = len(M[0]) if M else 0
    for row in R:
        if all(row[j] % q == 0 for j in range(n)) and row[n] % q:
            return None
    x = [0]*n
    for i,c in enumerate(piv):
        if c < n:
            x[c] = R[i][n] % q
    return x


def in_colspan(A, b, q=Q):
    # A m x r, solve A rho=b
    if not A:
        return all(x % q == 0 for x in b)
    return solve_linear(A, b, q) is not None


def left_separator(A, b, q=Q):
    # find lambda: A^T lambda=0, b^T lambda=1
    m = len(b)
    AT = transpose(A)
    M = [row[:] for row in AT] + [list(b)]
    rhs = [0]*len(AT) + [1]
    lam = solve_linear(M, rhs, q)
    return lam


def random_matrix(rows, cols, q=Q):
    return [[rng.randrange(q) for _ in range(cols)] for __ in range(rows)]


def random_invertible(n, q=Q):
    while True:
        M = random_matrix(n,n,q)
        if rank(M,q)==n:
            return M


def mat_mul(A,B,q=Q):
    if not A or not B:
        return []
    BT=transpose(B)
    return [[dot(row,col,q) for col in BT] for row in A]


def vec_add(a,b,q=Q):
    return [(x+y)%q for x,y in zip(a,b)]


def scalar_vec(k,b,q=Q):
    return [(k*x)%q for x in b]


def enumerate_rho(r,q=Q):
    total=q**r
    for t in range(total):
        x=[]
        z=t
        for _ in range(r):
            x.append(z%q); z//=q
        yield x


def rank_count(m,d,r,q=Q):
    if r<0 or r>min(m,d): return 0
    if r==0: return 1
    num=1; den=1
    for i in range(r):
        num *= (q**m-q**i)*(q**d-q**i)
        den *= (q**r-q**i)
    return num//den


def exact_sep_probability(m,d,q=Q):
    total=q**(m*d)
    exp_in=Fraction(0,1)
    for r in range(min(m,d)+1):
        cnt=rank_count(m,d,r,q)
        exp_in += Fraction(cnt,total)*Fraction(q**r,q**m)
    return 1-exp_in


def full_row_rank_probability(m,d,q=Q):
    if d < m:
        return Fraction(0,1)
    out=Fraction(1,1)
    for i in range(m):
        out *= Fraction(q**d-q**i,q**d)
    return out


def poly_eval_row(D, w, q=Q):
    return [pow(w,i,q) for i in range(D+1)]


def ideal_generator_matrix(D,q=Q):
    # columns are coeff vectors of z^i*(z^2-z), i=0..D-2, ambient coeffs degree<=D
    N=D+1; d=D-1
    G=[[0]*d for _ in range(N)]
    for i in range(d):
        G[i+1][i] = (-1)%q
        G[i+2][i] = 1
    return G


def invert_matrix(M,q=Q):
    n=len(M)
    aug=[M[i][:]+[1 if i==j else 0 for j in range(n)] for i in range(n)]
    R,piv=rref_aug(aug,q)
    if len([p for p in piv if p<n])<n:
        raise ValueError('singular')
    return [row[n:] for row in R]


def high_degree_fixture(D=32,m=8,q=Q,trials=400):
    N=D+1
    G=ideal_generator_matrix(D,q)
    ev0=poly_eval_row(D,0,q)
    ev1=poly_eval_row(D,1,q)
    # S0 first two rows are witness evaluations; remaining are random linear sketches.
    S0=[ev0,ev1]+random_matrix(m-2,N,q)
    Mix=random_invertible(m,q)
    S=mat_mul(Mix,S0,q)
    A=mat_mul(S,G,q)
    e0=[1]+[0]*D
    b=mat_vec(S,e0,q)
    if in_colspan(A,b,q):
        raise AssertionError('fixture unexpectedly hid key')
    lam_pub=left_separator(A,b,q)
    if lam_pub is None or dot(lam_pub,b,q)!=1 or any(mat_vec(transpose(A),lam_pub,q)):
        raise AssertionError('public separator failed')
    Minv=invert_matrix(Mix,q)
    # lambda^T Mix = e_i^T => lambda = Mix^{-T} e_i, i.e. row i of Mix^{-1} as column
    lam0=Minv[0][:]
    lam1=Minv[1][:]
    # Check these are valid witness decoders.
    for lam in (lam0,lam1):
        if dot(lam,b,q)!=1 or any(mat_vec(transpose(A),lam,q)):
            raise AssertionError('witness decoder not separator')
    ok=0
    for _ in range(trials):
        rho=[rng.randrange(q) for _ in range(D-1)]
        k=rng.randrange(q)
        c=vec_add(mat_vec(A,rho,q),scalar_vec(k,b,q),q)
        if dot(lam0,c,q)==k and dot(lam1,c,q)==k and dot(lam_pub,c,q)==k:
            ok+=1
    return {
        'degree':D,'ambient_coeffs':N,'seed_dimension':D-1,'sketch_dimension':m,
        'capsules_checked':trials,'both_witness_decoders_correct':ok,
        'public_separator_correct':ok,
        'public_separator':lam_pub,
        'witness_decoder_0':lam0,
        'witness_decoder_1':lam1,
    }


def main():
    # 1. Exact coset dichotomy over many random small matrices.
    dichotomy=0; hidden=0; exposed=0; dist_points=0
    for _ in range(320):
        m=rng.randint(2,5); r=rng.randint(1,4)
        A=random_matrix(m,r,Q); b=[rng.randrange(Q) for _ in range(m)]
        inside=in_colspan(A,b,Q)
        if inside:
            hidden+=1
            # exact distributions for two keys by enumeration of rho
            counts=[]
            for k in (0,1):
                dct={}
                for rho in enumerate_rho(r,Q):
                    c=tuple(vec_add(mat_vec(A,rho,Q),scalar_vec(k,b,Q),Q))
                    dct[c]=dct.get(c,0)+1
                counts.append(dct)
            if counts[0]!=counts[1]:
                raise AssertionError('inside distributions differ')
            dist_points += len(set(counts[0])|set(counts[1]))
        else:
            exposed+=1
            lam=left_separator(A,b,Q)
            if lam is None: raise AssertionError('missing separator')
            seen=[set(),set()]
            for k in (0,1):
                for rho in enumerate_rho(r,Q):
                    c=tuple(vec_add(mat_vec(A,rho,Q),scalar_vec(k,b,Q),Q))
                    if dot(lam,c,Q)!=k:
                        raise AssertionError('separator decode failure')
                    seen[k].add(c)
            if seen[0] & seen[1]:
                raise AssertionError('outside cosets overlap')
            dist_points += len(seen[0])+len(seen[1])
        dichotomy+=1

    # 2. All-or-uniform law for arbitrary linear decoders lambda with lambda.b=1.
    all_or_uniform=0; exact_cases=0; uniform_cases=0; scalar_counts_checked=0
    for _ in range(500):
        m=rng.randint(2,5); r=rng.randint(1,4)
        A=random_matrix(m,r,Q)
        # choose nonzero lambda and b satisfying lambda.b=1
        while True:
            lam=[rng.randrange(Q) for _ in range(m)]
            if any(lam): break
        # choose b by solve one coordinate
        idx=next(i for i,x in enumerate(lam) if x%Q)
        b=[rng.randrange(Q) for _ in range(m)]
        rest=sum(lam[i]*b[i] for i in range(m) if i!=idx)%Q
        b[idx]=((1-rest)*inv(lam[idx],Q))%Q
        row=[dot(lam,[A[i][j] for i in range(m)],Q) for j in range(r)]
        counts=[0]*Q
        for rho in enumerate_rho(r,Q):
            val=dot(row,rho,Q)
            counts[val]+=1
        if all(x%Q==0 for x in row):
            exact_cases+=1
            if counts[0]!=Q**r or any(counts[v] for v in range(1,Q)):
                raise AssertionError('zero row not exact')
        else:
            uniform_cases+=1
            if len(set(counts))!=1:
                raise AssertionError('nonzero linear form not uniform')
        scalar_counts_checked += Q
        all_or_uniform += 1

    # 3. High-degree compressed ideal fixture with two valid witnesses.
    hd=high_degree_fixture()

    # 4. Random-sketch probability experiment and exact formula.
    prob_table=[]; prob_trials=3000
    for d in range(1,11):
        m=4; hits=0
        for _ in range(prob_trials):
            A=random_matrix(m,d,Q); b=[rng.randrange(Q) for _ in range(m)]
            if not in_colspan(A,b,Q): hits+=1
        exact=exact_sep_probability(m,d,Q)
        fr=full_row_rank_probability(m,d,Q)
        prob_table.append({
            'd':d,
            'empirical_separator_probability':hits/prob_trials,
            'exact_separator_probability':float(exact),
            'exact_separator_fraction':f'{exact.numerator}/{exact.denominator}',
            'full_row_rank_probability':float(fr),
            'full_row_rank_fraction':f'{fr.numerator}/{fr.denominator}',
        })

    # 5. Complexity-gap numeric consequence for q=5.
    complexity=[]
    for success in (0.60,0.80,0.95,0.99):
        # if witness linear decoder average success=s, public-exposed event prob >= (s-1/q)/(1-1/q)
        lower=(success-1/Q)/(1-1/Q)
        complexity.append({'witness_success':success,'min_public_exposed_probability':lower})

    result={
        'run':46,
        'candidate':'public linear sketch of a uniformly seeded high-degree source-ideal mask',
        'field_prime':Q,
        'seed':SEED,
        'dichotomy_fixtures':dichotomy,
        'hidden_cases':hidden,
        'exposed_cases':exposed,
        'distribution_support_points_checked':dist_points,
        'all_or_uniform_decoder_fixtures':all_or_uniform,
        'exact_decoder_cases':exact_cases,
        'uniform_noise_cases':uniform_cases,
        'scalar_histogram_bins_checked':scalar_counts_checked,
        'high_degree_ideal_fixture':hd,
        'random_sketch_trials_per_dimension':prob_trials,
        'random_sketch_table':prob_table,
        'complexity_gap_controls':complexity,
        'claims_not_made':[
            'No security claim follows from these tests.',
            'No impossibility theorem for nonlinear or computational compression is claimed.',
            'No arbitrary-QPT key-recovery extraction theorem is supplied for a surviving efficient WKEM.',
        ]
    }
    print(json.dumps(result, sort_keys=True, indent=2))

if __name__=='__main__':
    main()
