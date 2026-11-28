import itertools, random, json
from collections import Counter

def inv(a,q): return pow(a%q,-1,q)

def rref(rows,q):
    A=[list(x%q for x in r) for r in rows]
    if not A: return [],[]
    m,n=len(A),len(A[0]); rr=0; piv=[]
    for c in range(n):
        p=next((i for i in range(rr,m) if A[i][c]%q),None)
        if p is None: continue
        A[rr],A[p]=A[p],A[rr]
        s=inv(A[rr][c],q); A[rr]=[(s*x)%q for x in A[rr]]
        for i in range(m):
            if i!=rr and A[i][c]%q:
                s=A[i][c]%q
                A[i]=[(A[i][j]-s*A[rr][j])%q for j in range(n)]
        piv.append(c); rr+=1
        if rr==m: break
    return A[:rr],piv

def reduce_mod(v,basis,q):
    R,piv=rref(basis,q)
    out=[x%q for x in v]
    for row,p in zip(R,piv):
        if out[p]:
            s=out[p]
            out=[(out[j]-s*row[j])%q for j in range(len(out))]
    return tuple(out)

def add(a,b,q): return [(x+y)%q for x,y in zip(a,b)]
def scale(c,a,q): return [(c*x)%q for x in a]

def quotient_attack(D,N,M,q):
    qd=reduce_mod(D,M,q); qn=reduce_mod(N,M,q)
    for a,b in zip(qd,qn):
        if a:
            return b*inv(a,q)%q
    return None

def eval_poly(c,x,y,q):
    # basis 1,x,y,xy
    return (c[0]+c[1]*x+c[2]*y+c[3]*x*y)%q

def true_xy0_trials():
    q=101; rng=random.Random(1901)
    M=[[0,0,0,1]] # multiples of xy
    ws=[(0,0),(0,1),(1,0)]
    total=2000; all_complete=0; attack_ok=0; honest_checks=0
    for _ in range(total):
        K=rng.randrange(q)
        A=[rng.randrange(q) for _ in range(4)]
        u0=[0,0,0,rng.randrange(q)]
        u1=[0,0,0,rng.randrange(q)]
        D=add(A,u0,q); N=add(scale(K,A,q),u1,q)
        got=quotient_attack(D,N,M,q)
        if got==K: attack_ok+=1
        vals=[eval_poly(D,*w,q) for w in ws]
        if all(v!=0 for v in vals):
            all_complete+=1
            for w in ws:
                dec=eval_poly(N,*w,q)*inv(eval_poly(D,*w,q),q)%q
                assert dec==K
                honest_checks+=1
            assert got==K
    return {"trials":total,"all_witness_complete":all_complete,
            "honest_decodes_checked":honest_checks,
            "public_attack_success":attack_ok,
            "theory_all_complete":(100/101)**3}

def unique_witness_trials():
    q=101; rng=random.Random(1902)
    # masks span (1-x),(1-y)
    M=[[1,-1,0,0],[1,0,-1,0]]
    total=800; complete=0
    for _ in range(total):
        K=rng.randrange(q)
        A=[rng.randrange(q) for _ in range(4)]
        a,b=rng.randrange(q),rng.randrange(q)
        c,d=rng.randrange(q),rng.randrange(q)
        u0=[(a+b)%q,(-a)%q,(-b)%q,0]
        u1=[(c+d)%q,(-c)%q,(-d)%q,0]
        D=add(A,u0,q); N=add(scale(K,A,q),u1,q)
        den=eval_poly(D,1,1,q)
        if den:
            complete+=1
            assert eval_poly(N,1,1,q)*inv(den,q)%q==K
            assert quotient_attack(D,N,M,q)==K
    return {"trials":total,"nonzero_honest_denominator":complete}

def false_full_mask():
    q=3; dim=2
    distributions={}
    vecs=list(itertools.product(range(q), repeat=dim))
    for K in range(q):
        C=Counter()
        for A in vecs:
            for m0 in vecs:
                for m1 in vecs:
                    D=tuple((A[i]+m0[i])%q for i in range(dim))
                    N=tuple((K*A[i]+m1[i])%q for i in range(dim))
                    C[(D,N)]+=1
        distributions[K]=C
    assert distributions[0]==distributions[1]==distributions[2]
    vals=set(distributions[0].values())
    assert len(vals)==1
    return {"q":q,"dimension":dim,"keys":q,
            "support_size":len(distributions[0]),
            "count_per_output":next(iter(vals)),
            "samples_per_key":sum(distributions[0].values())}

def rank_mat(A,q):
    return len(rref(A,q)[1])

def matmul(A,B,q):
    return [[sum(A[i][k]*B[k][j] for k in range(len(B)))%q
             for j in range(len(B[0]))] for i in range(len(A))]

def solve_carrier(R,E,q):
    # R,E are quotient_dim x s. pick independent s rows and invert by solving.
    d=len(R); s=len(R[0])
    rows=None
    for inds in itertools.combinations(range(d),s):
        sub=[R[i] for i in inds]
        if rank_mat(sub,q)==s:
            rows=inds; break
    if rows is None: return None
    A=[R[i][:] for i in rows]
    B=[E[i][:] for i in rows]
    # Gauss-Jordan inverse action: augment A|B, reduce left to I.
    aug=[A[i]+B[i] for i in range(s)]
    rr=0
    for c in range(s):
        p=next(i for i in range(rr,s) if aug[i][c]%q)
        aug[rr],aug[p]=aug[p],aug[rr]
        z=inv(aug[rr][c],q)
        aug[rr]=[(z*x)%q for x in aug[rr]]
        for i in range(s):
            if i!=rr and aug[i][c]%q:
                z=aug[i][c]%q
                aug[i]=[(aug[i][j]-z*aug[rr][j])%q for j in range(2*s)]
        rr+=1
    return [row[s:] for row in aug]

def multicarrier_trials():
    q=101; rng=random.Random(1903); total=500; full=0
    # quotient represented directly as last four coordinates; mask first two
    for _ in range(total):
        K=rng.randrange(q)
        # Vdim 6, s=2 carriers
        U=[[rng.randrange(q) for _ in range(2)] for __ in range(6)]
        S=[[1,K],[0,1]]
        US=matmul(U,S,q)
        R=[]; E=[]
        for i in range(6):
            rrow=U[i][:]
            erow=US[i][:]
            if i<2:
                rrow=[(x+rng.randrange(q))%q for x in rrow]
                erow=[(x+rng.randrange(q))%q for x in erow]
            R.append(rrow); E.append(erow)
        QR=R[2:]; QE=E[2:]
        got=solve_carrier(QR,QE,q)
        if got is not None:
            full+=1
            assert got==S
            assert got[0][1]==K
    return {"trials":total,"full_rank_references":full,"recoveries":full}

def xor_composition():
    checks=0
    for N in range(1,7):
        for shares in itertools.product((0,1),repeat=N):
            final=0
            for x in shares: final^=x
            c=0
            for x in shares[1:]: c^=x
            for guess in (0,1):
                honest_guess=guess^c
                assert (honest_guess==shares[0])==(guess==final)
                checks+=1
    # negative control: after learning honest h, malicious m=h forces xor 0
    forced=sum(1 for h in (0,1) if (h^h)==0)
    assert forced==2
    # Uniform honest bit remains uniform after XOR with any fixed/adaptive c
    uniform_controls=0
    for c in (0,1):
        outs=[h^c for h in (0,1)]
        assert sorted(outs)==[0,1]
        uniform_controls+=1
    return {"operator_counts":"1..6","prediction_equivalence_checks":checks,
            "uniform_xor_controls":uniform_controls,
            "raw_share_reveal_negative_control":"2/2 forced final zero"}

out={"status":"PASS",
     "true_xy0":true_xy0_trials(),
     "unique_witness":unique_witness_trials(),
     "false_full_mask":false_full_mask(),
     "multi_carrier":multicarrier_trials(),
     "xor_composition":xor_composition()}
print(json.dumps(out,indent=2,sort_keys=True))
