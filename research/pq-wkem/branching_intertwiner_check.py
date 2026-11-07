#!/usr/bin/env python3
import itertools, json, math, random
from collections import Counter

def inv_mod(a,q): return pow(a%q,-1,q)

def eye(n):
    return [[1 if i==j else 0 for j in range(n)] for i in range(n)]

def mul(A,B,q):
    return [[sum(A[i][k]*B[k][j] for k in range(len(B)))%q
             for j in range(len(B[0]))] for i in range(len(A))]

def det(A,q):
    M=[row[:] for row in A]; n=len(M); out=1
    for c in range(n):
        p=next((i for i in range(c,n) if M[i][c]%q),None)
        if p is None: return 0
        if p!=c:
            M[c],M[p]=M[p],M[c]
            out=(-out)%q
        a=M[c][c]%q
        out=out*a%q
        ai=inv_mod(a,q)
        for i in range(c+1,n):
            if M[i][c]%q:
                f=M[i][c]*ai%q
                for j in range(c,n):
                    M[i][j]=(M[i][j]-f*M[c][j])%q
    return out

def mat_inv(A,q):
    n=len(A)
    M=[[A[i][j]%q for j in range(n)] +
       [1 if i==j else 0 for j in range(n)] for i in range(n)]
    r=0
    for c in range(n):
        p=next((i for i in range(r,n) if M[i][c]),None)
        if p is None: raise ValueError("singular")
        M[r],M[p]=M[p],M[r]
        s=inv_mod(M[r][c],q)
        M[r]=[(s*x)%q for x in M[r]]
        for i in range(n):
            if i!=r and M[i][c]:
                f=M[i][c]
                M[i]=[(M[i][j]-f*M[r][j])%q for j in range(2*n)]
        r+=1
    return [row[n:] for row in M]

def prod(ms,q):
    if not ms: raise ValueError("empty")
    P=eye(len(ms[0]))
    for M in ms: P=mul(P,M,q)
    return P

def rand_inv(d,q,rng):
    while True:
        A=[[rng.randrange(q) for _ in range(d)] for __ in range(d)]
        if det(A,q): return A

def perm_matrix(p):
    d=len(p); M=[[0]*d for _ in range(d)]
    for i,j in enumerate(p): M[i][j]=1
    return M

def rand_perm_matrix(d,rng):
    p=list(range(d)); rng.shuffle(p); return perm_matrix(p)

def nullspace(M,q):
    A=[[x%q for x in row] for row in M]
    m=len(A); n=len(A[0]) if A else 0
    piv=[]; r=0
    for c in range(n):
        p=next((i for i in range(r,m) if A[i][c]),None)
        if p is None: continue
        A[r],A[p]=A[p],A[r]
        s=inv_mod(A[r][c],q)
        A[r]=[(s*x)%q for x in A[r]]
        for i in range(m):
            if i!=r and A[i][c]:
                f=A[i][c]
                A[i]=[(A[i][j]-f*A[r][j])%q for j in range(n)]
        piv.append(c); r+=1
        if r==m: break
    free=[c for c in range(n) if c not in piv]
    basis=[]
    for f in free:
        v=[0]*n; v[f]=1
        for rr,p in enumerate(piv):
            v[p]=(-A[rr][f])%q
        basis.append(v)
    return basis

def build_system(A,C,q):
    L=len(A); d=len(A[0][0]); n=(L+1)*d*d
    def ix(layer,r,c): return layer*d*d+r*d+c
    E=[]
    for i in range(L):
        for b in range(len(A[i])):
            AA=A[i][b]; CC=C[i][b]
            for r in range(d):
                for c in range(d):
                    row=[0]*n
                    for k in range(d):
                        row[ix(i+1,k,c)] = (row[ix(i+1,k,c)] + AA[r][k])%q
                        row[ix(i,r,k)] = (row[ix(i,r,k)] - CC[k][c])%q
                    E.append(row)
    return E

def unvec(v,L,d):
    ans=[]; p=0
    for _ in range(L+1):
        X=[]
        for _ in range(d):
            X.append(v[p:p+d]); p+=d
        ans.append(X)
    return ans

def random_solution(basis,L,d,q,rng,max_tries=10000):
    if not basis: raise AssertionError("zero solution space")
    n=len(basis[0])
    for t in range(1,max_tries+1):
        cs=[rng.randrange(q) for _ in basis]
        v=[sum(cs[j]*basis[j][i] for j in range(len(basis)))%q
           for i in range(n)]
        X=unvec(v,L,d)
        if all(det(Y,q) for Y in X):
            return X,t
    raise AssertionError("failed to sample invertible tuple")

def key_matrix(d,k,q):
    S=eye(d)
    S[0][1]=k%q
    return S

def gl_fixture(rng,q=101,d=2,L=5,hidden_global=False):
    A=[[rand_inv(d,q,rng),rand_inv(d,q,rng)] for _ in range(L)]
    w=[rng.randrange(2) for _ in range(L)]
    T=prod([A[i][w[i]] for i in range(L)],q)
    k=rng.randrange(q); S=key_matrix(d,k,q)

    if hidden_global:
        Q=rand_inv(d,q,rng)
        Qi=mat_inv(Q,q)
        Aused=[[mul(mul(Qi,A[i][b],q),Q,q) for b in (0,1)] for i in range(L)]
        Tused=mul(mul(Qi,T,q),Q,q)
    else:
        Q=eye(d); Aused=A; Tused=T

    R=[rand_inv(d,q,rng) for _ in range(L)]
    R.append(mul(mul(mat_inv(Tused,q),R[0],q),S,q))
    C=[]
    for i in range(L):
        Ri=mat_inv(R[i],q)
        C.append([mul(mul(Ri,Aused[i][b],q),R[i+1],q) for b in (0,1)])

    assert prod([C[i][w[i]] for i in range(L)],q)==S

    # Attack always uses public canonical A,T, not hidden Q,Aused,Tused.
    B=nullspace(build_system(A,C,q),q)
    X,tries=random_solution(B,L,d,q,rng)
    rec=mul(mul(mat_inv(X[0],q),T,q),X[-1],q)
    assert rec==S
    return len(B),tries,k

def permutation_fixture(rng,q=101,d=3,L=6,samples=8):
    # The intended transcript consists only of permutation matrices.  The attacker
    # is free to linearize their integer 0/1 representation over F_q.
    A=[[rand_perm_matrix(d,rng),rand_perm_matrix(d,rng)] for _ in range(L)]
    w=[rng.randrange(2) for _ in range(L)]
    T=prod([A[i][w[i]] for i in range(L)],q)
    bit=rng.randrange(2)
    S=perm_matrix(list(range(d)) if bit==0 else [1,0]+list(range(2,d)))
    R=[rand_perm_matrix(d,rng) for _ in range(L)]
    R.append(mul(mul(mat_inv(T,q),R[0],q),S,q))
    C=[]
    for i in range(L):
        Ri=mat_inv(R[i],q)
        C.append([mul(mul(Ri,A[i][b],q),R[i+1],q) for b in (0,1)])
    assert prod([C[i][w[i]] for i in range(L)],q)==S

    B=nullspace(build_system(A,C,q),q)
    tries=[]; recovered=[]
    for _ in range(samples):
        X,t=random_solution(B,L,d,q,rng)
        rec=mul(mul(mat_inv(X[0],q),T,q),X[-1],q)
        tries.append(t); recovered.append(rec)
        assert rec==S
    return len(B),tries,bit

def main():
    rng=random.Random(20260922)
    gl_dims=Counter(); gl_tries=[]; hidden_dims=Counter(); hidden_tries=[]
    for _ in range(500):
        d,t,_=gl_fixture(rng,hidden_global=False)
        gl_dims[d]+=1; gl_tries.append(t)
    for _ in range(300):
        d,t,_=gl_fixture(rng,hidden_global=True)
        hidden_dims[d]+=1; hidden_tries.append(t)

    perm_dims=Counter(); perm_tries=[]; perm_samples=0
    for _ in range(200):
        d,ts,_=permutation_fixture(rng,samples=8)
        perm_dims[d]+=1; perm_tries.extend(ts); perm_samples+=len(ts)

    out={
      "status":"PASS",
      "general_GL2":{
        "fixtures":500,
        "solution_dimensions":dict(sorted(gl_dims.items())),
        "max_sampling_tries":max(gl_tries),
        "all_recovered_key_matrix":True,
      },
      "hidden_global_conjugation":{
        "fixtures":300,
        "attack_used_only_canonical_A_T":True,
        "solution_dimensions":dict(sorted(hidden_dims.items())),
        "max_sampling_tries":max(hidden_tries),
        "all_recovered_key_matrix":True,
      },
      "permutation_state_relabeling":{
        "fixtures":200,
        "invertible_solutions_sampled":perm_samples,
        "linearization_field":101,
        "solution_dimensions":dict(sorted(perm_dims.items())),
        "max_sampling_tries":max(perm_tries),
        "all_sampled_solutions_recovered_same_key_permutation":True,
      },
      "notes":[
        "These are finite-algebra checks of the proved intertwiner identity.",
        "They are not cryptographic security experiments.",
        "The attack theorem assumes a public canonical targeted branching representation and a true instance."
      ]
    }
    print(json.dumps(out,indent=2,sort_keys=True))

if __name__=="__main__":
    main()
