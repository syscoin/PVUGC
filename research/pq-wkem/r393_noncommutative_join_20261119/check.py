#!/usr/bin/env python3
"""Finite-field public matrix-path regression; no FE, Bitcoin or source witnesses."""
import json, hashlib
MOD = 257

def rank(matrix):
    m = [list(map(lambda x: x % MOD,row)) for row in matrix]
    if not m:
        return 0
    h,w=len(m),len(m[0]); p=0
    for j in range(w):
        pivot=next((i for i in range(p,h) if m[i][j]),None)
        if pivot is None: continue
        m[p],m[pivot]=m[pivot],m[p]
        inv=pow(m[p][j],-1,MOD)
        m[p]=[(v*inv)%MOD for v in m[p]]
        for i in range(h):
            if i!=p and m[i][j]:
                factor=m[i][j]
                m[i]=[(u-factor*v)%MOD for u,v in zip(m[i],m[p])]
        p+=1
        if p==h: break
    return p

def mask_deterministic(x,y,dimension):
    d=dimension
    a=[int.from_bytes(hashlib.sha256(b'A'+x.to_bytes(2,'big')+j.to_bytes(2,'big')).digest()[:2],'big')%MOD for j in range(d)]
    b=[int.from_bytes(hashlib.sha256(b'B'+y.to_bytes(2,'big')+j.to_bytes(2,'big')).digest()[:2],'big')%MOD for j in range(d)]
    return sum(i*j for i,j in zip(a,b))%MOD

summary=[]
for n in range(1,7):
    N=1<<n
    K=31
    exact=[[K if i==j else 0 for j in range(N)] for i in range(N)]
    r=rank(exact)
    d=max(1,N//2)
    lower=[[mask_deterministic(i,j,d) for j in range(N)] for i in range(N)]
    low_rank=rank(lower)
    assert r==N and low_rank<=d
    assert any(lower[i][j] != exact[i][j] for i in range(N) for j in range(N))
    summary.append({'n':n,'required_linear_state_dimension':r,'test_dimension':d,
                    'public_factor_matrix_rank':low_rank,'exact_K_delta_matrix_representable':False})
print(json.dumps({'scope':'separated two-claim equality in finite-field noncommutative linear state; not original source or FE',
                  'field':MOD,'cases':summary,'no_source_release_implementation':True},
                  indent=2,sort_keys=True))
