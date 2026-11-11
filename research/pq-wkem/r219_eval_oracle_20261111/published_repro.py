#!/usr/bin/env python3
"""R219 toy: raw nonwitness evaluations reveal a hidden polynomial key.
Not SHA256/AuxPoW or a hash-based WKEM; oracle is a deliberately idealized leak.
"""
import json, random
Q=257
probes=[z for z in range(32) if z.bit_count()<=3]
def row(z):
    a,b,c,u,v=[(z>>i)&1 for i in range(5)]
    C=(u-a*b, v-u*c, v-1)
    mon=(1,a,b,c,u,v)
    return [1]+[(x*y)%Q for x in C for y in mon]
def solve(A, y):
    mat=[[x%Q for x in r]+[v%Q] for r,v in zip(A,y)]
    pivot=[]; k=0
    for j in range(len(A[0])):
        i=next((i for i in range(k,len(mat)) if mat[i][j]),None)
        if i is None: continue
        mat[i],mat[k]=mat[k],mat[i]
        inv=pow(mat[k][j],-1,Q)
        mat[k]=[(z*inv)%Q for z in mat[k]]
        for i in range(len(mat)):
            if i!=k and mat[i][j]:
                t=mat[i][j]
                mat[i]=[(x-t*y)%Q for x,y in zip(mat[i],mat[k])]
        pivot.append(j);k+=1
        if k==len(mat):break
    assert all(any(r[:-1]) or not r[-1] for r in mat)
    sol=[0]*len(A[0])
    for i,j in enumerate(pivot):sol[j]=mat[i][-1]
    return sol,pivot
assert len(probes)==26 and all(row(z)[1:7]!=[0]*6 or row(z)[7:13]!=[0]*6 or row(z)[13:]!=[0]*6 for z in probes)
checks=0
A=[row(z) for z in probes]
for i in range(32):
    r=random.Random(20261111+i)
    secret=[r.randrange(Q) for _ in range(19)]
    # Public evaluator returns only values, not the hidden secret coefficients.
    values=[sum(x*y for x,y in zip(row(z),secret))%Q for z in probes]
    recovered,pivot=solve(A,values)
    assert recovered[0]==secret[0]
    assert 0 in pivot
    checks+=2
print(json.dumps({'run':'R219-ORACLE-ONLY','assertions':checks+2,'oracle_queries_per_case':len(probes),
 'all_queries_unsatisfying':True,'keys_recovered':32,
 'scope':'ideal unrestricted raw evaluation interface; no original SHA/AuxPoW Build/Open'},sort_keys=True,indent=2))
