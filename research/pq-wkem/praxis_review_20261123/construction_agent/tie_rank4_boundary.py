"""Exact rank-four boundary probe of Praxis Eq.(5), outside Lemma B.6.

Use actual Forms(M) with d_R=2,k=2,n=6 and a full four-dimensional
rowspace. Comparing passing stack dimensions to honest-stack spans is a
finite algebra check, not a group attack or production parameter test.
"""
import hashlib
import itertools
import json
import random
from pathlib import Path
from tie_subspace_check import row_rank


def run(q, c, seed):
    n, ambient = 6, 4
    rng = random.Random(seed)
    omega = pow(c, (q - 1) // n, q)
    assert pow(omega, 3, q) == q - 1 and pow(omega, 2, q) != 1
    pairs = [(i, j) for i in range(ambient) for j in range(i, ambient)]
    copies = [("U", i) for i in range(n)] + [("V", i) for i in range(0, n, 2)]
    width = len(copies) * len(pairs)
    # M has two rows, and three ring columns (constant plus two limbs).
    while True:
        M = [[[rng.randrange(q), rng.randrange(q)] for _ in range(3)] for _ in range(2)]
        z = [[0] * n for _ in range(ambient)]
        z[0][0] = 1
        for k in range(2):
            z[0][2 + 2*k:4 + 2*k] = M[k][0]
            a,b = M[k][1]
            z[1][2 + 2*k:4 + 2*k] = [a,b]
            z[2][2 + 2*k:4 + 2*k] = [-b % q,a]
            a,b = M[k][2]
            z[3][2 + 2*k:4 + 2*k] = [a,b]
        if row_rank(z,q) == ambient:
            break

    def mul(a,b):
        out = [0] * n
        for i,x in enumerate(a):
            for j,y in enumerate(b):
                out[(i+j) % n] += x*y*(c if i+j >= n else 1)
        return [x % q for x in out]

    def sub(a,s):
        return [x*pow(s,i,q) % q for i,x in enumerate(a)]

    def residual(vec,policy):
        mats = []
        for a in range(len(copies)):
            mat = [[0]*ambient for _ in range(ambient)]
            for off,(i,j) in enumerate(pairs):
                mat[i][j] = mat[j][i] = vec[a*len(pairs)+off]
            mats.append(mat)
        result=[]
        for mat in mats:
            result.extend(mat[j][j]-mat[0][j] for j in range(1,ambient))
            if policy == "false_sum_and_product":
                result.extend([mat[0][1]+mat[0][2]-mat[0][0],mat[1][2]-mat[0][0]])
            if policy == "product_zero":
                result.append(mat[1][2])
        wu = [[[0]*n for _ in range(ambient)] for _ in range(ambient)]
        wv = [[[0]*n for _ in range(ambient)] for _ in range(ambient)]
        for (tag,deg),mat in zip(copies,mats):
            w = wu if tag=="U" else wv
            for i in range(ambient):
                for j in range(ambient):
                    w[i][j][deg] = mat[i][j]
        def mv(mat,v):
            out=[]
            for i in range(ambient):
                s=[0]*n
                for j in range(ambient):
                    p=mul(mat[i][j],v[j])
                    s=[(x+y) % q for x,y in zip(s,p)]
                out.append(s)
            return out
        wm=[[sub(a,-omega) for a in row] for row in wu]
        zm=[sub(a,-pow(omega,-1,q)) for a in z]
        z0=[sub(a,-1) for a in z]
        zp=[sub(a,-omega) for a in z]
        for a,b in [(mv(wu,z0),mv(wv,zm)),(mv(wu,zp),mv(wm,zm)),(mv(wv,zp),mv(wm,z0))]:
            for x,y in zip(a,b):
                result.extend(s-t for s,t in zip(x,y))
        return [x % q for x in result]

    honest=[]
    for bits in itertools.product([0,1],repeat=ambient-1):
        w=(1,)+bits
        zz=[sum(w[j]*z[j][k] for j in range(ambient)) % q for k in range(n)]
        u=mul(zz,sub(zz,pow(omega,n//2-1,q)))
        v=mul(zz,sub(zz,pow(omega,n//2,q)))
        assert not any(v[i] for i in range(1,n,2))
        vec=[(u if tag=="U" else v)[deg]*w[i]*w[j] % q for tag,deg in copies for i,j in pairs]
        honest.append((w,vec))
    results=[]
    for policy in ["none","product_zero","false_sum_and_product"]:
        columns=[residual([int(i==j) for i in range(width)],policy) for j in range(width)]
        passing_dim=width-row_rank(list(map(list,zip(*columns))),q)
        hs=[vec for w,vec in honest if policy=="none" or policy=="product_zero" and w[1]*w[2]==0]
        for v in hs:
            assert not any(residual(v,policy))
        hdim=row_rank(hs,q)
        results.append({"policy":policy,"passing_dim":passing_dim,"honest_dim":hdim,"gap":passing_dim-hdim})
    return {"q":q,"n":n,"ambient":ambient,"rowspace_dimension":4,"z_rank":row_rank(z,q),
            "c":c,"seed":seed,"M":M,"results":results}


if __name__=="__main__":
    out={"scope":__doc__,"cases":[run(q,c,seed) for q,c in [(7,3),(13,2)] for seed in range(10)],
         "source_sha256":hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
    print(json.dumps(out,indent=2,sort_keys=True))
