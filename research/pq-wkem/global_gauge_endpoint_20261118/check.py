#!/usr/bin/env python3
"""Synthetic public endpoint-gauge recovery; NOT ORIGINAL WKEM."""
import hashlib,itertools,json,random
p=101
I=((1,0),(0,1))
def mm(a,b):
    return tuple(tuple(sum(a[i][k]*b[k][j] for k in range(2))%p for j in range(2)) for i in range(2))
def prod(mats):
    a=I
    for b in mats:a=mm(a,b)
    return a
def det(a):return (a[0][0]*a[1][1]-a[0][1]*a[1][0])%p
def inv(a):
    d=pow(det(a),-1,p)
    return tuple(tuple((d*x)%p for x in row) for row in ((a[1][1],-a[0][1]),(-a[1][0],a[0][0])))
def randmat(rng):
    while True:
        m=tuple(tuple(rng.randrange(p) for _ in range(2)) for _ in range(2))
        if det(m):return m
def rref(rows):
    mat=[list(row) for row in rows]
    rank=0;pivots=[]
    for c in range(len(mat[0])):
        k=next((j for j in range(rank,len(mat)) if mat[j][c]%p),None)
        if k is None:continue
        mat[rank],mat[k]=mat[k],mat[rank]
        t=pow(mat[rank][c]%p,-1,p)
        mat[rank]=[(x*t)%p for x in mat[rank]]
        for j in range(len(mat)):
            if j!=rank and mat[j][c]:
                t=mat[j][c]%p
                mat[j]=[(x-t*y)%p for x,y in zip(mat[j],mat[rank])]
        pivots.append(c);rank+=1
        if rank==len(mat):break
    free=[i for i in range(len(mat[0])) if i not in pivots]
    vecs=[]
    for j in free:
        v=[0]*len(mat[0]);v[j]=1
        for i,c in enumerate(pivots):v[c]=(-mat[i][j])%p
        vecs.append(v)
    return rank,vecs
def eqs(z,arr,masked):
    A=prod(arr[i][bit] for i,bit in enumerate(z))
    B=prod(masked[i][bit] for i,bit in enumerate(z))
    rows=[]
    for i in range(2):
        for j in range(2):
            row=[0]*8
            for k in range(2):
                row[2*i+k]+=B[k][j]
                row[4+2*k+j]-=A[i][k]
            rows.append([x%p for x in row])
    return rows
def pad(a):
    return hashlib.sha256(b'PVUGC-global-gauge-negative-v1'+bytes(x for row in a for x in row)).digest()
a=((1,1),(0,1));b=((1,0),(1,1))
g=prod([a,b,inv(a),inv(b)])
def test(name,arr,withheld,consistent,seed):
    rng=random.Random(seed)
    P=[randmat(rng) for _ in range(len(arr)+1)]
    B=[tuple(prod([inv(P[i]),v,P[i+1]]) for v in pair) for i,pair in enumerate(arr)]
    C=prod([inv(P[0]),g,P[-1]])
    secret=hashlib.sha256(('synthetic-capability:'+name).encode()).digest()
    D=bytes(x^y for x,y in zip(secret,pad(C)))
    probes=[z for z in itertools.product((0,1),repeat=len(arr)) if z!=withheld]
    rank,basis=rref([row for z in probes for row in eqs(z,arr,B)])
    assert rank==7 and len(basis)==1
    v=basis[0]
    X=((v[0],v[1]),(v[2],v[3]));Y=((v[4],v[5]),(v[6],v[7]))
    assert det(X)
    recovered=prod([inv(X),g,Y])
    got=bytes(x^y for x,y in zip(D,pad(recovered)))
    assert recovered==C and got==secret
    outcomes=[prod(arr[i][z[i]] for i in range(len(arr))) for z in consistent]
    if name=='FALSE_x_AND_not_x':assert all(h==I for h in outcomes)
    if name=='TRUE_x_AND_y':assert outcomes.count(g)==1
    return dict(name=name,probes=len(probes),linear_rank=rank,nullspace_dim=len(basis),withheld=''.join(map(str,withheld)),accepting_consistent_count=outcomes.count(g),target_recovered=recovered==C,secret_recovered=got==secret,secret_sha256=hashlib.sha256(got).hexdigest())
def main():
    true=[(I,a),(I,b),(I,inv(a)),(I,inv(b))]
    false=[(I,a),(b,I),(I,inv(a)),(inv(b),I)]
    result={'scope':'synthetic full-public gauge attack, not ORIGINAL bridge',
            'checks':[test('FALSE_x_AND_not_x',false,(1,0,1,0),[(0,0,0,0),(1,1,1,1)],777),
                      test('TRUE_x_AND_y',true,(1,1,1,1),[(x,y,x,y) for x in (0,1) for y in (0,1)],778)]}
    print(json.dumps(result,indent=2,sort_keys=True))
if __name__=='__main__':main()
