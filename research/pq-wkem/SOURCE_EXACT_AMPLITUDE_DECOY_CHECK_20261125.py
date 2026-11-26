import numpy as np
import hashlib
from itertools import product
p=101
rng=np.random.default_rng(20261125)

def inv(a):
    a=np.concatenate([a.copy(),np.eye(len(a),dtype=np.int64)],axis=1)
    n=len(a)
    for i in range(n):
        k=next((k for k in range(i,n) if a[k,i]%p),None)
        if k is None: return None
        a[[i,k]]=a[[k,i]]
        a[i]=a[i]*pow(int(a[i,i]),-1,p)%p
        for j in range(n):
            if j!=i: a[j]=(a[j]-a[j,i]*a[i])%p
    return a[:,n:]

def random_invertible(n):
    while True:
        a=rng.integers(0,p,(n,n),dtype=np.int64)
        ai=inv(a)
        if ai is not None: return a,ai

def kron(xs):
    a=np.array([1],dtype=np.int64)
    for x in xs: a=np.kron(a,x)%p
    return a

def unit(i,n):
    v=np.zeros(n,dtype=np.int64);v[i]=1;return v

def first(b):
    a=np.zeros((4,4),dtype=np.int64);a[:,0]=unit(1+b,4);return a

def last(b,v,d):
    a=np.column_stack([d,d,d,d]);a[:,1+b]=v;return a

def noncollinear():
    while True:
        v,d=rng.integers(0,p,(2,4),dtype=np.int64)
        if any((int(v[i])*int(d[j])-int(v[j])*int(d[i]))%p for i in range(4) for j in range(4)):
            return v,d

def digest(y):
    return hashlib.sha256(bytes(map(int,y))).digest()

# Build: the source is x=0, y=0, z=NAND(x,y), z=0. FALSE.
# A wire and its private entangling ancilla form an 8-dimensional site.
T=[random_invertible(8) for _ in range(3)]
vd=[noncollinear() for _ in range(3)]
U=kron([t@kron([unit(0,4),unit(0,2)])%p for t,_ in T])
V=kron([t@kron([v,unit(0,2)])%p for (t,_),(v,d) in zip(T,vd)])

def lift(i,a):
    t,ti=T[i]; return t@kron([a,np.eye(2,dtype=np.int64)])@ti%p

# Each row is serialized as its full support matrix, not the local factors.
# Gate order: fixed x=0; fixed y=0; NAND; fixed z=0.
rows=[((0,),{(0,):lift(0,first(0))}),((1,),{(0,):lift(1,first(0))}),
      ((0,1,2),{(x,y,1-x*y):kron([lift(0,last(x,*vd[0])),lift(1,last(y,*vd[1])),lift(2,first(1-x*y))]) for x,y in product(range(2),repeat=2)}),
      ((2,),{(0,):lift(2,last(0,*vd[2]))})]
secret=hashlib.sha256(b'synthetic not native').digest()
D=bytes(a^b for a,b in zip(secret,digest(V)))

def apply(state, sites, mats):
    # mats is a single operator on the listed sites; all sites dimension 8.
    order=list(sites)+[i for i in range(3) if i not in sites]
    arr=state.reshape([8]*3).transpose(order).reshape(8**len(sites),-1)
    return (mats@arr%p).reshape([8]*3).transpose(np.argsort(order)).reshape(-1)

for a in rows[2][1]:
    st=U.copy()
    for (sites,rs),choice in zip(rows,[(0,),(0,),a,(0,)]): st=apply(st,sites,rs[choice])
    assert np.any(st) and not np.array_equal(st,V)
print('Four locally allowed source streams: nonzero decoys, no exact target.')

# Adversary takes only U, D, public support indices and matrices.
def recover(U,D,rows):
    B={};rho={}
    for g,(sites,rs) in enumerate(rows):
        k=len(sites)
        for a,A in rs.items():
            rr,cc=map(int,np.argwhere(A!=0)[0]); q=int(A[rr,cc]); qi=pow(q,-1,p)
            r=list(np.unravel_index(rr,[8]*k)); c=list(np.unravel_index(cc,[8]*k)); factors=[]
            for j,i in enumerate(sites):
                M=np.empty((8,8),dtype=np.int64)
                for u,v in product(range(8),repeat=2):
                    rt=r.copy();ct=c.copy();rt[j]=u;ct[j]=v
                    M[u,v]=int(A[np.ravel_multi_index(rt,[8]*k),np.ravel_multi_index(ct,[8]*k)])*qi%p
                key=(g,i,a[j]); assert key not in B or np.array_equal(B[key],M)
                B[key]=M;factors.append(M)
            assert np.array_equal(q*kron(factors)%p,A)
            rho[g,a]=q
    # Local signed affine marginals for all-zero wires (invalid NAND row).
    lam=[{(0,):1},{(0,):1},{(0,0,1):2,(0,1,1):-1,(1,0,1):-1,(1,1,0):1},{(0,):1}]
    st=U.copy(); scale=1
    for g,(sites,rs) in enumerate(rows):
        assert sum(lam[g].values())==1
        assert all(sum(k*a[j] for a,k in lam[g].items())==0 for j in range(len(sites)))
        for i in sites: st=apply(st,(i,),B[g,i,0])
        for a,k in lam[g].items(): scale=scale*pow(rho[g,a],k,p)%p
    target=st*scale%p
    return target,bytes(a^b for a,b in zip(D,digest(target))),scale

recovered,opened,scale=recover(U,D,rows)
assert np.array_equal(recovered,V) and opened==secret
print('Exact (not projective) target recovered on FALSE; public scale:',scale)
print('Target SHA256:',digest(recovered).hex())
print('Synthetic pad recovery: exact.')
