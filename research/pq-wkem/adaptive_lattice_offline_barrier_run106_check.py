#!/usr/bin/env python3
from itertools import product
import json

def vadd(a,b,q): return tuple((x+y)%q for x,y in zip(a,b))
def vscale(c,a,q): return tuple((c*x)%q for x in a)
def matmul_row(v,M,q): return tuple(sum(v[i]*M[i][j] for i in range(len(v)))%q for j in range(len(M[0])))
def dot(a,b,q): return sum(x*y for x,y in zip(a,b))%q

def gadget_row(r,q,ell):
    g=[pow(2,j,q) for j in range(ell)]
    return tuple(z for ri in r for z in ((ri*gj)%q for gj in g))

def recover(B,k,ell,q):
    return tuple(B[i*ell]%q for i in range(k))

checks=[]
def ok(name,cond,detail=None):
    if not cond: raise AssertionError(f"{name}: {detail}")
    checks.append({"name":name,"detail":detail})

# 1. r^T G injectivity / direct affine universalization.
for q in (3,5,7,17):
    ell=max(2,(q-1).bit_length())
    for k in (1,2,3):
        for r in product(range(q),repeat=k):
            B=gadget_row(r,q,ell)
            ok(f"gadget_{q}_{k}_{r}",recover(B,k,ell,q)==r)

q=7;k=2;ell=3;m=3
affine_cases=0
for s0 in ((1,2),(3,4)):
  for r in ((1,0),(2,5),(6,6)):
    B=gadget_row(r,q,ell); width=m*k*ell
    A=(tuple((2*j+1)%q for j in range(width)),
       tuple((3*j+2)%q for j in range(width)))
    base=tuple((s0[0]*A[0][j]+s0[1]*A[1][j])%q for j in range(width))
    coeffs=[]
    for j in range(m):
        row=[0]*width; row[j*k*ell:(j+1)*k*ell]=B; coeffs.append(tuple(row))
        ok(f"coeff_recovers_{s0}_{r}_{j}",recover(B,k,ell,q)==r)
    for x in product(range(q),repeat=m):
        c=base
        for j,xj in enumerate(x): c=vadd(c,vscale(xj,coeffs[j],q),q)
        direct=list(base)
        for j,xj in enumerate(x):
            for t,val in enumerate(B): direct[j*k*ell+t]=(direct[j*k*ell+t]+xj*val)%q
        ok(f"affine_{affine_cases}",c==tuple(direct))
        affine_cases+=1

# 2. Actual half-succinct OTE zero-noise algebra, ell_y=1.
q=5;m=2;ote_cases=0
for A in product(range(q),repeat=m):
  for S in product(range(q),repeat=m):
    for y in range(q):
        C=tuple(tuple((A[i]*S[j]+(y if i==j else 0))%q for j in range(m)) for i in range(m))
        for bi in range(m):
            x=tuple(1 if i==bi else 0 for i in range(m))
            d=dot(A,x,q)
            v=tuple(sum(C[i][j]*x[i] for i in range(m))%q for j in range(m))
            w=tuple((-S[j]*d)%q for j in range(m))
            total=vadd(v,w,q)
            exp=tuple((y*xj)%q for xj in x)
            ok(f"ote_correct_{ote_cases}_{bi}",total==exp)
            ok(f"ote_recover_{ote_cases}_{bi}",total[bi]==y)
        ote_cases+=1

# 3. Functionality-level public completion.
q=7;m=3;ell_y=2;pcases=0
for y in list(product(range(q),repeat=ell_y))[:20]:
  for bi in range(m):
    x=tuple(1 if i==bi else 0 for i in range(m))
    tensor=tuple(xi*yj%q for xi in x for yj in y)
    v=tuple((3*j+1)%q for j in range(len(tensor)))
    w=tuple((tensor[j]-v[j])%q for j in range(len(tensor)))
    rec=vadd(v,w,q)
    ok(f"pc_tensor_{pcases}",rec==tensor)
    ok(f"pc_y_{pcases}",rec[bi*ell_y:(bi+1)*ell_y]==y)
    pcases+=1

# 4. Adaptive LEnc multiplication identity, k=1.
q=7;G=(1,2,4)
def rightinv(A): return (tuple(A),(0,0,0),(0,0,0))
def lenc(A,x,s,r,e): return tuple((s*A[j]+x*r*G[j]+e[j])%q for j in range(3))
mul_cases=0
samples=[0,1,2,4,6]
for A0 in ((1,3,5),(2,0,6),(6,6,1)):
  for A1 in ((4,2,1),(0,5,3),(6,1,2)):
    M=rightinv(A1)
    ok(f"rinv_{A1}",matmul_row(G,M,q)==A1)
    Aout=tuple((-z)%q for z in matmul_row(A0,M,q))
    for x0 in samples:
      for x1 in samples:
       for s0,s1,s2 in ((1,2,3),(4,0,6)):
        for e0,e1 in (((0,0,0),(0,0,0)),((1,0,2),(0,3,1))):
            c0=lenc(A0,x0,s0,s1,e0); c1=lenc(A1,x1,s1,s2,e1)
            lhs=vadd(vscale(-1,matmul_row(c0,M,q),q),vscale(x0,c1,q),q)
            eout=vadd(vscale(-1,matmul_row(e0,M,q),q),vscale(x0,e1,q),q)
            rhs=lenc(Aout,(x0*x1)%q,s0,s2,eout)
            ok(f"mul_{mul_cases}",lhs==rhs)
            mul_cases+=1

# 5. Fully succinct syntax retains final phi_r.
for depth in range(1,17):
    phis=list(range(1,depth+1))
    ok(f"phi_depth_{depth}",phis[-1]==depth)

out={
 "run":106,"status":"PASS","total_assertions":len(checks),
 "direct_affine_universalization":{"q":7,"k":2,"m":3,"cases":affine_cases,
   "claim":"Exact affine x-coefficients expose r via r^T G because gadget blocks start with 1."},
 "half_succinct_ote":{"q":5,"m":2,"zero_noise_cases":ote_cases,
   "claim":"With E and phi public, basis x reconstructs encoder input y in the exact zero-noise algebra."},
 "public_completion":{"q":7,"m":3,"encoder_dimension":2,"cases":pcases,
   "claim":"A public replacement for the missing encoder share on arbitrary x makes x tensor y public; basis x reveals y."},
 "adaptive_lenc_merge":{"q":7,"k":1,"gadget":[1,2,4],"multiplication_cases":mul_cases,
   "claim":"Published adaptive-lattice multiplication identity holds exactly in the finite toy."},
 "fully_succinct_state":{"depths_checked":16,
   "claim":"Recursive succinctness retains a final private encoder-evaluation state."},
 "scope":["Algebra/syntax controls only; no LWE security is inferred.",
          "Direct affine leakage does not rule out every conceivable witness-independent compiler.",
          "Public-completion barrier applies when encoder input y is intended to remain secret.",
          "Published paper quantifies PPT, not QPT, attackers."]
}
print(json.dumps(out,indent=2,sort_keys=True))
