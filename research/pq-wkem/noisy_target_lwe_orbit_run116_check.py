#!/usr/bin/env python3
from __future__ import annotations
from itertools import product
from collections import Counter
from fractions import Fraction
import json, math

check_count=0
def ok(name, cond, detail=None):
    global check_count
    if not cond:
        raise AssertionError(f"{name}: {detail}")
    check_count += 1

def dot(a,b,q=None):
    v=sum(x*y for x,y in zip(a,b))
    return v if q is None else v%q

def mat_vec(A,u,q):
    return tuple(dot(row,u,q) for row in A)

def transpose(A):
    return tuple(tuple(A[i][j] for i in range(len(A))) for j in range(len(A[0])))

def mat_mul(A,B,q):
    BT=transpose(B)
    return tuple(tuple(dot(row,col,q) for col in BT) for row in A)

def ident(n):
    return tuple(tuple(1 if i==j else 0 for j in range(n)) for i in range(n))

def inv_mod(a,q): return pow(a,-1,q)

def mat_inv(A,q):
    n=len(A); I=ident(n)
    M=[list(A[i])+list(I[i]) for i in range(n)]
    for c in range(n):
        p=next((r for r in range(c,n) if M[r][c]%q),None)
        if p is None: return None
        M[c],M[p]=M[p],M[c]
        z=inv_mod(M[c][c]%q,q)
        M[c]=[(v*z)%q for v in M[c]]
        for r in range(n):
            if r==c: continue
            f=M[r][c]%q
            if f: M[r]=[(x-f*y)%q for x,y in zip(M[r],M[c])]
    return tuple(tuple(row[n:]) for row in M)

def all_mats(q,r,c):
    for vals in product(range(q), repeat=r*c):
        yield tuple(tuple(vals[i*c+j] for j in range(c)) for i in range(r))

def gl(q,n):
    out=[]
    for A in all_mats(q,n,n):
        Ai=mat_inv(A,q)
        if Ai is not None: out.append((A,Ai))
    return out

def centered(x,q):
    x%=q
    return x-q if x>q//2 else x

def l1_centered(v,q): return sum(abs(centered(x,q)) for x in v)

def rank(A,q):
    M=[list(r) for r in A]; rr=0; rows=len(M); cols=len(M[0])
    for c in range(cols):
        p=next((i for i in range(rr,rows) if M[i][c]%q),None)
        if p is None: continue
        M[rr],M[p]=M[p],M[rr]
        z=inv_mod(M[rr][c]%q,q); M[rr]=[(x*z)%q for x in M[rr]]
        for i in range(rows):
            if i==rr: continue
            f=M[i][c]%q
            if f: M[i]=[(x-f*y)%q for x,y in zip(M[i],M[rr])]
        rr+=1
        if rr==rows: break
    return rr

# 1. Exact left-GL orbit randomization on the complete q=3,n=2,m=2 space.
q=3; n=2; m=2
GL=gl(q,n); fixed_t=(1,0); As=list(all_mats(q,n,m))
nonzero_t=[v for v in product(range(q),repeat=n) if any(v)]
pair_counts=Counter()
for R,_ in GL:
    Rt=mat_vec(R,fixed_t,q)
    for A in As:
        pair_counts[(mat_mul(R,A,q),Rt)] += 1
expected=len(GL)//len(nonzero_t)
ok('left_support',len(pair_counts)==len(As)*len(nonzero_t))
for A2 in As:
    for t2 in nonzero_t:
        ok(f'left_uniform_{check_count}',pair_counts[(A2,t2)]==expected)

# 2. Exact secret change of basis on a deterministic cross-product.
identity_cases=0
for R,Rinv in GL:
    RinvT=transpose(Rinv)
    for s in product(range(q),repeat=n):
        sp=mat_vec(RinvT,s,q)
        for A in As[::9]:
            RA=mat_mul(R,A,q)
            ok(f'secretA_{identity_cases}',mat_vec(transpose(RA),sp,q)==mat_vec(transpose(A),s,q))
            ok(f'secrett_{identity_cases}',dot(mat_vec(R,fixed_t,q),sp,q)==dot(fixed_t,s,q))
            identity_cases+=1

# 3. Exact TV of uniform-nonzero target from uniform target.
tv_rows=[]
for q0,n0 in ((3,1),(3,2),(5,2),(7,2),(3,3)):
    N=q0**n0
    tv=Fraction(1,2)*(Fraction(1,N)+(N-1)*abs(Fraction(1,N-1)-Fraction(1,N)))
    ok(f'tv_{q0}_{n0}',tv==Fraction(1,N))
    tv_rows.append({'q':q0,'n':n0,'tv':str(tv)})

# 4. Noisy target sample / common-key wrapper: finite exhaustive fixture.
q=11; n=2; m=2; centers=(0,q//2); rho=2
A=((1,0),(0,1))
correctness_cases=0
for u in product((-1,0,1),repeat=m):
    if u==(0,0): continue
    t=mat_vec(A,u,q)
    for s in product(range(0,q,2),repeat=n): # deterministic subset: 36 secrets
        base=mat_vec(transpose(A),s,q)
        for e in product((-1,0,1),repeat=m):
            b=tuple((base[j]+e[j])%q for j in range(m))
            for e0 in (-1,0,1):
                y=(dot(t,s,q)+e0)%q
                err=dot(e,u)-e0
                for K in (0,1):
                    d=(centers[K]-y)%q
                    got=(dot(b,u,q)+d)%q
                    ok(f'wrap_id_{correctness_cases}',got==(centers[K]+err)%q)
                    if abs(err)<=rho:
                        dist=[abs(centered(got-c,q)) for c in centers]
                        dec=0 if dist[0]<dist[1] else 1
                        ok(f'wrap_dec_{correctness_cases}',dec==K,(u,e,e0,K,err,got,dist))
                    ok(f'key_to_y_{correctness_cases}',(centers[K]-d)%q==y)
                    correctness_cases+=1

# 5. Projected-error norm bound on a deterministic grid.
bound_cases=0
for Be,B0 in ((1,1),(2,1),(2,2)):
    for u in product(range(-2,3),repeat=2):
        # representative extreme and mixed errors, enough to check exact inequality logic
        E=[(-Be,-Be),(-Be,Be),(Be,-Be),(Be,Be),(0,0)]
        for e in E:
            for e0 in (-B0,0,B0):
                err=abs(dot(e,u)-e0); bound=Be*sum(abs(x) for x in u)+B0
                ok(f'bound_{bound_cases}',err<=bound,(Be,B0,u,e,e0,err,bound))
                bound_cases+=1

# 6. Perfect masking when y is uniform.
mask_cases=0
for q0 in (5,7,11,17):
    C=(0,q0//2)
    for K in (0,1):
        counts=Counter((C[K]-y)%q0 for y in range(q0))
        ok(f'mask_{q0}_{K}',set(counts.values())=={1})
        mask_cases+=1

# 7. Right-GL uniformization vs shortness, exact q=5,m=2,n=1 orbit.
q=5; GL2=gl(q,2); A0=((1,0),); u0=(1,0); t0=(1,)
A_counts=Counter(); u_counts=Counter()
for idx,(Q,Qinv) in enumerate(GL2):
    Ap=mat_mul(A0,Q,q); up=mat_vec(Qinv,u0,q)
    A_counts[Ap]+=1; u_counts[up]+=1
    ok(f'right_relation_{idx}',mat_vec(Ap,up,q)==t0)
full_rank_rows={((a,b),) for a,b in product(range(q),repeat=2) if (a,b)!=(0,0)}
nonzero_u={v for v in product(range(q),repeat=2) if v!=(0,0)}
ok('right_A_support',set(A_counts)==full_rank_rows)
ok('right_A_uniform',len(set(A_counts.values()))==1)
ok('right_u_support',set(u_counts)==nonzero_u)
ok('right_u_uniform',len(set(u_counts.values()))==1)
short_rows=[]
for B in range(0,5):
    cnt=sum(1 for u in nonzero_u if l1_centered(u,q)<=B)
    short_rows.append({'B':B,'count':cnt,'den':len(nonzero_u),'prob':str(Fraction(cnt,len(nonzero_u)))})
ok('right_B1',short_rows[1]['prob']=='1/6',short_rows[1])

# 8. Exact l1-ball formula for B<q/2, using enumeration only for moderate spaces.
def l1_ball_count(m,B):
    return sum(2**k*math.comb(m,k)*math.comb(B,k) for k in range(min(m,B)+1))
ball_rows=[]
for q0,m0,B in ((11,3,2),(11,4,2),(13,4,3)):
    actual=sum(1 for v in product(range(q0),repeat=m0) if l1_centered(v,q0)<=B)
    formula=l1_ball_count(m0,B)
    ok(f'ball_{q0}_{m0}_{B}',actual==formula,(actual,formula))
    ball_rows.append({'q':q0,'m':m0,'B':B,'nonzero_short':actual-1,'nonzero_total':q0**m0-1,'prob':str(Fraction(actual-1,q0**m0-1))})

# 9. Rank-deficiency conditioning: exact small spaces and elementary union bound.
rank_rows=[]
for q0,n0,m0 in ((3,1,3),(3,2,3),(5,2,2)):
    total=q0**(n0*m0); bad=0
    for A in all_mats(q0,n0,m0):
        if rank(A,q0)<n0: bad+=1
    pbad=Fraction(bad,total)
    union=Fraction(q0**n0-1,q0**m0)
    ok(f'rank_bound_{q0}_{n0}_{m0}',pbad<=union,(str(pbad),str(union)))
    rank_rows.append({'q':q0,'n':n0,'m':m0,'exact_rank_def':str(pbad),'union_bound':str(union)})

out={
 'run':116,'status':'PASS','total_assertions':check_count,
 'left_orbit':{'q':3,'n':2,'m':2,'gl_size':len(GL),'A_count':len(As),'nonzero_target_count':len(nonzero_t),'per_pair_count':expected},
 'target_conditioning_tv':tv_rows,
 'secret_change_basis_cases':identity_cases,
 'noisy_wrapper':{'cases':correctness_cases,'claim':'b^T u + (c_K-y)=c_K+e^T u-e0 and K,d recover y exactly.'},
 'error_bound_cases':bound_cases,'mask_cases':mask_cases,
 'right_randomization':{'q':5,'m':2,'gl_size':len(GL2),'A_orbit':len(A_counts),'u_orbit':len(u_counts),'short_probabilities':short_rows},
 'l1_ball_rows':ball_rows,'rank_conditioning_rows':rank_rows,
 'scope':[
  'Finite algebra/distribution checks only; tests do not establish computational LWE security.',
  'The security theorem in the note is a straight-line reduction conditional on exact-parameter decisional LWE against QPT adversaries and a compiler whose matrix is uniform (or quantified-close) independent of a nonzero target.',
  'No generic-NP uniform-matrix short-preimage compiler or practical parameter set is constructed.'
 ]
}
print(json.dumps(out,indent=2,sort_keys=True))
