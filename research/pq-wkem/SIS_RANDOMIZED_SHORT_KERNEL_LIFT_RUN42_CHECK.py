#!/usr/bin/env python3
import json, random, hashlib
from collections import Counter

SEED = 0x42_2026_09_22
rng = random.Random(SEED)

def mat_vec(M, v, q):
    return [sum(a*b for a,b in zip(row,v)) % q for row in M]

def transpose(M):
    return [list(col) for col in zip(*M)] if M else []

def mat_mul(A,B,q):
    BT=transpose(B)
    return [[sum(x*y for x,y in zip(row,col))%q for col in BT] for row in A]

def vec_add(a,b,q): return [(x+y)%q for x,y in zip(a,b)]
def dot(a,b,q): return sum(x*y for x,y in zip(a,b))%q

def inv(a,q): return pow(a%q,-1,q)

def rref(A,q):
    A=[row[:] for row in A]
    m=len(A); n=len(A[0]) if m else 0
    piv=[]; r=0
    for c in range(n):
        p=next((i for i in range(r,m) if A[i][c]%q),None)
        if p is None: continue
        A[r],A[p]=A[p],A[r]
        z=inv(A[r][c],q)
        A[r]=[(z*x)%q for x in A[r]]
        for i in range(m):
            if i!=r and A[i][c]%q:
                f=A[i][c]%q
                A[i]=[(x-f*y)%q for x,y in zip(A[i],A[r])]
        piv.append(c); r+=1
        if r==m: break
    return A,piv

def nullspace(H,q):
    R,piv=rref(H,q)
    n=len(H[0]) if H else 0
    free=[c for c in range(n) if c not in piv]
    out=[]
    for f in free:
        v=[0]*n; v[f]=1
        for i,p in enumerate(piv): v[p]=(-R[i][f])%q
        out.append(v)
    return out

def rand_mat(rows,cols,q):
    return [[rng.randrange(q) for _ in range(cols)] for __ in range(rows)]

def hcat(A,B): return [ra+rb for ra,rb in zip(A,B)]

def centered(a,q):
    a%=q
    return a-q if a>q//2 else a

def centered_norm2(v,q): return sum(centered(x,q)**2 for x in v)

def all_eta(vals,n):
    cur=[0]*n
    def rec(i):
        if i==n:
            yield cur[:]; return
        for x in vals:
            cur[i]=x
            yield from rec(i+1)
    yield from rec(0)

results={"seed":SEED,"identity_trials":0,"kernel_classifications":0,"semantic_survival_trials":0,
         "quotient_probe_trials":0,"exact_noise_distribution_cases":0,"failures":[]}

# 1) Randomized SIS-lift identity and classification.
for q in (5,7,101):
    for fixture in range(60):
        r,N,m,n=3,5,3,4
        H=rand_mat(r,N,q); C=rand_mat(n,r,q); A=rand_mat(n,m,q)
        D=hcat(C,A)
        M=hcat(mat_mul(C,H,q),A)
        for _ in range(25):
            x=[rng.randrange(q) for _ in range(N)]
            z=[rng.randrange(q) for _ in range(m)]
            e=x+z
            v=mat_vec(H,x,q)+z
            lhs=mat_vec(M,e,q)
            rhs=mat_vec(D,v,q)
            results["identity_trials"] += 1
            if lhs!=rhs:
                results["failures"].append(["lift_identity",q,fixture])
            if all(t==0 for t in lhs):
                results["kernel_classifications"] += 1
                if any(t!=0 for t in v):
                    if any(t!=0 for t in mat_vec(D,v,q)):
                        results["failures"].append(["sis_classification",q,fixture])
                else:
                    if any(t!=0 for t in mat_vec(H,x,q)) or any(t!=0 for t in z):
                        results["failures"].append(["semantic_classification",q,fixture])

# 2) Explicit false semantic pseudomode survives every random SIS lift.
for q in (5,7,11,101):
    H=[[1,1,(-3)%q]]
    xfalse=[1,2,1]
    assert mat_vec(H,xfalse,q)==[0]
    for fixture in range(250):
        n,m=3,4
        C=rand_mat(n,1,q); A=rand_mat(n,m,q)
        M=hcat(mat_mul(C,H,q),A)
        ef=xfalse+[0]*m
        results["semantic_survival_trials"] += 1
        if any(mat_vec(M,ef,q)):
            results["failures"].append(["semantic_survival",q,fixture])

# 3) Public semantic quotient/probe strips all D-derived masking.
for q in (5,7,11,101):
    H=[[1,1,(-3)%q]]
    Kbasis=nullspace(H,q)
    # Includes xfalse up to basis combination; test every basis vector and xfalse itself.
    probes=Kbasis+[[1,2,1]]
    for fixture in range(100):
        n,m=3,4
        C=rand_mat(n,1,q); A=rand_mat(n,m,q)
        s=[rng.randrange(q) for _ in range(n)]
        eta_x=[rng.randrange(q) for _ in range(3)]
        eta_z=[rng.randrange(q) for _ in range(m)]
        K=rng.randrange(q)
        Ht=transpose(H); Ct=transpose(C); At=transpose(A)
        # first mask = H^T C^T s
        cs=mat_vec(Ct,s,q)
        mask_x=mat_vec(Ht,cs,q)
        mask_z=mat_vec(At,s,q)
        e_h=[0,0,1]
        cx=[(mask_x[i]+eta_x[i]+K*e_h[i])%q for i in range(3)]
        cz=[(mask_z[i]+eta_z[i])%q for i in range(m)]
        for u in probes:
            results["quotient_probe_trials"] += 1
            got=dot(u,cx,q)
            want=(dot(u,eta_x,q)+K*u[2])%q
            if got!=want:
                results["failures"].append(["quotient_probe",q,fixture,u])

# 4) Exact scalar-channel invariance for the explicit false mode under unrelated lifts.
# Enumerate all eta_x in {-1,0,1}^3; the distribution of <xfalse,cx> is independent of C,A,s.
for q in (11,101):
    H=[[1,1,(-3)%q]]; xfalse=[1,2,1]; vals=[-1,0,1]
    baseline=None
    for lift in range(8):
        n,m=3,2
        C=rand_mat(n,1,q); A=rand_mat(n,m,q); s=[rng.randrange(q) for _ in range(n)]
        Ht=transpose(H); Ct=transpose(C)
        mask_x=mat_vec(Ht,mat_vec(Ct,s,q),q)
        for K in (0,1):
            cnt=Counter()
            for eta in all_eta(vals,3):
                cx=[(mask_x[i]+eta[i]+K*(1 if i==2 else 0))%q for i in range(3)]
                cnt[dot(xfalse,cx,q)] += 1
            normalized=sorted(cnt.items())
            results["exact_noise_distribution_cases"] += 1
            # Compare to direct channel <x,eta>+K.
            direct=Counter()
            for eta in all_eta(vals,3):
                direct[(dot(xfalse,[e%q for e in eta],q)+K)%q]+=1
            if normalized!=sorted(direct.items()):
                results["failures"].append(["exact_channel",q,lift,K])

# 5) Norm inflation bound check for centered residues.
# Use Frobenius bound ||Hx||_2 <= ||H||_F ||x||_2 as an executable control.
results["norm_bound_trials"]=0
for q in (101,257):
    for _ in range(1000):
        r,N=4,6
        Hi=[[rng.choice((-1,0,1)) for _ in range(N)] for __ in range(r)]
        H=[[a%q for a in row] for row in Hi]
        xint=[rng.randint(-3,3) for _ in range(N)]
        x=[a%q for a in xint]
        hx=mat_vec(H,x,q)
        lhs=centered_norm2(hx,q)
        fro2=sum(a*a for row in Hi for a in row)
        xn2=sum(a*a for a in xint)
        results["norm_bound_trials"] += 1
        if lhs>fro2*xn2:
            results["failures"].append(["norm_bound",q,lhs,fro2*xn2])

results["ok"] = not results["failures"]
blob=json.dumps(results,sort_keys=True,indent=2)+"\n"
print(blob,end="")
