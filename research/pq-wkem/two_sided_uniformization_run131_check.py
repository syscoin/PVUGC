#!/usr/bin/env python3
"""Run 131 deterministic algebra checks.

This is finite-field algebra validation for the Hair--Sahai-style weighted-table
source interface used in the preceding research notes.  It is not a QPT-hardness
or cryptographic-security test.
"""
from itertools import product
from math import comb, log2
import json, random

SEED = 13120260926
ASSERTIONS = 0

def ck(x):
    global ASSERTIONS
    ASSERTIONS += 1
    assert x

def inv(x,p): return pow(x % p, p-2, p)

def rref(M,p):
    M=[[x%p for x in row] for row in M]
    if not M: return [],[]
    r=0; piv=[]
    for c in range(len(M[0])):
        j=next((i for i in range(r,len(M)) if M[i][c]),None)
        if j is None: continue
        M[r],M[j]=M[j],M[r]
        s=inv(M[r][c],p); M[r]=[(s*x)%p for x in M[r]]
        for i in range(len(M)):
            if i!=r and M[i][c]:
                f=M[i][c]
                M[i]=[(x-f*y)%p for x,y in zip(M[i],M[r])]
        piv.append(c); r+=1
        if r==len(M): break
    return M[:r],piv

def rank(M,p): return len(rref(M,p)[1])

def nullspace(M,p,n):
    if not M:
        return [[int(i==j) for i in range(n)] for j in range(n)]
    R,piv=rref(M,p); free=[j for j in range(n) if j not in piv]; out=[]
    for f in free:
        x=[0]*n; x[f]=1
        for i in range(len(piv)-1,-1,-1):
            pc=piv[i]
            x[pc]=(-sum(R[i][j]*x[j] for j in free))%p
        out.append(x)
    return out

def basis(V,p): return rref(V,p)[0] if V else []

def alphas(R): return [a for a in product(range(R+1),repeat=R) if sum(a)<=R]

def encode(w,N,R,p):
    v=[1]+list(w); hs=[]; flat=[]
    for t in range(2*N*R+1):
        L=[sum(pow((pow(2,j,p)*t)%p,i,p)*v[i] for i in range(N+1))%p for j in range(R)]
        for aa in alphas(R):
            h=1
            for x,e in zip(L,aa): h=h*pow(x,e,p)%p
            hs.append(h)
            flat += [(h*x*y)%p for x in v for y in v]
    return hs,flat

def source(N,R,p):
    W=list(product((0,1),repeat=N)); H=[]; E=[]
    for w in W:
        h,e=encode(w,N,R,p); H.append(h); E.append(e)
    # Explicit false equation q_N=sum b_i-(N+1).
    C=[[H[i][j]*(sum(W[i])-(N+1))%p for i in range(len(W))] for j in range(len(H[0]))]
    S=[]
    for c in nullspace(C,p,len(W)):
        S.append([sum(c[i]*E[i][j] for i in range(len(W)))%p for j in range(len(E[0]))])
    return basis(S,p), H, E

def mat(v,b): return [v[i:i+b] for i in range(0,len(v),b)]

def lincomb(c,S,p):
    return [sum(x*B[j] for x,B in zip(c,S))%p for j in range(len(S[0]))]

def nextprime(n):
    def prime(x):
        if x<2:return False
        d=2
        while d*d<=x:
            if x%d==0:return False
            d+=1
        return True
    while not prime(n): n+=1
    return n

def capacities(S,b,p):
    mats=[mat(B,b) for B in S]; a=len(mats[0])
    horizontal=[[x for B in mats for x in B[row]] for row in range(a)]
    vertical=[row for B in mats for row in B]
    return a,rank(horizontal,p),rank(vertical,p)

def build_right_map(S,b,p,r,t,rng):
    """Condition on right factors. One output-row linear map U -> F_p^(t*k)."""
    mats=[mat(B,b) for B in S]; a=len(mats[0])
    V=[[[rng.randrange(p) for _ in range(b)] for _ in range(t)] for _ in range(r)]
    T=[]
    for s in range(t):
        for B in mats:
            row=[]
            for j in range(r):
                v=V[j][s]
                row += [sum(B[x][c]*v[c] for c in range(b))%p for x in range(a)]
            T.append(row)
    return T

def build_left_map(S,b,p,r,t,rng):
    """Condition on left factors. One output-column linear map V -> F_p^(t*k)."""
    mats=[mat(B,b) for B in S]; a=len(mats[0])
    U=[[[rng.randrange(p) for _ in range(a)] for _ in range(t)] for _ in range(r)]
    L=[]
    for q in range(t):
        for B in mats:
            row=[]
            for j in range(r):
                u=U[j][q]
                row += [sum(u[x]*B[x][c] for x in range(a))%p for c in range(b)]
            L.append(row)
    return L

def col_contains(A,y,p):
    return rank(A,p)==rank([row+[yy] for row,yy in zip(A,y)],p)

def canonical_line(v,p):
    i=next(i for i,x in enumerate(v) if x%p)
    s=inv(v[i],p)
    return tuple((s*x)%p for x in v)

def anchor_kernel_basis(S,p):
    ell=[B[0]%p for B in S]
    Kc=nullspace([ell],p,len(S))
    K=[lincomb(c,S,p) for c in Kc]
    # Pick a public anchor-one representative from the source basis.
    j=next(i for i,e in enumerate(ell) if e)
    sc=inv(ell[j],p)
    A=[sc*x%p for x in S[j]]
    ck(A[0]==1)
    return ell,K,A

def residual_rank_equivalence(S,b,p,r,t,samples,rng):
    ell,K,A=anchor_kernel_basis(S,p); k=len(S); a=len(S[0])//b
    # Work in basis [A] + K, whose anchor vector is (1,0,...,0).
    SB=[A]+K
    good=0; injective_K=0
    for _ in range(samples):
        L=build_left_map(SB,b,p,r,t,rng)
        # Anchor output rows and K-output rows.
        LA=[L[q*k] for q in range(t)]
        LK=[L[q*k+i] for q in range(t) for i in range(1,k)]
        ns=nullspace(LK,p,r*b)
        # Matrix of LA restricted to ker(LK): t x dimker.
        R=[[sum(row[c]*z[c] for c in range(r*b))%p for z in ns] for row in LA]
        rr=rank(R,p)
        if rank(LK,p)==r*b: injective_K+=1
        contain=True
        for s in range(t):
            delta=[]
            for q in range(t):
                delta += [1 if (q==s and i==0) else 0 for i in range(k)]
            contain &= col_contains(L,delta,p)
        ck(contain==(rr==t))
        good += int(contain)
    return {'samples':samples,'delta_containment':good,'K_injective':injective_K}

def K_eval_census(S,b,p):
    ell,K,A=anchor_kernel_basis(S,p); Km=[mat(B,b) for B in K]; a=len(Km[0]); kd=len(K)
    hist={}; low=[]; kernel_lines={}
    for v in product(range(p),repeat=b):
        if not any(v): continue
        # columns of Phi_v: K -> F_p^a, represented a x kd
        Phi=[[sum(Km[j][x][c]*v[c] for c in range(b))%p for j in range(kd)] for x in range(a)]
        d=rank(Phi,p); hist[d]=hist.get(d,0)+1
        if d<kd:
            ker=nullspace(Phi,p,kd)
            ck(len(ker)==kd-d)
            if d==kd-1:
                vl=canonical_line(v,p); kl=canonical_line(ker[0],p)
                low.append((vl,kl))
                kernel_lines.setdefault(kl,set()).add(vl)
    return hist,low,kernel_lines

def main():
    rng=random.Random(SEED)
    fixture=[]
    sources={}
    for N in range(2,7):
        R=int(log2(N)); p=nextprime(max(2**N,2*N*R)+1)
        S,H,E=source(N,R,p); b=N+1; a,ccol,crow=capacities(S,b,p); k=len(S)
        degree_cap=sum(comb(N,d) for d in range(min(N,R+1)+1))
        ck(ccol<=degree_cap)
        fixture.append({'N':N,'R':R,'p':p,'k':k,'a':a,'b':b,'column_capacity':ccol,'row_capacity':crow,'degree_R_plus_1_cap':degree_cap,'right_uniformization_possible_by_dimension':2*k<ccol,'left_uniformization_possible_by_dimension':2*k<crow})
        sources[N]=(S,p)

    # The N=3 false fixture is the first case where the raw long dimension a is huge
    # but the effective column-span capacity is too small for correctness-compatible
    # right-conditioned full uniformization.
    S3,p3=sources[3]; b3=4; a3,cc3,cr3=capacities(S3,b3,p3)
    ck((len(S3),a3,cc3,cr3)==(4,56,6,4))
    right=[]; left=[]
    for r in (1,2,3,4):
        t=2*r+1; rs={}; ls={}
        for _ in range(200):
            T=build_right_map(S3,b3,p3,r,t,rng); q=rank(T,p3); rs[q]=rs.get(q,0)+1; ck(q<=r*cc3); ck(q<t*len(S3))
            L=build_left_map(S3,b3,p3,r,t,rng); q=rank(L,p3); ls[q]=ls.get(q,0)+1; ck(q<=r*cr3); ck(q<t*len(S3))
        right.append({'r':r,'t':t,'rank_hist':rs,'capacity':r*cc3,'target':t*len(S3)})
        left.append({'r':r,'t':t,'rank_hist':ls,'capacity':r*cr3,'target':t*len(S3)})

    # Exact anchor-zero evaluation geometry for N=3.
    hist,low,kernel_lines=K_eval_census(S3,b3,p3)
    ck(hist=={2:40,3:14600})
    low_v_lines={v for v,k in low}; low_k_lines={k for v,k in low}
    ck(len(low_v_lines)==4 and len(low_k_lines)==4)
    ck(all(len(vs)==1 for vs in kernel_lines.values()))
    # Every projective low-v line has p-1 nonzero scalar representatives.
    ck(len(low)==4*(p3-1))

    # The exact tuple-rank enumerator follows from the four disjoint exceptional
    # projective lines: d_K(V)=2 iff all nonzero tuple entries lie on the same one.
    K_bounds=[]
    for r in (1,2,4,8,16,32):
        t=2*r+1
        n2=4*(p3**r-1); total=p3**(b3*r)-1; n3=total-n2
        # Union bound for non-injectivity of the anchor-zero conditional map.
        Z=n2/(p3**(2*t)) + n3/(p3**(3*t))
        K_bounds.append({'r':r,'t':t,'rank2_tuples':n2,'rank3_tuples':n3,'noninjective_union_bound':Z,'bits':-log2(Z)})
    ck(K_bounds[-1]['bits']>200)

    residual=residual_rank_equivalence(S3,b3,p3,1,3,200,rng)
    ck(residual['delta_containment']==0)

    # Positive sanity slice: N=2 has k=1 and both effective capacities 3>2k.
    S2,p2=sources[2]; full=0
    for _ in range(300):
        T=build_right_map(S2,3,p2,2,5,rng)
        full += int(rank(T,p2)==5)
    ck(full>0)

    out={
      'run':131,
      'seed':SEED,
      'assertions':ASSERTIONS,
      'fixtures':fixture,
      'N3_conditioned_rank_samples':{'right':right,'left':left},
      'N3_anchor_zero_eval':{'single_vector_hist':hist,'low_projective_v_lines':len(low_v_lines),'low_kernel_lines':len(low_k_lines),'tuple_union_bounds':K_bounds},
      'N3_anchor_residual_equivalence':residual,
      'N2_positive_right_full_rank_samples':{'r':2,'t':5,'samples':300,'full_rank':full},
      'scope':'finite algebra and exact linear-algebra identities only; no computational hardness or arbitrary-QPT extraction claim'
    }
    print(json.dumps(out,sort_keys=True,separators=(',',':')))

if __name__=='__main__': main()
