#!/usr/bin/env python3
"""Run 51 finite-field checker. Standard library only; not a security proof."""
from collections import Counter
from fractions import Fraction
from itertools import product
import json, random

SEED=510051001
R=random.Random(SEED)

def inv(a,q): return pow(a%q,q-2,q)
def dot(a,b,q): return sum(x*y for x,y in zip(a,b))%q
def add(a,b,q): return tuple((x+y)%q for x,y in zip(a,b))
def scale(c,a,q): return tuple(c*x%q for x in a)

def basis(rows,q):
    A=[list(x%q for x in r) for r in rows if any(x%q for x in r)]
    if not A:return []
    m,n=len(A),len(A[0]); rr=0
    for cc in range(n):
        p=next((i for i in range(rr,m) if A[i][cc]%q),None)
        if p is None:continue
        A[rr],A[p]=A[p],A[rr]; z=inv(A[rr][cc],q)
        A[rr]=[z*x%q for x in A[rr]]
        for i in range(m):
            if i!=rr and A[i][cc]%q:
                z=A[i][cc]%q; A[i]=[(x-z*y)%q for x,y in zip(A[i],A[rr])]
        rr+=1
        if rr==m:break
    return [tuple(r) for r in A[:rr]]

def in_span(v,V,q):
    B=basis(V,q); return len(basis(B+[tuple(x%q for x in v)],q))==len(B)

def span(V,q,d):
    B=basis(V,q)
    if not B:return [(0,)*d]
    out=[]
    for cs in product(range(q),repeat=len(B)):
        v=[0]*d
        for c,b in zip(cs,B):
            for i,x in enumerate(b):v[i]=(v[i]+c*x)%q
        out.append(tuple(v))
    return out

def solve(M,rhs,q):
    A=[list(r)+[b%q] for r,b in zip(M,rhs)]
    if not A:return ()
    m,n=len(A),len(A[0])-1; rr=0; piv=[]
    for cc in range(n):
        p=next((i for i in range(rr,m) if A[i][cc]%q),None)
        if p is None:continue
        A[rr],A[p]=A[p],A[rr]; z=inv(A[rr][cc],q); A[rr]=[z*x%q for x in A[rr]]
        for i in range(m):
            if i!=rr and A[i][cc]%q:
                z=A[i][cc]%q; A[i]=[(x-z*y)%q for x,y in zip(A[i],A[rr])]
        piv.append(cc); rr+=1
    for i in range(rr,m):
        if all(A[i][j]%q==0 for j in range(n)) and A[i][n]%q:return None
    x=[0]*n
    for i,c in enumerate(piv):x[c]=A[i][n]%q
    return tuple(x)

def sep(V,r,q):
    lam=solve(list(V)+[r],[0]*len(V)+[1],q)
    if lam is None:return None
    assert all(dot(lam,v,q)==0 for v in V) and dot(lam,r,q)==1
    return lam

def tv(a,b):
    na,nb=sum(a.values()),sum(b.values()); K=set(a)|set(b)
    return sum(abs(Fraction(a[k],na)-Fraction(b[k],nb)) for k in K)/2

def subspace(exposed,r,q):
    if not exposed:return [r]
    for i in range(len(r)):
        e=tuple(int(j==i) for j in range(len(r)))
        if not in_span(r,[e],q):return [e]
    raise AssertionError

def shares(scheme,K,rnd,q):
    if scheme=='3-of-3': return (rnd[0],rnd[1],(K-rnd[0]-rnd[1])%q)
    a=rnd[0]; return tuple((K+a*x)%q for x in (1,2,3))

def auth(scheme,E): return len(E)==3 if scheme=='3-of-3' else len(E)>=2

def dist(scheme,K,bits,q=5):
    rs=[(j+1,1) for j in range(3)]; Vs=[subspace(bool(bits[j]),rs[j],q) for j in range(3)]
    masks=[span(Vs[j],q,2) for j in range(3)]; out=Counter()
    rnds=product(range(q),repeat=2) if scheme=='3-of-3' else ((a,) for a in range(q))
    for rnd in rnds:
        ss=shares(scheme,K,rnd,q)
        for ms in product(*masks): out[tuple(add(scale(ss[j],rs[j],q),ms[j],q) for j in range(3))]+=1
    return out,rs,Vs

def exact_lsss():
    pats=0; points=0; authp=0
    for scheme in ('3-of-3','2-of-3'):
        for bits in product((0,1),repeat=3):
            d0,rs,Vs=dist(scheme,0,bits); d1,_,_=dist(scheme,1,bits)
            E={i for i,b in enumerate(bits) if b}; want=Fraction(int(auth(scheme,E)),1)
            assert tv(d0,d1)==want
            for j,b in enumerate(bits): assert (sep(Vs[j],rs[j],5) is not None)==bool(b)
            pats+=1; points+=sum(d0.values())+sum(d1.values()); authp+=int(want)
    return {'patterns':pats,'authorized_patterns':authp,'enumerated_transcripts_with_multiplicity':points}

def random_quotients():
    q,d=7,5; exposed=hidden=extracts=shifts=0
    for _ in range(600):
        V=basis([tuple(R.randrange(q) for _ in range(d)) for __ in range(R.randrange(4))],q)
        r=tuple(R.randrange(q) for _ in range(d))
        if not any(r):r=(1,0,0,0,0)
        if in_span(r,V,q):
            hidden+=1; S=set(span(V,q,d))
            for s in range(q): assert {add(v,scale(s,r,q),q) for v in S}==S; shifts+=1
        else:
            exposed+=1; l=sep(V,r,q); S=span(V,q,d)
            for __ in range(7):
                s=R.randrange(q); c=add(scale(s,r,q),R.choice(S),q); assert dot(l,c,q)==s; extracts+=1
    return {'fixtures':600,'exposed':exposed,'hidden':hidden,'separator_extractions':extracts,'hidden_support_shift_checks':shifts}

def peval(c,w,q):
    z=p=1; z=0
    for a in c:z=(z+a*p)%q;p=p*w%q
    return z

def containment():
    q=7; Vt=basis([(0,1,0),(0,0,1)],q); Vf=basis([(0,1,0),(0,0,1),(-1,1,0),(0,-1,1)],q)
    rs=[(1,1,0),(2,1,0),(3,1,0)]; A={j for j,r in enumerate(rs) if peval(r,0,q)}
    Et={j for j,r in enumerate(rs) if not in_span(r,Vt,q)}; Ef={j for j,r in enumerate(rs) if not in_span(r,Vf,q)}
    assert A==Et=={0,1,2} and not Ef
    for _ in range(1000):
        q,d=11,6; ev=tuple(R.randrange(q) for _ in range(d))
        if not any(ev):ev=(1,0,0,0,0,0)
        p=next(i for i,x in enumerate(ev) if x); raw=[]
        for __ in range(R.randrange(5)):
            v=[R.randrange(q) for _ in range(d)]; other=sum(ev[i]*v[i] for i in range(d) if i!=p)%q
            v[p]=(-other*inv(ev[p],q))%q; raw.append(tuple(v))
        V=basis(raw,q); r=tuple(R.randrange(q) for _ in range(d))
        if in_span(r,V,q):assert dot(ev,r,q)==0
        if dot(ev,r,q):assert not in_span(r,V,q)
    return {'true_accessible':sorted(A),'true_exposed':sorted(Et),'false_exposed':sorted(Ef),'random_containment_checks':1000}

def mixture():
    pats=[(1,0,0),(1,1,0),(0,1,1),(1,1,1)]; ws=[1,2,3,4]; M=[Counter(),Counter()]
    for sid,(pat,w) in enumerate(zip(pats,ws)):
        for K in (0,1):
            d,_,_=dist('2-of-3',K,pat)
            for tr,n in d.items():M[K][(sid,tr)]+=w*n
    p=Fraction(sum(w for pat,w in zip(pats,ws) if auth('2-of-3',{i for i,b in enumerate(pat) if b})),sum(ws))
    assert tv(M[0],M[1])==p==Fraction(9,10)
    return {'tv':str(p),'authorized_setup_probability':str(p)}

def lagrange(indices,ss,q):
    out=0
    for j in indices:
        xj=j+1; num=den=1
        for k in indices:
            if k==j:continue
            xk=k+1; num=num*(-xk)%q; den=den*(xj-xk)%q
        out=(out+ss[j]*num*inv(den,q))%q
    return out

def reconstruct():
    q=11
    for _ in range(1000):
        K=R.randrange(q); ss=shares('2-of-3',K,(R.randrange(q),),q); ids=R.sample(range(3),2); assert lagrange(ids,ss,q)==K
    return {'shamir_2_of_3_reconstructions':1000}

def main():
    x={'run':51,'seed':SEED,'scope':'finite-field validation only; not a security proof','exact_lsss_distributions':exact_lsss(),'random_component_quotient':random_quotients(),'true_containment':containment(),'randomized_setup':mixture(),'threshold_reconstruction':reconstruct()}
    print(json.dumps(x,sort_keys=True,indent=2))
if __name__=='__main__':main()
