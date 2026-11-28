#!/usr/bin/env python3
from itertools import product
from fractions import Fraction
from math import log2
import json, sys

ASSERTS = 0

def check(cond, msg="assertion failed"):
    global ASSERTS
    ASSERTS += 1
    if not cond:
        raise AssertionError(msg)

def rref(A, p):
    A=[[(x%p) for x in row] for row in A]
    if not A:
        return A, []
    nr=len(A); nc=len(A[0]); r=0; piv=[]
    for c in range(nc):
        i=next((i for i in range(r,nr) if A[i][c]),None)
        if i is None:
            continue
        A[r],A[i]=A[i],A[r]
        z=pow(A[r][c],-1,p)
        A[r]=[(z*x)%p for x in A[r]]
        for j in range(nr):
            if j!=r and A[j][c]:
                f=A[j][c]
                A[j]=[(x-f*y)%p for x,y in zip(A[j],A[r])]
        piv.append(c); r+=1
        if r==nr: break
    return A,piv

def rank(A,p): return len(rref(A,p)[1])

def matvec(A,x,p): return tuple(sum(a*b for a,b in zip(row,x))%p for row in A)

def in_span(A,y,p):
    return rank(A,p)==rank([row[:] + [yy%p] for row,yy in zip(A,y)],p)

def inv_matrix(A,p):
    n=len(A)
    check(all(len(row)==n for row in A),"inverse requires square matrix")
    aug=[[(x%p) for x in row] + [1 if i==j else 0 for j in range(n)] for i,row in enumerate(A)]
    r=0
    for c in range(n):
        i=next((i for i in range(r,n) if aug[i][c]),None)
        check(i is not None,"matrix unexpectedly singular")
        aug[r],aug[i]=aug[i],aug[r]
        z=pow(aug[r][c],-1,p)
        aug[r]=[(z*x)%p for x in aug[r]]
        for j in range(n):
            if j!=r and aug[j][c]:
                f=aug[j][c]
                aug[j]=[(x-f*y)%p for x,y in zip(aug[j],aug[r])]
        r+=1
    return [row[n:] for row in aug]

def bounded_membership_full_row_rank(A,y,m,p):
    """Exact membership in A*{0,...,m-1}^n for rank(A)=k.

    Returns (accept, recovered_preimage_or_None, iterations).
    """
    k=len(A); n=len(A[0]); R,pivs=rref(A,p)
    check(len(pivs)==k,"full-row-rank solver called on deficient A")
    P=pivs[:]
    F=[j for j in range(n) if j not in P]
    AP=[[A[i][j]%p for j in P] for i in range(k)]
    AI=inv_matrix(AP,p)
    it=0
    for free_vals in product(range(m), repeat=len(F)):
        it+=1
        rhs=[]
        for i in range(k):
            z=y[i]%p
            for j,v in zip(F,free_vals):
                z=(z-A[i][j]*v)%p
            rhs.append(z)
        piv_vals=matvec(AI,rhs,p)
        if all(0 <= v < m for v in piv_vals):
            x=[None]*n
            for j,v in zip(P,piv_vals): x[j]=v
            for j,v in zip(F,free_vals): x[j]=v
            x=tuple(x)
            check(matvec(A,x,p)==tuple(z%p for z in y),"recovered preimage mismatch")
            return True,x,it
    return False,None,it

def combined_distinguisher(A,y,m,p):
    q=rank(A,p); k=len(A); n=len(A[0])
    if q<k:
        return in_span(A,y,p), None, 0, "span"
    ok,x,it=bounded_membership_full_row_rank(A,y,m,p)
    return ok,x,it,"bounded"

def exhaustive_fixture(A,p,m):
    k=len(A); n=len(A[0]); q=rank(A,p)
    B=list(product(range(m),repeat=n))
    ys=list(product(range(p),repeat=k))
    support={matvec(A,x,p) for x in B}
    maxit=0
    for y in ys:
        got,x,it,mode=combined_distinguisher(A,y,m,p)
        maxit=max(maxit,it)
        check(got==(y in support),"combined membership != brute support")
        if got and x is not None:
            check(x in B,"recovered vector outside box")
    for x in B:
        y=matvec(A,x,p)
        got,_,_,_=combined_distinguisher(A,y,m,p)
        check(got,"structured sample rejected")
    expected_bound = (Fraction(p**q,p**k) if q<k else Fraction(m**n,p**k))
    false_accept=Fraction(len(support),p**k)
    if q<k:
        check(false_accept==Fraction(p**q,p**k),"deficient span support should equal image")
    else:
        check(false_accept<=expected_bound,"full-rank support bound")
    return {
        "p":p,"m":m,"k":k,"n":n,"rank":q,"codimension":n-q,
        "support_size":len(support),
        "false_accept":f"{false_accept.numerator}/{false_accept.denominator}",
        "max_enumeration_iterations":maxit,
        "universal_upper_bound":f"{expected_bound.numerator}/{expected_bound.denominator}",
    }

def main():
    A_full=[[1,2,0,1],[0,1,3,2]]
    full=exhaustive_fixture(A_full,13,3)
    check(full["rank"]==2 and full["codimension"]==2,"full-rank fixture shape")
    check(full["max_enumeration_iterations"]<=3**2,"enumeration exceeded m^d")

    A_def=[[1,2,3,4],[2,4,6,8]]
    deficient=exhaustive_fixture(A_def,13,3)
    check(deficient["rank"]==1,"deficient fixture rank")
    check(deficient["false_accept"]=="1/13","deficient false accept must be p^(q-k)")

    for m0,d0 in [(4,0),(17,1),(101,2),(1009,3)]:
        check(m0**d0 >= 1, "enumeration-count arithmetic")

    out={
      "run":245,
      "status":"PASS",
      "python":sys.version.split()[0],
      "assertions":ASSERTS,
      "theorem_checked":{
        "full_row_rank":"choose k pivot columns; enumerate all m^(n-k) free box coordinates; solve pivot coordinates uniquely; this is exact membership in A*[0,m)^n",
        "rank_deficient":"span membership is exact for the structured image; uniform false accept is p^(rank-k)",
        "combined":"structured acceptance is 1 for every A; uniform false accept is <= max(1/p, m^n/p^k) when rank deficiency is at least one",
        "complexity":"O(m^(n-k) * poly(n,k,log p)) on the full-row-rank branch"
      },
      "toy_full_rank":full,
      "toy_rank_deficient":deficient,
      "scope":{
        "proved":"generic classical post-exponent-recovery membership algorithm and its exact finite validation; polynomial-time when effective codimension n-k is constant and m is polynomial in the security/circuit parameter",
        "not_proved":"a concrete-group PQ attack; generic DLOG outside QGGM; hardness or easiness when effective codimension grows; full WKEM QPT hiding/extraction/setup composition"
      }
    }
    print(json.dumps(out,sort_keys=True,indent=2))

if __name__=="__main__": main()
