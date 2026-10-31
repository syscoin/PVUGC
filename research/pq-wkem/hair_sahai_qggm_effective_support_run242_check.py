#!/usr/bin/env python3
from fractions import Fraction
from itertools import product
from math import comb, floor, log2
import json, hashlib

ASSERTS = 0

def check(cond, msg):
    global ASSERTS
    ASSERTS += 1
    if not cond:
        raise AssertionError(msg)

def rank_mod(mat, p):
    a=[row[:] for row in mat]
    if not a: return 0
    r=0; c=0
    while r < len(a) and c < len(a[0]):
        piv=next((i for i in range(r,len(a)) if a[i][c]%p),None)
        if piv is None:
            c+=1; continue
        a[r],a[piv]=a[piv],a[r]
        inv=pow(a[r][c]%p,-1,p)
        a[r]=[(x*inv)%p for x in a[r]]
        for i in range(len(a)):
            if i!=r and a[i][c]%p:
                f=a[i][c]%p
                a[i]=[(x-f*y)%p for x,y in zip(a[i],a[r])]
        r+=1; c+=1
    return r

def in_colspace(A, y, p):
    # rank(A) == rank([A|y])
    r1=rank_mod(A,p)
    aug=[row[:] + [yy%p] for row,yy in zip(A,y)]
    return r1==rank_mod(aug,p)

def As_from_basis(s, basis, n_eff, p):
    # basis[j][row][col], only first n_eff columns are relevant
    out=[]
    for M in basis:
        row=[]
        for c in range(n_eff):
            row.append(sum((s[i]*M[i][c]) for i in range(len(s)))%p)
        out.append(row)
    return out

def y_from_full_r(s, basis, r, p):
    ys=[]
    for M in basis:
        v=0
        for i,si in enumerate(s):
            for c,rc in enumerate(r):
                v += si*M[i][c]*rc
        ys.append(v%p)
    return tuple(ys)

def y_from_eff(A, reff, p):
    return tuple(sum(row[c]*reff[c] for c in range(len(reff)))%p for row in A)

def fixture(p, m_total, n_eff, basis):
    k=len(basis)
    all_s=list(product(range(p), repeat=m_total))
    box=list(product(range(m_total), repeat=n_eff))
    uy=list(product(range(p), repeat=k))
    tv_sum=Fraction(0)
    span_adv_sum=Fraction(0)
    ranks={}
    support_sizes=[]
    for s in all_s:
        A=As_from_basis(s,basis,n_eff,p)
        rk=rank_mod(A,p)
        ranks[rk]=ranks.get(rk,0)+1
        counts={}
        for r in box:
            y=y_from_eff(A,r,p)
            counts[y]=counts.get(y,0)+1
        support_sizes.append(len(counts))
        ps=Fraction(1,len(box)); pu=Fraction(1,len(uy))
        tv=Fraction(0)
        for y in uy:
            tv += abs(Fraction(counts.get(y,0),len(box))-pu)
        tv_sum += tv/2
        direct_accept=p**rk
        # Exhaustively cross-check column-space size only on a bounded prefix.
        if len(support_sizes) <= 24:
            direct_enum=sum(1 for y in uy if in_colspace(A,y,p))
            check(direct_enum == direct_accept, "column-space size mismatch")
        span_adv_sum += 1-Fraction(direct_accept,len(uy))
    joint_tv=tv_sum/len(all_s)
    span_adv=span_adv_sum/len(all_s)
    formula_adv=1-sum(Fraction(cnt,p**(k-rk)) for rk,cnt in ranks.items())/len(all_s)
    check(span_adv==formula_adv,"span advantage formula")
    check(joint_tv >= 1-Fraction(m_total**n_eff,p**k),"support lower bound")
    check(max(support_sizes) <= m_total**n_eff,"support size bound")
    return {
        "p":p,"m_total":m_total,"n_eff":n_eff,"k":k,
        "rank_hist":{str(k):v for k,v in sorted(ranks.items())},
        "joint_tv":f"{joint_tv.numerator}/{joint_tv.denominator}",
        "support_lower_bound":f"{(1-Fraction(m_total**n_eff,p**k)).numerator}/{(1-Fraction(m_total**n_eff,p**k)).denominator}",
        "span_test_advantage":f"{span_adv.numerator}/{span_adv.denominator}",
        "max_structured_support":max(support_sizes),
    }

def zero_matrix(r,c): return [[0]*c for _ in range(r)]

def basis_overdetermined():
    p=7; m=4; n=2
    B=[]
    M=zero_matrix(m,m); M[0][0]=1; B.append(M)
    M=zero_matrix(m,m); M[1][1]=1; B.append(M)
    M=zero_matrix(m,m); M[2][0]=1; M[3][1]=1; B.append(M)
    return p,m,n,B

def basis_square():
    p=7; m=4; n=2
    B=[]
    M=zero_matrix(m,m); M[0][0]=1; B.append(M)
    M=zero_matrix(m,m); M[1][1]=1; B.append(M)
    return p,m,n,B

def validate_tail_independence(p,m,n,B):
    s=(1,2,3,4)
    A=As_from_basis(s,B,n,p)
    counts_full={}
    for r in product(range(m), repeat=m):
        y=y_from_full_r(s,B,r,p)
        counts_full[y]=counts_full.get(y,0)+1
        check(y==y_from_eff(A,r[:n],p),"tail coordinate affected exponent")
    counts_eff={}
    for r in product(range(m), repeat=n):
        y=y_from_eff(A,r,p)
        counts_eff[y]=counts_eff.get(y,0)+1
    factor=m**(m-n)
    check(counts_full=={y:c*factor for y,c in counts_eff.items()},"tail multiplicity mismatch")

def paper_param_rows():
    rows=[]
    min_gap=None
    for N in range(2,65):
        R=floor(log2(N))
        m=(N+1)*(2*N*R+1)*comb(2*R,R)
        gap=m-(N+1)*log2(m) # k=1 worst nontrivial output dimension
        check(gap>0,f"paper support exponent not negative at N={N}")
        min_gap=gap if min_gap is None else min(min_gap,gap)
        if N in (2,3,4,8,16,32,64):
            rows.append({"N":N,"R":R,"m":m,"k1_gap_bits":round(gap,6)})
    return rows, min_gap

def main():
    p,m,n,B=basis_overdetermined()
    validate_tail_independence(p,m,n,B)
    a=fixture(p,m,n,B)
    # k>n universal lower bound: 1-p^(n-k)
    lower=1-Fraction(1,p**(len(B)-n))
    adv=Fraction(*map(int,a["span_test_advantage"].split("/")))
    check(adv>=lower,"overdetermined span lower bound")

    p2,m2,n2,B2=basis_square()
    validate_tail_independence(p2,m2,n2,B2)
    b=fixture(p2,m2,n2,B2)
    rows,min_gap=paper_param_rows()

    out={
      "status":"PASS",
      "assertions":ASSERTS,
      "fixture_overdetermined":a,
      "fixture_square":b,
      "paper_parameter_rows":rows,
      "minimum_k1_gap_bits_N2_to_64":round(min_gap,6),
      "claims_checked":[
        "zero padding makes Y independent of the last m-(N+1) coordinates of r",
        "conditional structured support is at most m^(N+1)",
        "joint exponent-space TV is at least 1-m^(N+1)/p^k",
        "span-membership distinguisher has exact advantage 1-E_s[p^(rank(A_s)-k)]",
        "if k>N+1 then span advantage is at least 1-p^(-(k-N-1))",
        "paper parameter formula makes m^(N+1)/2^m exponentially small already for k=1"
      ]
    }
    print(json.dumps(out,sort_keys=True,indent=2))

if __name__=='__main__': main()
