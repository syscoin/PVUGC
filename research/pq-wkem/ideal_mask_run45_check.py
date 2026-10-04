#!/usr/bin/env python3
import itertools, json, hashlib, math, random
from collections import defaultdict

P = 101


def inv(a,p=P): return pow(a%p,p-2,p)

def monomials_leq(nvars, D):
    out=[]
    def rec(pos, rem, cur):
        if pos==nvars-1:
            for e in range(rem+1):
                out.append(tuple(cur+[e]))
            return
        for e in range(rem+1):
            rec(pos+1, rem-e, cur+[e])
    rec(0,D,[])
    return out

def deg(mon): return sum(mon)

def add_poly(a,b,p=P):
    r=dict(a)
    for m,c in b.items():
        v=(r.get(m,0)+c)%p
        if v:r[m]=v
        elif m in r: del r[m]
    return r

def scale_poly(a,s,p=P): return {m:(c*s)%p for m,c in a.items() if (c*s)%p}

def mul_monom_poly(mon, poly,p=P):
    return {tuple(a+b for a,b in zip(mon,m)):c%p for m,c in poly.items()}

def eval_poly(poly, point,p=P):
    z=0
    for m,c in poly.items():
        v=c
        for e,x in zip(m,point): v=v*pow(x,e,p)%p
        z=(z+v)%p
    return z

def sparse_basis(rows, index, p=P):
    # rows are dict mon->coef; return pivot->normalized row basis
    basis={}
    for poly in rows:
        row={index[m]:c%p for m,c in poly.items() if c%p}
        while row:
            j=max(row)
            if j not in basis:
                s=inv(row[j],p)
                row={k:(v*s)%p for k,v in row.items() if (v*s)%p}
                basis[j]=row
                break
            f=row[j]
            br=basis[j]
            for k,v in br.items():
                nv=(row.get(k,0)-f*v)%p
                if nv: row[k]=nv
                elif k in row: del row[k]
    return basis

def reduce_vec(poly,basis,index,p=P):
    row={index[m]:c%p for m,c in poly.items() if c%p}
    while row:
        j=max(row)
        if j not in basis: break
        f=row[j]; br=basis[j]
        for k,v in br.items():
            nv=(row.get(k,0)-f*v)%p
            if nv: row[k]=nv
            elif k in row: del row[k]
    return row

def chain_constraints(n,p=P):
    # vars x0..xn, y1..yn ; total 2n+1
    nv=2*n+1
    def unit(idx):
        m=[0]*nv;m[idx]=1;return tuple(m)
    zero=(0,)*nv
    gs=[]
    gs.append({unit(0):1})
    for i in range(1,n+1):
        xi=unit(i)
        m=[0]*nv; m[i-1]=1; m[n+i]=1
        gs.append({xi:1,tuple(m):-1%p})
    gs.append({unit(n):1,zero:-1%p})
    return gs

def truncated_generators(gs,nvars,D,p=P):
    mons=monomials_leq(nvars,D)
    out=[]
    for g in gs:
        dg=max(map(deg,g))
        for m in mons:
            if deg(m)+dg<=D:
                out.append(mul_monom_poly(m,g,p))
    return out

def psi_monom_chain(mon,n):
    # Laurent exponents in y1..yn after x_i -> prod_{k=i+1}^n y_k^-1, y_j -> y_j
    e=[0]*n
    # direct y variables at index n+j, j=1..n
    for j in range(1,n+1):
        e[j-1]+=mon[n+j]
    for i in range(0,n+1):
        a=mon[i]
        if a:
            for k in range(i+1,n+1):
                e[k-1]-=a
    return tuple(e)

def ct_psi_poly(poly,n,p=P):
    s=0
    for m,c in poly.items():
        if all(v==0 for v in psi_monom_chain(m,n)):
            s=(s+c)%p
    return s

def telescoping_certificate(n,p=P):
    gs=chain_constraints(n,p)
    nv=2*n+1
    total={}
    # g_n + y_n g_{n-1}+...+(prod y_2..y_n)g_1 +(prod y_1..y_n)g0 - g_end
    for j in range(n,0,-1):
        m=[0]*nv
        for k in range(j+1,n+1): m[n+k]=1
        total=add_poly(total,mul_monom_poly(tuple(m),gs[j],p),p)
    m=[0]*nv
    for k in range(1,n+1): m[n+k]=1
    total=add_poly(total,mul_monom_poly(tuple(m),gs[0],p),p)
    total=add_poly(total,scale_poly(gs[-1],-1,p),p)
    return total

def random_combination(gens,rng,p=P):
    out={}
    # sparse random combo enough to test annihilator
    for g in gens:
        if rng.randrange(8)==0:
            c=rng.randrange(p)
            if c: out=add_poly(out,scale_poly(g,c,p),p)
    return out

def run():
    rng=random.Random(0x45A1DEA1)
    report={"field":P,"checks":{},"resource_counts":{}}
    # 1. exact chain degree threshold by span membership n=1..4
    degree_rows=[]
    for n in range(1,5):
        nv=2*n+1
        found=[]
        for D in range(1,n+2):
            mons=monomials_leq(nv,D); idx={m:i for i,m in enumerate(mons)}
            gs=chain_constraints(n)
            gens=truncated_generators(gs,nv,D)
            basis=sparse_basis(gens,idx)
            const={(0,)*nv:1}
            in_span=(len(reduce_vec(const,basis,idx))==0)
            found.append((D,in_span,len(mons),len(basis)))
        assert all(not x[1] for x in found if x[0]<=n)
        assert found[-1][0]==n+1 and found[-1][1]
        degree_rows.append({"n":n,"rows":[{"D":D,"one_in_span":b,"ambient_monomials":M,"span_rank":r} for D,b,M,r in found]})
    report["checks"]["exact_degree_thresholds"]=degree_rows

    # 2. Laurent dual annihilation exhaustive over every allowed monomial multiple for n=1..8, D=n
    dual_count=0
    for n in range(1,9):
        nv=2*n+1; D=n; gs=chain_constraints(n)
        assert ct_psi_poly({(0,)*nv:1},n)==1
        mons=monomials_leq(nv,D)
        for g in gs:
            dg=max(map(deg,g))
            for m in mons:
                if deg(m)+dg<=D:
                    poly=mul_monom_poly(m,g)
                    assert ct_psi_poly(poly,n)==0
                    dual_count+=1
    report["checks"]["laurent_dual_generator_multiples"]={"n_max":8,"checked":dual_count,"failures":0}

    # 3. telescoping certificate identity n=1..64
    cert_count=0
    for n in range(1,65):
        cert=telescoping_certificate(n)
        assert cert=={(0,)*(2*n+1):1}
        cert_count+=1
    report["checks"]["telescoping_certificates"]={"n_max":64,"checked":cert_count,"failures":0}

    # 4. false-key extraction from complete coefficient output at subcritical D
    attacks=0
    for n in range(2,7):
        D=n; nv=2*n+1; gs=chain_constraints(n)
        gens=truncated_generators(gs,nv,D)
        for _ in range(100):
            K=rng.randrange(P)
            R=random_combination(gens,rng)
            C=add_poly(R,{(0,)*nv:K})
            got=ct_psi_poly(C,n)
            assert got==K
            attacks+=1
    report["checks"]["complete_view_false_key_extractions"]={"trials":attacks,"failures":0}

    # 5. honest correctness on a true quadratic system; any ideal mask evaluates to zero at witness.
    # vars z0,z1 ; constraints z0-1=0, z1=0, z0*z1=0; witness (1,0)
    nv=2; zero=(0,0)
    gtrue=[{(1,0):1,zero:-1%P},{(0,1):1},{(1,1):1}]
    gens=truncated_generators(gtrue,nv,4)
    honest=0
    for _ in range(500):
        K=rng.randrange(P)
        R=random_combination(gens,rng)
        C=add_poly(R,{zero:K})
        assert eval_poly(C,(1,0))==K
        honest+=1
    report["checks"]["honest_decapsulations"]={"trials":honest,"failures":0}

    # 6. shift-invariance control when 1 enters span: if B is a basis and const in span, affine cosets same.
    shift_controls=[]
    for n in range(1,5):
        D=n+1; nv=2*n+1; mons=monomials_leq(nv,D);idx={m:i for i,m in enumerate(mons)}
        gens=truncated_generators(chain_constraints(n),nv,D)
        basis=sparse_basis(gens,idx)
        rem=reduce_vec({(0,)*nv:1},basis,idx)
        assert not rem
        shift_controls.append({"n":n,"D":D,"ambient_monomials":len(mons),"span_rank":len(basis),"one_in_span":True})
    report["checks"]["false_hiding_shift_invariance_controls"]=shift_controls

    # 7. resource counts
    for n in [8,16,32,64,128]:
        N=2*n+1; D=n+1; M=math.comb(N+D,D)
        report["resource_counts"][str(n)]={"variables":N,"minimum_degree":D,"ambient_monomials":M,"log2_ambient":math.log2(M)}

    encoded=json.dumps(report,sort_keys=True,indent=2)+"\n"
    print(encoded,end="")

if __name__=='__main__': run()
