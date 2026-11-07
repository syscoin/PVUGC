#!/usr/bin/env python3
"""Exact joint-public-view repair test for the earlier pivot-Schur support attack.

Uses the local 2026-10-25 coupled-metric pipeline and copies the precise
public certificate construction of the 2026-10-24 GitHub checkpoint, pinned
SHA aa814d446419d84babc294de00b0205d7fe3c636.  Synthetic finite fields;
NOT a WKEM security or QPT hiding proof.
"""
from __future__ import annotations
import itertools,random,json,hashlib
import quotient_recurrence_check as f
import check_coupled_metric as cm
import check_joint_schur as old

checks=0

def ck(cond,msg):
    global checks;checks+=1
    if not cond:raise AssertionError(msg)

def tr(a):return [list(v) for v in zip(*a)]

def kern(A):
    red,p=f.rref_with_pivots(A)
    frees=[j for j in range(len(A[0])) if j not in p]
    out=[]
    for j in frees:
        v=[0]*len(A[0]);v[j]=1
        for i,k in enumerate(p):v[k]=red[i][j]
        out.append(v)
    return out

def basis(A):
    if not A:return []
    red,p=f.rref_with_pivots(A)
    return red[:len(p)]

def intersect_rows(A,B):
    a=basis(A);b=basis(B)
    if not a or not b:return []
    rel=kern(tr(a+b))
    return basis(f.mm([v[:len(a)] for v in rel],a)) if rel else []

def row(*items):
    z=[0]*5
    for i in items:z[i]^=1
    return z

def relation(false):
    A=[]; B=[]; C=[]
    for i in range(1,5): A.append(row(i));B.append(row(i));C.append(row(i))
    A.extend([row(1),row(3),row(3,4) if false else row(4)])
    B.extend([row(2),row(0),row(0)])
    C.extend([row(3),row(0,4),row() if false else row(0)])
    return A,B,C

def generate(false,seed,L=8,h=5):
    n,m=4,7; N=2*L+h; rng=random.Random(seed)
    rows=relation(false)
    nodes=[]; K=rng.randrange(256)
    for e in range(m,m+L):
        weights=old.interpolation_weights(e,m)
        forms=[[old.dot(weights,[r[j] for r in matrix]) for j in range(n+1)] for matrix in rows]
        Z=1
        for j in range(m):Z=f.F[Z][e^j]
        alphas=[]
        for i in range(n):
            beta=rng.randrange(16)^f.E[f.THETA][f.fpow(e,i)]
            alphas.append(f.epow(beta,128))
        nodes.append(dict(forms=forms, alpha=alphas, sl2=f.sl2(rng),
                          mu=rng.randrange(16,256), orientation=rng.randrange(2),
                          sqrtZ=f.fpow(Z,8),xi=f.fpow(e,8),
                          U=[[rng.randrange(256) for _ in range(3)] for _ in range(N)],
                          V=[[rng.randrange(256) for _ in range(N)] for _ in range(3)]))
    D=n+m
    Cs=[]
    for j in range(D):
        y=[int(t==j) for t in range(D)]
        out=f.zeros(N,N)
        for node in nodes:
            out=f.madd(out,f.mm(f.mm(node['U'],cm.gate(node,y,n)),node['V']))
        Cs.append(out)
    metric=f.zeros(N,N)
    for node in nodes:
        node['T']=cm.schur(*(rng.randrange(256) for _ in range(5)))
        metric=f.madd(metric,f.mm(f.mm(node['U'],node['T']),node['V']))
    if f.rank(metric)!=N:raise ValueError('setup would abort')
    base0=Cs[0]
    Cs[0]=f.madd(base0,f.mscale(K,metric))
    return rows,nodes,Cs,metric,K,base0

def projectors(T,roots):
    N=len(T); I=f.ident(N);ans=[]
    for i,x in enumerate(roots):
        P=I; den=1
        for j,y in enumerate(roots):
            if i!=j:
                P=f.mm(P,f.madd(T,f.mscale(y,I)))
                den=f.E[den][x^y]
        P=f.mscale(f.INV[den],P)
        ck(f.rank(P)==2,'spectral projector rank two')
        ans.append(P)
    return ans

def lift_public_support(Cs,n,roots):
    N=len(Cs[0]);L=len(roots)
    A,B,li,ri=f.rank_factor(Cs[n+1])
    T=f.mm(f.mm(li,Cs[n+2]),ri)
    marks=[f.mm(f.mm(A,P),B) for P in projectors(T,roots)]
    left=kern(tr(Cs[n+1]));right=tr(kern(Cs[n+1]))
    SR=basis([rr for C in Cs[1:n+1] for rr in f.mm(left,C)])
    SL=basis([rr for C in Cs[1:n+1] for rr in tr(f.mm(C,right))])
    if len(SL)+len(SR)!=3*L:
        return {'status':'unsaturated','SL':len(SL),'SR':len(SR)}
    H=kern(SL);Z=tr(kern(SR))
    terms=[];cls=[]
    for mark in marks:
        ac,bc,_,_=f.rank_factor(mark)
        ir=intersect_rows(bc,SR);ic=intersect_rows(tr(ac),SL)
        classes=(len(ir),len(ic));cls.append(classes)
        if classes==(1,0):
            v1=ir[0];v3=next(v for v in bc if f.rank([v,v1])==2)
            vv=[v3,v1];_,idx=f.rref_with_pivots(vv)
            Vi=f.invmat(f.submatrix(vv,[0,1],idx))
            uu=f.mm(f.submatrix(mark,list(range(N)),idx),Vi)
            u3=[[r[1]] for r in uu]
            extra=f.mm(u3,[v3])
        elif classes==(0,1):
            u1=ic[0];u3=next(u for u in tr(ac) if f.rank([u1,u])==2)
            uu=tr([u1,u3]);_,idx=f.rref_with_pivots(tr(uu))
            Ui=f.invmat(f.submatrix(uu,idx,[0,1]))
            vv=f.mm(Ui,f.submatrix(mark,idx,list(range(N))))
            extra=f.mm(tr([u3]),[vv[0]])
        else:
            return {'status':'bad_intersection','classes':cls,'SL':len(SL),'SR':len(SR)}
        terms.extend([f.mm(f.mm(H,mark),Z),f.mm(f.mm(H,extra),Z)])
    vec=lambda M:sum(M,[])
    S=basis([vec(t) for t in terms])
    return {'status':'certified','H':H,'Z':Z,'space':S,'classes':cls,'SL':len(SL),'SR':len(SR),'rank':len(S)}

def member(space,vec):
    return len(basis(space+[vec]))==len(space)

def trial(seed, false):
    rows,nodes,Cs,B,key,M0=generate(false,seed)
    n=4;L=len(nodes); root=[node['xi'] for node in nodes]
    report=lift_public_support(Cs,n,root)
    if report['status']!='certified':return {'seed':seed,'status':report['status'],'SL':report['SL'],'SR':report['SR']}
    H,Z,S=report['H'],report['Z'],report['space']
    proj=lambda M:f.mm(f.mm(H,M),Z)
    vec=lambda M:sum(M,[])
    ck(member(S,vec(proj(M0))),'baseline in public projected support')
    ck(member(S,vec(proj(B))),'COUPLED METRIC in same public projected support')
    ck(member(S,vec(proj(Cs[0]))),'full constant view in support')
    ck(not member(S,vec(proj(f.ident(len(B))))),'old scalar metric outside projected support')
    for node in nodes:
        each=f.mm(f.mm(H,f.mm(f.mm(node['U'],node['T']),node['V'])),Z)
        ck(member(S,vec(each)),'every coupled local metric block in S')
    # Both inclusions: the complete projection of the FIVE-DIMENSIONAL
    # local metric space is EXACTLY the attack's PUBLIC space S.
    allimages=[]
    for node in nodes:
        for template in [cm.schur(1,0,0,0,0),cm.schur(0,1,0,0,0),
                         cm.schur(0,0,1,0,0),cm.schur(0,0,0,1,0),
                         cm.schur(0,0,0,0,1)]:
            v=f.mm(f.mm(H,f.mm(f.mm(node['U'],template),node['V'])),Z)
            allimages.append(vec(v))
    ck(len(basis(allimages))==len(S),'entire projected metric image equals S')
    if seed in (1000,1001):
        for v in allimages:
            ck(member(S,v),'all local projected carrier basis elements lie in public S')
    if not false:
        # Complete Boolean-wire census. Four Booleanity rows ensure that all
        # GF(16)-valued originals actually lie in {0,1}^4.
        valid=[w for w in itertools.product((0,1),repeat=4) if cm.source_ok(rows,w)]
        ck(len(valid)==3,'true ORIGINAL relation has precisely three witnesses')
        if seed in (1000,1001,1002):
            for w in valid:
                y=cm.encode(rows,w)
                C=cm.meval(Cs,y)
                ck(f.rank(f.madd(C,f.mscale(key,B))) <=2*L,
                   'all genuine ORIGINAL witnesses recover same K by full rank test')
    elif seed==1000:
        ck(not any(cm.source_ok(rows,w) for w in itertools.product((0,1),repeat=4)),
           'false ORIGINAL has no Boolean witness')
    for lam in [0,1,key,key^1,255]:
        shifted=f.madd(Cs[0],f.mscale(lam,B))
        ck(member(S,vec(proj(shifted))),'every tested shifted key view in S')
    return {'seed':seed,'status':'certified','SL':report['SL'],'SR':report['SR'],
            'rankS':report['rank'],'old_identity_outside':True,
            'coupled_metric_inside':True, 'full_constant_inside':True}

def main():
    results=[]
    for false in (True,False):
        for seed in range(1000,1032):
            results.append({'relation':'false' if false else 'true',**trial(seed,false)})
    stats={t:sum(r['status']==t for r in results) for t in set(r['status'] for r in results)}
    print(json.dumps({'checks':checks,'trials':len(results),'statuses':stats,'certified': [r for r in results if r['status']=='certified'][:4],
                      'provenance':'synthetic GF(16) subfield GF(256), exact current gate; no QPT secrecy claim'},sort_keys=True,indent=2))

if __name__=='__main__': main()
