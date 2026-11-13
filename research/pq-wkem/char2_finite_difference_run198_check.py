#!/usr/bin/env python3
from itertools import product
from collections import Counter
from fractions import Fraction
import json

class GF2h:
    def __init__(self,h,poly):
        self.h=h; self.q=1<<h; self.poly=poly
    def add(self,a,b): return a^b
    def mul(self,a,b):
        z=0
        while b:
            if b&1: z ^= a
            b >>= 1; a <<= 1
            if a & self.q: a ^= self.poly
        return z
    def pow(self,a,e):
        z=1
        while e:
            if e&1: z=self.mul(z,a)
            a=self.mul(a,a); e>>=1
        return z
    def inv(self,a):
        assert a
        return self.pow(a,self.q-2)
    def order(self,a):
        z=1
        for k in range(1,self.q):
            z=self.mul(z,a)
            if z==1:return k
        raise AssertionError

def alphas(R):
    return [a for a in product(range(R+1),repeat=R) if sum(a)<=R]

def choose_gamma(F,N):
    return next(a for a in range(2,F.q) if F.order(a)>N)

def weights_for_word(word,N,R,F,gamma):
    v=[1]+[(word>>i)&1 for i in range(N)]
    aa=alphas(R)
    out=[]
    for tau in range(2*N*R+1):
        forms=[]
        for j in range(R):
            g=F.mul(F.pow(gamma,j),tau)
            ell=0
            for i,bi in enumerate(v):
                if bi: ell ^= F.pow(g,i)
            forms.append(ell)
        for alpha in aa:
            h=1
            for e,x in zip(alpha,forms): h=F.mul(h,F.pow(x,e))
            out.append(h)
    return v,out

def add_assignment_matrix(acc_cols,word,N,R,F,gamma):
    v,weights=weights_for_word(word,N,R,F,gamma)
    n=N+1; row=0
    for h in weights:
        for i,vi in enumerate(v):
            for j,vj in enumerate(v):
                if vi and vj:
                    acc_cols[j][row+i] ^= h
        row += n
    return len(weights)*n

def field_rank_cols(cols,F):
    if not cols:return 0
    A=[list(row) for row in zip(*cols)]
    m=len(A); n=len(A[0]); r=0
    for c in range(n):
        p=next((i for i in range(r,m) if A[i][c]),None)
        if p is None: continue
        A[r],A[p]=A[p],A[r]
        inv=F.inv(A[r][c]); A[r]=[F.mul(inv,x) for x in A[r]]
        for i in range(m):
            if i!=r and A[i][c]:
                fac=A[i][c]
                A[i]=[x ^ F.mul(fac,y) for x,y in zip(A[i],A[r])]
        r+=1
        if r==n: break
    return r

def binary_rank_cols(cols,F):
    vals=[]
    for col in cols:
        bits=0
        pos=0
        for x in col:
            for k in range(F.h):
                if (x>>k)&1: bits |= 1<<pos
                pos += 1
        vals.append(bits)
    piv={}
    for v in vals:
        while v:
            k=v.bit_length()-1
            if k in piv: v ^= piv[k]
            else: piv[k]=v; break
    return len(piv)

def construct(N,R,F,T,zbits):
    gamma=choose_gamma(F,N); s=R+1
    outside=[i for i in range(N) if i not in T]
    words=[]
    for xbits in range(1<<s):
        w=0
        for k,i in enumerate(T):
            if (xbits>>k)&1: w |= 1<<i
        for k,i in enumerate(outside):
            if (zbits>>k)&1: w |= 1<<i
        words.append(w)
    nw=(2*N*R+1)*len(alphas(R)); rows=nw*(N+1)
    cols=[[0]*rows for _ in range(N+1)]
    sums=[0]*nw
    for w in words:
        v,ws=weights_for_word(w,N,R,F,gamma)
        sums=[a^b for a,b in zip(sums,ws)]
        add_assignment_matrix(cols,w,N,R,F,gamma)
    assert all(x==0 for x in sums)
    assert any(any(x for x in col) for col in cols)
    anchor=cols[0][0]
    assert anchor==0
    for k,i in enumerate(outside):
        expected=cols[0] if ((zbits>>k)&1) else [0]*rows
        assert cols[i+1]==expected
    fr=field_rank_cols(cols,F); br=binary_rank_cols(cols,F)
    assert R < fr <= R+2
    assert fr <= br <= R+2
    assert any(cols[0])
    return {'field_rank':fr,'binary_rank':br,'rows_field':rows,'gamma':gamma,'gamma_order':F.order(gamma),
            'outside_bits':zbits,'column0_nonzero':True,'anchor':anchor,
            'fingerprint':tuple(tuple(c) for c in cols)}

def p_full(t,m):
    if m<t:return Fraction(0,1)
    z=Fraction(1,1)
    for j in range(t): z*=Fraction((1<<m)-(1<<j),1<<m)
    return z

def fixture(N,R,h,poly):
    F=GF2h(h,poly); assert F.q>2*N*R
    T=tuple(range(R+1)); outside=N-(R+1)
    mats=[]; hist=Counter()
    for z in range(1<<outside):
        rec=construct(N,R,F,T,z)
        hist[rec['binary_rank']]+=1; mats.append(rec)
    assert len({m['fingerprint'] for m in mats})==1<<outside
    t=R+3; r=1
    adv=[]
    pt=p_full(t,t)
    for m in mats:
        rho=m['binary_rank']; p=p_full(t,r*rho)
        adv.append(str(pt*(1-p)))
    return {'N':N,'R':R,'field_bits':h,'field_size':F.q,'family_size':1<<outside,
            'binary_rank_histogram':dict(sorted(hist.items())),'all_anchor_zero':True,
            'all_column0_nonzero':True,'t_demo':t,'r_demo':r,
            'rank_event_advantages':sorted(set(adv)),'gamma':mats[0]['gamma'],'gamma_order':mats[0]['gamma_order']}

def main():
    rows=[fixture(3,1,3,0b1011),fixture(4,1,4,0b10011),fixture(5,2,5,0b100101),fixture(6,2,5,0b100101)]
    print(json.dumps({'run':198,'status':'PASS','scope':'characteristic-two finite-difference false family for the binary scalar-descent source; generic-NP false-source attack only', 'fixtures':rows},indent=2,sort_keys=True))

if __name__=='__main__': main()
