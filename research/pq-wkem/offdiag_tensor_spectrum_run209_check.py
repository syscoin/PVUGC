#!/usr/bin/env python3
from itertools import product
from collections import Counter
from fractions import Fraction
import json

ASSERTIONS=0

def check(x,msg='assertion failed'):
    global ASSERTIONS
    ASSERTIONS += 1
    if not x:
        raise AssertionError(msg)

class GF2h:
    def __init__(self,h,poly): self.h=h; self.q=1<<h; self.poly=poly
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
    def order(self,a):
        z=1
        for k in range(1,self.q):
            z=self.mul(z,a)
            if z==1:return k
        raise AssertionError

def alphas(R): return [a for a in product(range(R+1),repeat=R) if sum(a)<=R]
def choose_gamma(F,N): return next(a for a in range(2,F.q) if F.order(a)>N)

def weights_for_word(word,N,R,F,gamma):
    v=[1]+[(word>>i)&1 for i in range(N)]
    out=[]
    for tau in range(2*N*R+1):
        forms=[]
        for j in range(R):
            g=F.mul(F.pow(gamma,j),tau)
            ell=0
            for i,bi in enumerate(v):
                if bi: ell ^= F.pow(g,i)
            forms.append(ell)
        for alpha in alphas(R):
            h=1
            for e,x in zip(alpha,forms): h=F.mul(h,F.pow(x,e))
            out.append(h)
    return v,out

def assignment_cols(word,N,R,F,gamma):
    v,weights=weights_for_word(word,N,R,F,gamma)
    n=N+1; rows=len(weights)*n
    cols=[[0]*rows for _ in range(n)]
    row=0
    for h in weights:
        for i,vi in enumerate(v):
            if vi:
                for j,vj in enumerate(v):
                    if vj: cols[j][row+i] ^= h
        row += n
    return cols

def xor_field_cols(A,B): return [[x^y for x,y in zip(a,b)] for a,b in zip(A,B)]

def cube_cols(N,R,F,T,zbits):
    gamma=choose_gamma(F,N); s=R+1
    outside=[i for i in range(N) if i not in T]
    acc=None
    for xbits in range(1<<s):
        word=0
        for k,i in enumerate(T):
            if (xbits>>k)&1: word |= 1<<i
        for k,i in enumerate(outside):
            if (zbits>>k)&1: word |= 1<<i
        C=assignment_cols(word,N,R,F,gamma)
        if acc is None: acc=C
        else: acc=xor_field_cols(acc,C)
    return acc

def descend_cols(cols,F):
    out=[]
    for col in cols:
        bits=0; pos=0
        for x in col:
            for k in range(F.h):
                if (x>>k)&1: bits |= 1<<pos
                pos += 1
        out.append(bits)
    return out, len(cols[0])*F.h

def rank_bitcols(cols):
    piv={}
    for v0 in cols:
        v=v0
        while v:
            k=v.bit_length()-1
            if k in piv: v ^= piv[k]
            else: piv[k]=v; break
    return len(piv)

def rank_bitrows(rows):
    return rank_bitcols(rows)

def basis_from_cube(N,R,h,poly):
    F=GF2h(h,poly); check(F.q>2*N*R)
    T=tuple(range(R+1)); outside=[i for i in range(N) if i not in T]
    A0f=cube_cols(N,R,F,T,0)
    A0,nrows=descend_cols(A0f,F)
    basis=[A0]
    for j in range(len(outside)):
        Ajf=cube_cols(N,R,F,T,1<<j)
        Df=xor_field_cols(Ajf,A0f)
        D,_=descend_cols(Df,F)
        basis.append(D)
    d=len(basis); s=R+1
    check(d==N-R)
    check(all(rank_bitcols(B)==s+1 for B in basis), 'basis ranks')
    # every nonzero combination should have exact rank s+1
    for mask in range(1,1<<d):
        cols=[0]*len(basis[0])
        for a,B in enumerate(basis):
            if (mask>>a)&1:
                cols=[x^y for x,y in zip(cols,B)]
        check(rank_bitcols(cols)==s+1, f'codeword rank mask={mask}')
    return basis,nrows,s,d

def assemble_rank(basis,nrows,t,coeff_masks):
    # coeff_masks[p][q] is d-bit coefficient vector.
    d=len(basis); ncols=len(basis[0]); outcols=[]
    for q in range(t):
        for j in range(ncols):
            col=0
            for p in range(t):
                block=0; mask=coeff_masks[p][q]
                for a in range(d):
                    if (mask>>a)&1: block ^= basis[a][j]
                col |= block << (p*nrows)
            outcols.append(col)
    return rank_bitcols(outcols)

def flatten_ranks(coeff_masks,d,t):
    # H: rows p, columns (q,a)
    H=[]
    for p in range(t):
        row=0; pos=0
        for q in range(t):
            mask=coeff_masks[p][q]
            for a in range(d):
                if (mask>>a)&1: row |= 1<<pos
                pos+=1
        H.append(row)
    a_rank=rank_bitrows(H)
    # G: columns q, rows (p,a), encode each column q as bit vector
    G=[]
    for q in range(t):
        col=0; pos=0
        for p in range(t):
            mask=coeff_masks[p][q]
            for a in range(d):
                if (mask>>a)&1: col |= 1<<pos
                pos+=1
        G.append(col)
    b_rank=rank_bitcols(G)
    return a_rank,b_rank

def gauss_binom(n,k):
    if k<0 or k>n:return 0
    num=1; den=1
    for i in range(k):
        num *= (2**n-2**i)
        den *= (2**k-2**i)
    return num//den

def mobius_codim(k): return (-1)**k * (2**(k*(k-1)//2))

def concise_count(a,b,d):
    z=0
    for i in range(a+1):
        for j in range(b+1):
            z += gauss_binom(a,i)*gauss_binom(b,j)*mobius_codim(a-i)*mobius_codim(b-j)*(2**(i*j*d))
    return z

def tensor_rank_count(t,d,a,b):
    return gauss_binom(t,a)*gauss_binom(t,b)*concise_count(a,b,d)

def coeff_from_int(x,t,d):
    C=[[0]*t for _ in range(t)]
    pos=0
    for p in range(t):
        for q in range(t):
            mask=0
            for a in range(d):
                if (x>>pos)&1: mask |= 1<<a
                pos+=1
            C[p][q]=mask
    return C

def fraction_pow2_neg(k): return Fraction(1,1<<k)

def fixture(N,R,h,poly,t=2):
    basis,nrows,s,d=basis_from_cube(N,R,h,poly)
    total_bits=t*t*d
    check(total_bits<=14,'fixture too large')
    hist=Counter(); rank_hist=Counter(); chi_enum=Fraction(0,1)
    r=1
    for x in range(1,1<<total_bits):
        C=coeff_from_int(x,t,d)
        a,b=flatten_ranks(C,d,t)
        rr=assemble_rank(basis,nrows,t,C)
        expect=s*b+a
        check(rr==expect,f'assembled rank mismatch x={x}: {rr}!={expect}, a={a},b={b}')
        hist[(a,b)]+=1; rank_hist[rr]+=1
        chi_enum += fraction_pow2_neg(2*r*rr)
    # exact joint mode-rank counts by q-Mobius inversion
    formula_total=0; chi_formula=Fraction(0,1); count_rows={}
    for a in range(1,t+1):
        for b in range(1,t+1):
            cnt=tensor_rank_count(t,d,a,b)
            formula_total += cnt
            count_rows[f'{a},{b}']=cnt
            check(cnt==hist[(a,b)],f'count mismatch {(a,b)} {cnt}!={hist[(a,b)]}')
            chi_formula += Fraction(cnt,1<< (2*r*(s*b+a)))
    check(formula_total==(1<<total_bits)-1)
    check(chi_formula==chi_enum)
    # Run-197 slice control: coefficient tensor lambda_{pq}*c has rank (s+1)rank(lambda)
    c=1
    for lam in range(1,1<<(t*t)):
        C=[[0]*t for _ in range(t)]; rows=[]
        pos=0
        for p in range(t):
            row=0
            for q in range(t):
                bit=(lam>>pos)&1; pos+=1
                if bit:
                    C[p][q]=c; row |= 1<<q
            rows.append(row)
        lr=rank_bitrows(rows)
        a,b=flatten_ranks(C,d,t)
        rr=assemble_rank(basis,nrows,t,C)
        check(a==lr and b==lr)
        check(rr==(s+1)*lr)
    return {
        'N':N,'R':R,'s':s,'d':d,'t':t,'source_rows_binary':nrows,
        'nonzero_character_count':(1<<total_bits)-1,
        'joint_mode_rank_histogram':{f'{a},{b}':n for (a,b),n in sorted(hist.items())},
        'assembled_rank_histogram':dict(sorted(rank_hist.items())),
        'chi_square_r1':str(chi_formula),
        'chi_square_r1_float':float(chi_formula),
        'mobius_count_sum':formula_total,
    }

def main():
    rows=[fixture(4,1,4,0b10011,2),fixture(5,2,5,0b100101,2)]
    out={
        'run':209,
        'status':'PASS',
        'assertions':ASSERTIONS,
        'scope':'exact off-diagonal coefficient-tensor rank spectrum for the characteristic-two cube code; generic false-source family only',
        'fixtures':rows,
    }
    print(json.dumps(out,indent=2,sort_keys=True))

if __name__=='__main__': main()
