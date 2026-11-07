"""Bounded exact checks for normalized QAP-to-spectral SOURCE coupling.
No cryptographic-security claim; deterministic test coins are not production RNG.
Run: OPENBLAS_NUM_THREADS=1 python check.py
"""
from __future__ import annotations
import hashlib,itertools,json,math
from pathlib import Path
import numpy as np
import sympy as sp
from sympy.polys.matrices import DomainMatrix
import qap_coupling as e
COUNT=0

def require(condition:bool,message:str)->None:
    global COUNT
    COUNT+=1
    if not bool(condition):raise AssertionError(message)

def linear_eval(forms,y):
    # Shapes: (gate, coefficient, four source forms).
    return np.einsum('gvf,v->gf',forms,y)%e.P

def valid_values(forms,y):
    z=linear_eval(forms,y)
    return bool(np.all((z[:,0]*z[:,1]-z[:,2]*z[:,3])%e.P==0))

def field_roots(matrix):
    dm=DomainMatrix.from_Matrix(sp.Matrix(matrix.tolist())).convert_to(sp.GF(e.P))
    x=sp.Symbol('x')
    coeff=[int(a)%e.P for a in dm.charpoly()]
    _,factors=sp.factor_list(sp.Poly.from_list(coeff,x,modulus=e.P))
    roots=[]
    for fac,_ in factors:
        if fac.degree()==1:
            a,b=map(int,fac.all_coeffs());roots.append((-b*pow(a%e.P,-1,e.P))%e.P)
    return sorted(set(roots))

def public_pencil(public,block,indices):
    a,c,d=indices;Q=e.inv(public[a]);A=e.mm(Q,public[c]);B=e.mm(Q,public[d]);T=e.mm(Q,public[0])
    if block==1:return e.comm(T,A),e.comm(Q,A)
    S=e.comm(A,B);H=e.mm(S,S)
    return e.comm(H,T),e.comm(H,Q)

def test_compiler():
    results=[]
    for p,n in ((7,1),(11,2)):
        e.P=p
        for target in (1,n+1):
            A,B,C=e.family(n,target);co=e.compile_qap(A,B,C)
            original=e.original_forms(A,B,C);m=n+1;L=2*m-1
            points=co['points'];require(len(set(points+co['nodes']))==L+m,'distinct disjoint points')
            require(e.rank(np.concatenate([A[:,1:],B[:,1:]],axis=0))==n,'injective input forms')
            accepted=0;originals=set()
            for vals in itertools.product(range(p),repeat=n+m-1):
                y=np.array([1]+list(vals),dtype=np.int64)
                truth=valid_values(co['forms'],y)
                if truth:
                    accepted+=1;originals.add(tuple(vals[:n]))
                    require(valid_values(original,y[:n+1]),'compiled acceptance extracts original')
            expected={w for w in itertools.product(range(p),repeat=n) if valid_values(original,np.array([1]+list(w),dtype=np.int64))}
            require(originals==expected,'all-original completeness and soundness')
            require(accepted==len(expected),'unique quotient extension')
            for w in expected:require(valid_values(co['forms'],e.encode(co,w)),'encode exact quotient')
            results.append(dict(q=p,variables=n,constraints=m,compiled_gates=L,assignments=p**(n+m-1),accepted=accepted))
    e.P=65537
    return results

def test_all_direction_support():
    e.P=7
    A,B,C=e.family(1,2);co=e.compile_qap(A,B,C);forms=co['forms'];minimum=99
    for vals in itertools.product(range(7),repeat=forms.shape[1]):
        if not any(vals):continue
        y=np.array(vals,dtype=np.int64);z=linear_eval(forms,y)
        support=int(np.count_nonzero(np.any(z!=0,axis=1)));minimum=min(minimum,support)
        require(support>=2,'all-direction source support lower bound')
        ranks=sum(e.rank(e.gate(*map(int,row),np.zeros((1,1),dtype=np.int64))) for row in z)
        require(ranks>=2*support,'typed-source preprojection rank lower bound')
    e.P=65537
    return dict(q=7,directions=7**3-1,minimum_support=minimum,theoretical_lower_bound=2)

def test_random_product_tail():
    # Exhaustive F2 products: validates stated loose tail, not a hardness test.
    e.P=2;N=3;r=2;threshold=1
    mats=[np.array(v,dtype=np.int64).reshape(N,r) for v in itertools.product(range(2),repeat=N*r)]
    bad=sum(e.rank(e.mm(U,V.T))<threshold for U in mats for V in mats)
    require(bad==274,'exact 4096-product rank census')
    e.P=65537
    return dict(q=2,N=N,r=r,products=len(mats)**2,rank_below_one=bad)

def test_honest_recovery():
    e.P=65537;n=3;A,B,C=e.family(n,1);co=e.compile_qap(A,B,C);key=12345
    rows=[]
    for block in (1,2):
        public,source=e.setup(co['forms'],block,seed=100+block,key=key);N=public.shape[1]
        hashes=[];roots_records=[]
        for w in itertools.product((0,1),repeat=n):
            if sum(w)!=1:continue
            y=e.encode(co,w);require(valid_values(co['forms'],y),'honest QAP acceptance')
            M=sum((int(a)*mat for a,mat in zip(y,public)),start=np.zeros((N,N),dtype=np.int64))%e.P
            require(e.rank((M-key*np.eye(N,dtype=np.int64))%e.P)<N,'same key eigenvalue')
            roots=field_roots(M);require(key in roots,'algebraic root recovery')
            tag=hashlib.sha256(b'toy-qap-capability:'+key.to_bytes(4,'big')).digest()
            selected=[k for k in roots if hashlib.sha256(b'toy-qap-capability:'+k.to_bytes(4,'big')).digest()==tag]
            require(selected==[key],'toy exact-key selector')
            roots_records.append(dict(witness=list(w),roots=roots))
            hashes.append(hashlib.sha256(M.tobytes()).hexdigest())
        require(len(set(hashes))==3,'different valid-witness matrices retained')
        rows.append(dict(block=block,N=N,witnesses=3,matrices=3,root_recovery=roots_records))
    return rows

def test_public_regressions():
    e.P=65537;rows=[]
    for block in (1,2):
        # Normalized R1CS control differs from the prior projective four-form attack family.
        # It is NOT a positive attack control; do not infer that QAP alone defeated that attack.
        n=7;A,B,C=e.family(n,n+1);co=e.compile_qap(A,B,C);original=e.original_forms(A,B,C)
        for seed in (3,7):
            for label,forms in (('normalized_r1cs_control',original),('coupled_qap',co['forms'])):
                public,E=e.setup(forms,block,seed,key=12345);N=public.shape[1]
                probes=[]
                for ids in ((1,2,3),(2,3,4),(3,4,5)):
                    try:F0,F1=public_pencil(public,block,ids)
                    except ValueError:
                        probes.append(dict(indices=list(ids),status='singular_pivot'));continue
                    dr=e.rank(F1);kr=e.rank((F0-12345*F1)%e.P)
                    probes.append(dict(indices=list(ids),denominator_rank=dr,key_pencil_rank=kr,key_is_root=bool(dr==N and kr<N)))
                if label=='coupled_qap':require(all(z.get('key_pencil_rank')==N for z in probes),'specified three probes do not expose key')
                # Adaptive density diagnostics are NOT the proof: scan fixed reproducible combinations.
                rng=np.random.default_rng(seed+2000);rr=[];ss=[]
                for _ in range(12):
                    v=rng.integers(0,e.P,forms.shape[1],dtype=np.int64);v[0]=0
                    value=np.zeros((N,N),dtype=np.int64)
                    for a,mat in zip(v,E):value=(value+int(a)*mat)%e.P
                    rr.append(e.rank(value));ss.append(int(np.count_nonzero(np.any(linear_eval(forms,v)!=0,axis=1))))
                rows.append(dict(compiler=label,block=block,seed=seed,original_constraints=n+1,gates=len(forms),N=N,coefficients=forms.shape[1],probes=probes,min_sample_source_rank=min(rr),min_sample_source_support=min(ss)))
    return rows

def resource_examples():
    rows=[]
    for n,m,b in ((29,30,1),(29,30,2),(11000,16000,1)):
        L=2*m-1;N=2*b*L+1;k=n+m
        orig=(n+1)*(2*b*m+1)**2;new=k*N*N
        # q >= 2^256 assumed only for arithmetic example, not an instantiation or security claim.
        e_margin=math.isqrt(k+1)
        while 3+256*(k-(e_margin+1)**2)>-128:e_margin+=1
        r0=2*b*(L-m+1)
        rows.append(dict(n=n,m=m,block=b,L=L,N=N,coefficients=k,original_field_elements=orig,new_field_elements=new,
           payload_ratio=new/orig,density_e=e_margin,simultaneous_source_rank_lower=r0-2*e_margin,
           density_failure_log2_upper=3+256*(k-(e_margin+1)**2)))
    return rows

def main():
    result={'checkpoint':'qap-source-coupling-20261022','scope':'Normalized SOURCE compiler and structural rank lemma only; NO QPT release security proof.',
       'compiler':test_compiler(),'direction_support':test_all_direction_support(),'random_product_census':test_random_product_tail(),
       'honest_recovery':test_honest_recovery(),'public_regressions':test_public_regressions(),'resource_examples':resource_examples()}
    result['assertions']=COUNT
    print(json.dumps(result,sort_keys=True,separators=(',',':')))

if __name__=='__main__':main()
