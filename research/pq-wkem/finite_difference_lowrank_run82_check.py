#!/usr/bin/env python3
import itertools, json, math, random, importlib.util, pathlib, sys
from fractions import Fraction

SEED=202609242215
rng=random.Random(SEED)

# Reuse the exact committed compiler checker module when run in the repo; fall back
# to the copy packaged beside this script for the local artifact.
candidates=[
    pathlib.Path('research/pq-wkem/literature-20260924/rank_field_extensions.py'),
    pathlib.Path(__file__).with_name('rank_field_extensions_dependency.py'),
    pathlib.Path('/mnt/data/deepdive/rank_field_extensions.py'),
]
for dep in candidates:
    if dep.exists():
        spec=importlib.util.spec_from_file_location('rfe',dep)
        rfe=importlib.util.module_from_spec(spec); spec.loader.exec_module(rfe); break
else:
    raise FileNotFoundError('rank_field_extensions.py dependency not found')

def det(A,F):
    A=[row[:] for row in A]; n=len(A); out=1
    for c in range(n):
        k=next((i for i in range(c,n) if A[i][c]),None)
        if k is None:return 0
        if k!=c:
            A[c],A[k]=A[k],A[c]; out=F.neg[out]
        piv=A[c][c]; out=F.mul[out][piv]; iv=F.inv[piv]
        for i in range(c+1,n):
            if A[i][c]:
                f=F.mul[A[i][c]][iv]
                A[i]=[F.sub(x,F.mul[f][y]) for x,y in zip(A[i],A[c])]
    return out

def mtrans(A):return [list(x) for x in zip(*A)]
def mmul(A,B,F):
    Bt=mtrans(B)
    return [[F.sum(F.mul[x][y] for x,y in zip(row,col)) for col in Bt] for row in A]
def eye(n):return [[int(i==j) for j in range(n)] for i in range(n)]
def shift(A,k,F):return [[F.add[A[i][j]][k if i==j else 0] for j in range(len(A))] for i in range(len(A))]
def roots(A,F):
    n=len(A); I=eye(n); out=[]
    for lam in range(F.q):
        M=[[F.sub(A[i][j], lam if i==j else 0) for j in range(n)] for i in range(n)]
        if det(M,F)==0:out.append(lam)
    return out

def alternating_formula(F,s,a):
    # sum_{j=0}^s (-1)^j C(s,j)/(j-a)
    num=F.integer(math.factorial(s)); den=1
    for j in range(s+1):den=F.mul[den][F.integer(a-j)]
    sign=F.neg[1] if (s+1)%2 else 1
    return F.mul[sign][F.mul[num][F.inv[den]]]

def free_column_formula(F,s,a):
    # sum_x (-1)^|x| x_1/(|x|-a) = -F_{s-1}(a-1)
    num=F.integer(math.factorial(s-1)); den=1
    for j in range(1,s+1):den=F.mul[den][F.integer(a-j)]
    sign=F.neg[1] if (s+1)%2 else 1
    return F.mul[sign][F.mul[num][F.inv[den]]]

def fd_codeword(N,R,p,T,zbits):
    F=rfe.Field(p); S=rfe.spec(N,R,F); s=R+1; T=tuple(T)
    outside=[i for i in range(N) if i not in T]
    assert len(zbits)==len(outside)
    z=dict(zip(outside,zbits))
    zero=(0,)*N; vec=[0]*len(rfe.encode(zero,S)); terms=[]
    for xbits in itertools.product((0,1),repeat=s):
        b=[0]*N
        for i,bit in z.items():b[i]=bit
        for i,bit in zip(T,xbits):b[i]=bit
        qv=F.sub(F.sum(b),N+1)
        assert qv!=0
        mu=1 if sum(xbits)%2==0 else F.neg[1]
        lam=F.mul[mu][F.inv[qv]]
        enc=rfe.encode(tuple(b),S)
        vec=[F.add[v][F.mul[lam][e]] for v,e in zip(vec,enc)]
        terms.append((tuple(b),lam,qv))
    A=rfe.reshape(vec,N+1)
    return F,S,A,vec,terms

def check_constraints(F,S,terms,N):
    # For every actual listed weight block, verify sum lambda*h(b)*q(b)=0.
    n=N+1; stride=n*n; enc_cache={b:rfe.encode(b,S) for b,_,_ in terms}
    blocks=len(S['ts'])*len(S['aa'])
    for hidx in range(blocks):
        z=0
        for b,lam,qv in terms:
            h=enc_cache[b][hidx*stride] # top-left is h(b)
            z=F.add[z][F.mul[lam][F.mul[h][qv]]]
        assert z==0

def solve_coords(B,target,F):
    # Solve sum_i c_i B_i = target using pivot coordinates of basis rows.
    k=len(B); cols=len(B[0])
    # Pick k independent coordinate columns of B (equiv. pivot columns of row basis).
    _,piv=rfe.rref(B,F)
    assert len(piv)==k
    A=[[B[i][j] for i in range(k)]+[target[j]] for j in piv]
    R,p=rfe.rref(A,F)
    # left kxk is invertible, rref becomes [I|c]
    assert p[:k]==list(range(k))
    c=[R[i][k] for i in range(k)]
    rec=rfe.lincomb(B,c,F)
    assert rec==target
    return c

def dot_dist(q,rho,r):
    # Exact q-ary symmetric distribution for sum of r independent dot products.
    eps=Fraction(1,q**(r*rho))
    high=Fraction(1,q)+Fraction(q-1,q)*eps
    low=Fraction(1,q)-Fraction(1,q)*eps
    return eps,high,low

out={'seed':SEED,'scope':'actual Hair-Sahai source-space finite-difference algebra and explicit candidate attacks; no QPT-hardness proof'}

reports=[]; distinct_total=0; coordinate_checks=0
params=[(3,1,7),(4,2,19),(5,2,23),(6,2,29),(8,3,67)]
for N,R,p in params:
    s=R+1;T=tuple(range(s));outside=N-s
    zlist=list(itertools.product((0,1),repeat=outside))
    seen={}; ranks={}; anchors={}
    for zbits in zlist:
        F,S,A,vec,terms=fd_codeword(N,R,p,T,zbits)
        check_constraints(F,S,terms,N)
        rr=rfe.rank(A,F); assert R<rr<=R+2
        w=sum(zbits); a=N+1-w
        anch=A[0][0]
        assert anch==alternating_formula(F,s,a)!=0
        # every free column has the closed-form nonzero constant-block row-0 entry
        n=N+1; const=A[:n]
        fc=free_column_formula(F,s,a); assert fc!=0
        for j in T: assert const[0][j+1]==fc
        # fixed outside columns are exactly 0 or column 0 in the whole stack
        c0=[row[0] for row in A]
        outside_idx=[i for i in range(N) if i not in T]
        for j,bit in zip(outside_idx,zbits):
            cj=[row[j+1] for row in A]
            assert cj==(c0 if bit else [0]*len(A))
        flat=tuple(vec); assert flat not in seen; seen[flat]=zbits
        ranks[rr]=ranks.get(rr,0)+1; anchors[anch]=anchors.get(anch,0)+1
        # On small cases, independently compute public-basis coordinates.
        if N<=4:
            eqs=[lambda w,F,N=N:F.sub(F.sum(w),N+1)]
            _,_,B=rfe.table_space(S,eqs)
            c=solve_coords(B,vec,F)
            ell=[row[0] for row in B]
            assert F.sum(F.mul[x][y] for x,y in zip(c,ell))==anch
            coordinate_checks+=1
    assert len(seen)==2**outside
    distinct_total+=len(seen)
    reports.append({'N':N,'R':R,'p':p,'free_dimension':s,'fixed_assignments':2**outside,
                    'distinct_codewords':len(seen),'rank_histogram':ranks,'anchor_values':len(anchors),
                    'theorem_count_lower_bound':2**(N-R-1)})
out['finite_difference_family']=reports
out['distinct_codewords_checked_total']=distinct_total
out['public_basis_coordinate_reconstructions']=coordinate_checks

# Exact scalar distinguisher on N=2,R=1,p=7: codeword rank is 3.
N,R,p=2,1,7;F,S,A,vec,terms=fd_codeword(N,R,p,(0,1),())
rho=rfe.rank(A,F);assert rho==3
# enumerate one dot product in rho dimensions
cnt=[0]*p
for u in itertools.product(range(p),repeat=rho):
    for v in itertools.product(range(p),repeat=rho):
        z=sum(x*y for x,y in zip(u,v))%p;cnt[z]+=1
tot=p**(2*rho);eps,hi,lo=dot_dist(p,rho,1)
assert Fraction(cnt[0],tot)==hi
for z in range(1,p):assert Fraction(cnt[z],tot)==lo
# P_K and P_K' are translates: exact TV = eps.
out['exact_scalar_distinguisher']={'q':p,'rho':rho,'r':1,'epsilon':[eps.numerator,eps.denominator],
    'p_zero':[hi.numerator,hi.denominator],'p_nonzero':[lo.numerator,lo.denominator],
    'pairwise_key_shift_TV':[eps.numerator,eps.denominator]}

# False pseudo-witness common-eigenvalue attack simulation using a real N=4,R=2 family member (rho=4).
N,R,p=4,2,19;F,S,A,vec,terms=fd_codeword(N,R,p,(0,1,2),(0,))
rho=rfe.rank(A,F); assert rho==4

def randmat(rows,cols,F):return [[rng.randrange(F.q) for _ in range(cols)] for __ in range(rows)]
def uv(rows,inner,F):
    U=randmat(rows,inner,F);V=randmat(rows,inner,F);return mmul(U,[[V[j][i] for j in range(rows)] for i in range(inner)],F)

def trial(t,inner,trials):
    miss=amb=0
    for _ in range(trials):
        K=rng.randrange(F.q); X1=uv(t,inner,F);X2=uv(t,inner,F)
        D1=shift(X1,K,F);D2=shift(X2,K,F)
        common=set(roots(D1,F))&set(roots(D2,F))
        miss+=K not in common; amb+=common!={K}
    return {'t':t,'inner_rank_factor':inner,'trials':trials,'missing_true_shift':miss,'ambiguous_or_missing':amb}
attack=trial(5,rho,900) # r=1, r*rho=4 < 5
control=trial(4,rho,400) # boundary r*rho=t: no guaranteed zero eigenvalue
assert attack['missing_true_shift']==0 and control['missing_true_shift']>0
out['false_pseudowitness_common_eigenvalue']={'source_N':N,'source_R':R,'source_rank':rho,'q':p,
                                              'vulnerable_t5_r1':attack,'boundary_t4_r1_control':control}

# Parameter/spectral necessary-condition ledger.
rows=[]
for N in [64,128,256,512,1024,4096,16384]:
    R=int(math.log2(N));Mbits=N-R-1
    for qbits in [16,32,64,128]:
        # single-character 2^-128 necessary condition and exact-spectral-mass criterion <=2^-256
        r_char=math.ceil(128/((R+2)*qbits))
        r_mass=math.ceil((Mbits+256)/(2*(R+2)*qbits))
        rows.append({'N':N,'R':R,'qbits':qbits,'log2_lowrank_family':Mbits,
                     'min_r_single_character_128bit':r_char,
                     'min_r_for_lowrank_spectral_submass_le_2^-256':r_mass})
out['parameter_necessary_conditions']=rows
out['status']='PASS'
print(json.dumps(out,indent=2,sort_keys=True))
