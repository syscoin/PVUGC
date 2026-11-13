#!/usr/bin/env python3
import itertools, json, math, random, importlib.util, pathlib

SEED=202609250035
rng=random.Random(SEED)

# Reuse exact committed compiler implementation when run in repo; local fallback for this session.
candidates=[
    pathlib.Path('research/pq-wkem/literature-20260924/rank_field_extensions.py'),
    pathlib.Path('/mnt/data/run82tmp/rank_field_extensions_dependency.py'),
]
for dep in candidates:
    if dep.exists():
        sp=importlib.util.spec_from_file_location('rfe',dep)
        rfe=importlib.util.module_from_spec(sp); sp.loader.exec_module(rfe); break
else:
    raise FileNotFoundError('rank_field_extensions.py dependency not found')

def theta(w,F):
    # Binary-integer label; injective on {0,1}^N whenever p>2^N.
    z=0
    for i,b in enumerate(w):
        if b:
            z=F.add[z][F.integer(1<<i)]
    return z

def qvec(w,F,m):
    th=theta(w,F)
    return [F.pow(th,j) for j in range(m)]

def aug_encode(w,S,m):
    F=S['F']; n=S['N']+1
    base=rfe.reshape(rfe.encode(w,S),n)
    q=qvec(w,F,m)
    out=[]
    for row in base:
        for a in q:
            out.extend(F.mul[a][x] for x in row)
    return out

def split_blocks(vec,S,m):
    n=S['N']+1; ncols=m*n
    M=rfe.reshape(vec,ncols)
    return [[row[j*n:(j+1)*n] for row in M] for j in range(m)]

def aug_advance(vec,i,S,m):
    # i is matrix/Boolean coordinate 1..N, currently zero then set to one.
    F=S['F']; n=S['N']+1
    blocks=[rfe.flatten(B) for B in split_blocks(vec,S,m)]
    advanced=[rfe.advance(B,i,S) for B in blocks]
    d=F.integer(1<<(i-1))
    mixed=[]
    for j in range(m):
        z=[0]*len(advanced[0])
        for k in range(j+1):
            c=F.mul[F.integer(math.comb(j,k))][F.pow(d,j-k)]
            if c:
                z=[F.add[x][F.mul[c][y]] for x,y in zip(z,advanced[k])]
        mixed.append(rfe.reshape(z,n))
    rows=len(mixed[0]); out=[]
    for rr in range(rows):
        for j in range(m): out.extend(mixed[j][rr])
    return out

def aug_constraint_matrix(S,eqs,m):
    N=S['N'];F=S['F']; words=list(itertools.product((0,1),repeat=N))
    base=[rfe.encode(w,S) for w in words]
    n=N+1;stride=n*n;blocks=len(S['ts'])*len(S['aa'])
    Q=[qvec(w,F,m) for w in words]
    rows=[]
    for eq in eqs:
        ev=[eq(w,F) for w in words]
        for hidx in range(blocks):
            hs=[e[hidx*stride] for e in base]
            for j in range(m):
                rows.append([F.mul[F.mul[hs[z]][Q[z][j]]][ev[z]] for z in range(len(words))])
    return words,rows

def aug_table_space(S,eqs,m):
    F=S['F'];words,C=aug_constraint_matrix(S,eqs,m)
    coeffs=rfe.nullspace(C,F,len(words))
    enc=[aug_encode(w,S,m) for w in words]
    basis=rfe.span([rfe.lincomb(enc,c,F) for c in coeffs],F)
    return words,enc,basis,coeffs,C

def base_block_extract(vec,S,eqs,m,R):
    F=S['F']
    for B in split_blocks(vec,S,m):
        if rfe.rank(B,F):
            assert rfe.rank(B,F)<=R
            w,rho=rfe.column_candidates(B,S,eqs)
            return w,rho
    return None,0

def nullity_of_restricted(C,inds,F):
    A=[[row[j] for j in inds] for row in C]
    return len(rfe.nullspace(A,F,len(inds)))

def fd_coeff(N,R,F,T,zbits):
    # Exact Run-82 finite-difference coefficient vector over assignment order.
    words=list(itertools.product((0,1),repeat=N)); pos={w:i for i,w in enumerate(words)}
    s=R+1; outside=[i for i in range(N) if i not in T]; z=dict(zip(outside,zbits))
    c=[0]*len(words)
    for xbits in itertools.product((0,1),repeat=s):
        b=[0]*N
        for i,v in z.items(): b[i]=v
        for i,v in zip(T,xbits): b[i]=v
        qv=F.sub(F.sum(b),N+1); assert qv
        mu=1 if sum(xbits)%2==0 else F.neg[1]
        lam=F.mul[mu][F.inv[qv]]
        c[pos[tuple(b)]]=lam
    return words,c

def vecmat(vec,ncols): return rfe.reshape(vec,ncols)

def enum_minrank(basis,F,ncols):
    hist={}; minr=10**9; total=0
    for c in itertools.product(range(F.q),repeat=len(basis)):
        if not any(c): continue
        A=vecmat(rfe.lincomb(basis,c,F),ncols); rr=rfe.rank(A,F)
        hist[rr]=hist.get(rr,0)+1;minr=min(minr,rr);total+=1
    return minr,hist,total

out={'seed':SEED,'scope':'product-feature source compiler algebra/finite controls only; no PPT/QPT hiding theorem'}

# 1. Incremental exact-span update controls.
trans=0; label_checks=0
for N,R,p,m in [(3,1,11,2),(4,1,17,3),(4,2,19,4)]:
    F=rfe.Field(p); assert p>2**N; S=rfe.spec(N,R,F)
    words=list(itertools.product((0,1),repeat=N))
    labels=[theta(w,F) for w in words]
    assert len(set(labels))==len(words); label_checks+=len(words)
    for i in range(1,N+1):
        # sample partial assignments with later bits zero.
        pres=list(itertools.product((0,1),repeat=i-1))
        if len(pres)>8: pres=rng.sample(pres,8)
        for pre in pres:
            w=pre+(0,)*(N-i+1); ww=list(w);ww[i-1]=1;ww=tuple(ww)
            assert aug_advance(aug_encode(w,S,m),i,S,m)==aug_encode(ww,S,m)
            trans+=1
out['injective_assignment_labels_checked']=label_checks
out['augmented_partial_assignment_transition_checks']=trans

# 2. Generic sparse-support theorem control with NO single equation nonzero everywhere.
# Contradictory system b0=0 and b0=1; for each assignment one equation catches it.
N,R,p,m=3,1,11,3;F=rfe.Field(p);S=rfe.spec(N,R,F)
eqs=[lambda w,F:w[0], lambda w,F:F.sub(w[0],1)]
words,C=aug_constraint_matrix(S,eqs,m)
subset_checks=0
for s in range(1,m+1):
    for inds in itertools.combinations(range(len(words)),s):
        assert nullity_of_restricted(C,inds,F)==0
        subset_checks+=1
out['generic_false_sparse_support_subsets_checked']=subset_checks
out['generic_false_minimum_coefficient_support_lower_bound']=m+1

# 3. Run-82 finite difference vector is rejected once m covers its support.
N,R,p,m=4,1,17,4;F=rfe.Field(p);S=rfe.spec(N,R,F)
eq_false=[lambda w,F,N=N:F.sub(F.sum(w),N+1)]
words,C=aug_constraint_matrix(S,eq_false,m)
words2,c=fd_coeff(N,R,F,(0,1),(0,0)); assert words==words2
support=[i for i,x in enumerate(c) if x]
assert len(support)==2**(R+1)==m
residual=[F.sum(F.mul[a][b] for a,b in zip(row,c)) for row in C]
assert any(residual)
out['run82_sparse_family_rejection']={'N':N,'R':R,'m':m,'support':len(support),'nonzero_constraint_residuals':sum(x!=0 for x in residual)}

# 4. Exhaustive true low-rank extraction inheritance.
N,R,p,m=3,1,11,2;F=rfe.Field(p);S=rfe.spec(N,R,F)
eq_true=[lambda w,F:F.sub(F.add[w[0]][w[1]],1)]
words,enc,basis,coeffs,C=aug_table_space(S,eq_true,m)
low=ext=0
for c in itertools.product(range(p),repeat=len(basis)):
    if not any(c): continue
    vec=rfe.lincomb(basis,c,F);A=vecmat(vec,m*(N+1));rr=rfe.rank(A,F)
    if rr<=R:
        low+=1;w,rho=base_block_extract(vec,S,eq_true,m,R)
        assert w is not None and all(eq(w,F)==0 for eq in eq_true)
        ext+=1
out['exhaustive_true_lowrank_extraction']={'N':N,'R':R,'m':m,'source_dimension':len(basis),'rank_le_R_nonzero':low,'extracted':ext}

# 5. Exact false small-space census: feature lift materially raises minrank in this fixture.
N,R,p,m=4,1,17,3;F=rfe.Field(p);S=rfe.spec(N,R,F)
eq_false=[lambda w,F,N=N:F.sub(F.sum(w),N+1)]
words,enc,basis,coeffs,C=aug_table_space(S,eq_false,m)
assert len(basis)==3
minr,hist,total=enum_minrank(basis,F,m*(N+1))
assert minr==9 and hist=={9:448,10:4464}
out['exact_false_census']={'N':N,'R':R,'p':p,'m':m,'source_dimension':len(basis),'nonzero_matrices':total,'minimum_rank':minr,'rank_histogram':hist}

# 6. Honest witnesses remain rank one and share original block q0=1.
honest=0
for N,R,p,m in [(3,1,11,3),(4,2,19,4)]:
    F=rfe.Field(p);S=rfe.spec(N,R,F)
    for w in itertools.product((0,1),repeat=N):
        A=vecmat(aug_encode(w,S,m),m*(N+1))
        assert rfe.rank(A,F)==1
        B0=split_blocks(rfe.flatten(A),S,m)[0]
        assert rfe.flatten(B0)==rfe.encode(w,S)
        honest+=1
out['honest_rank1_and_base_block_checks']=honest

# 7. Size/field ledger. mfeat=2^(R+1) kills the original Run-82 support.
ledger=[]
for N in [32,64,128,256,512,1024]:
    R=int(math.log2(N)); mfeat=2**(R+1)
    K=(2*N*R+1)*math.comb(2*R,R)
    rows=(N+1)*K; cols=(N+1)*mfeat
    entries=rows*cols
    ledger.append({'N':N,'R':R,'feature_m':mfeat,'base_rows':rows,'aug_columns':cols,'aug_entries':entries,'field_bits_at_least':N+1})
out['size_ledger']=ledger
out['status']='PASS'
print(json.dumps(out,indent=2,sort_keys=True))
