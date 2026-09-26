#!/usr/bin/env python3
import itertools, json, math, random, importlib.util, pathlib

SEED=202609250117
rng=random.Random(SEED)

candidates=[
    pathlib.Path('research/pq-wkem/literature-20260924/rank_field_extensions.py'),
    pathlib.Path('/mnt/data/run84/rank_field_extensions_dependency.py'),
]
for dep in candidates:
    if dep.exists():
        sp=importlib.util.spec_from_file_location('rfe',dep)
        rfe=importlib.util.module_from_spec(sp); sp.loader.exec_module(rfe); break
else:
    raise FileNotFoundError('rank_field_extensions.py dependency not found')

def theta(w,F):
    z=0
    for i,b in enumerate(w):
        if b: z=F.add[z][F.integer(1<<i)]
    return z

def qvec(w,F,m):
    th=theta(w,F)
    return [F.pow(th,j) for j in range(m)]

def aug_encode(w,S,m):
    F=S['F']; n=S['N']+1
    base=rfe.reshape(rfe.encode(w,S),n)
    q=qvec(w,F,m); out=[]
    for row in base:
        for a in q:
            out.extend(F.mul[a][x] for x in row)
    return out


def split_blocks(vec,S,m):
    n=S['N']+1; ncols=m*n
    M=rfe.reshape(vec,ncols)
    return [[row[j*n:(j+1)*n] for row in M] for j in range(m)]

def aug_advance(vec,i,S,m):
    # Exact linear update for flipping Boolean coordinate i from 0 to 1.
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

def generalized_fd_dp_vec(N,R,m,F,S,T,zbits):
    # Polynomial-time dynamic program: aggregate all 2^(R+m) assignments by
    # Hamming weight without enumerating them. Uses only public linear update maps.
    s=R+m; assert len(T)==s and s<=N
    outside=[i for i in range(N) if i not in T]; assert len(zbits)==len(outside)
    cur=aug_encode((0,)*N,S,m)
    for idx,bit in zip(outside,zbits):
        if bit: cur=aug_advance(cur,idx+1,S,m)
    D=[cur]+[[0]*len(cur) for _ in range(s)]
    processed=0
    for idx in T:
        new=[[0]*len(cur) for _ in range(s+1)]
        for k in range(processed+1):
            new[k]=[F.add[a][b] for a,b in zip(new[k],D[k])]
            adv=aug_advance(D[k],idx+1,S,m)
            new[k+1]=[F.add[a][b] for a,b in zip(new[k+1],adv)]
        D=new; processed+=1
    w=sum(zbits); out=[0]*len(cur)
    for k in range(s+1):
        f=F.sub(F.integer(k+w),F.integer(N+1)); assert f
        mu=1 if k%2==0 else F.neg[1]
        lam=F.mul[mu][F.inv[f]]
        out=[F.add[a][F.mul[lam][b]] for a,b in zip(out,D[k])]
    return out

def aug_constraint_matrix(S,eqs,m):
    N=S['N'];F=S['F']; words=list(itertools.product((0,1),repeat=N))
    base=[rfe.encode(w,S) for w in words]
    n=N+1; stride=n*n; blocks=len(S['ts'])*len(S['aa'])
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
    F=S['F']; words,C=aug_constraint_matrix(S,eqs,m)
    coeffs=rfe.nullspace(C,F,len(words))
    enc=[aug_encode(w,S,m) for w in words]
    basis=rfe.span([rfe.lincomb(enc,c,F) for c in coeffs],F)
    return words,enc,basis,coeffs,C

def generalized_fd_coeff(N,R,m,F,T,zbits):
    s=R+m
    assert len(T)==s and s<=N
    words=list(itertools.product((0,1),repeat=N)); pos={w:i for i,w in enumerate(words)}
    outside=[i for i in range(N) if i not in T]; assert len(zbits)==len(outside)
    z=dict(zip(outside,zbits)); c=[0]*len(words)
    for xb in itertools.product((0,1),repeat=s):
        b=[0]*N
        for i,v in z.items(): b[i]=v
        for i,v in zip(T,xb): b[i]=v
        f=F.sub(F.sum(b),N+1)
        assert f
        mu=1 if sum(xb)%2==0 else F.neg[1]
        c[pos[tuple(b)]]=F.mul[mu][F.inv[f]]
    return words,c

def anchor_closed_form(N,s,w,F):
    # (-1)^(s+1) s!/[a(a-1)...(a-s)], a=N+1-w.
    a=N+1-w
    num=F.integer(math.factorial(s))
    if (s+1)%2: num=F.neg[num]
    den=1
    for j in range(s+1):
        den=F.mul[den][F.integer(a-j)]
    assert den
    return F.mul[num][F.inv[den]]

def enumerate_source_hist(basis,F,ncols):
    hist={}; total=0; minr=10**9
    for cc in itertools.product(range(F.q),repeat=len(basis)):
        if not any(cc): continue
        A=rfe.reshape(rfe.lincomb(basis,cc,F),ncols)
        rr=rfe.rank(A,F); hist[rr]=hist.get(rr,0)+1; minr=min(minr,rr); total+=1
    return (None if total==0 else minr),hist,total

out={
    'seed':SEED,
    'scope':'generalized finite-difference attack on product-feature lift; finite algebra only; no cryptographic security inferred'
}

# A. Exact generalized finite-difference family in several actual product-feature spaces.
cases=[]; total_members=0
for N,R,m,p in [
    (3,1,1,11),(3,1,2,11),
    (4,1,2,17),(4,1,3,17),
    (5,1,2,37),(5,1,3,37),
    (6,2,2,67),(6,2,3,67),
    (7,2,3,131),
]:
    if R+m>N: continue
    F=rfe.Field(p); assert p>2**N; S=rfe.spec(N,R,F)
    eqs=[lambda w,F,N=N:F.sub(F.sum(w),N+1)]
    words,C=aug_constraint_matrix(S,eqs,m); enc=[aug_encode(w,S,m) for w in words]
    s=R+m; T=tuple(range(s)); outside=N-s
    ranks=[]; anchors=[]; supports=[]; vecs=[]
    for zb in itertools.product((0,1),repeat=outside):
        ww,c=generalized_fd_coeff(N,R,m,F,T,zb); assert ww==words
        residual=[F.sum(F.mul[a][b] for a,b in zip(row,c)) for row in C]
        assert not any(residual)
        support=sum(x!=0 for x in c); assert support==2**s
        vec=rfe.lincomb(enc,c,F)
        dpvec=generalized_fd_dp_vec(N,R,m,F,S,T,zb)
        assert dpvec==vec
        A=rfe.reshape(vec,m*(N+1)); rr=rfe.rank(A,F)
        assert rr<=m*(s+1)
        anchor=F.sum(c); assert anchor!=0
        assert anchor==anchor_closed_form(N,s,sum(zb),F)
        ranks.append(rr);anchors.append(anchor);supports.append(support);vecs.append(tuple(vec))
        total_members+=1
    assert len(set(vecs))==2**outside
    cases.append({
        'N':N,'R':R,'m':m,'p':p,'s_free':s,
        'family_size':2**outside,'support_each':2**s,
        'rank_bound_m_times_splus1':m*(s+1),
        'polynomial_dp_matches_enumeration':True,
        'observed_ranks':ranks,'anchors_nonzero':all(a!=0 for a in anchors),
    })
out['generalized_fd_cases']=cases
out['generalized_fd_members_checked']=total_members

# B. Exact small census across m=1,2,3 on the same false N=3,R=1 instance.
N,R,p=3,1,11; F=rfe.Field(p); S=rfe.spec(N,R,F)
eqs=[lambda w,F,N=N:F.sub(F.sum(w),N+1)]
census=[]
for m in (1,2,3):
    words,enc,basis,coeffs,C=aug_table_space(S,eqs,m)
    assert len(basis)<=4
    minr,hist,total=enumerate_source_hist(basis,F,m*(N+1))
    census.append({'m':m,'source_dimension':len(basis),'nonzero_matrices':total,
                   'minimum_rank':minr,'rank_histogram':hist})
assert census[0]['source_dimension']==4 and census[0]['minimum_rank']==3
assert census[1]['source_dimension']==1 and census[1]['minimum_rank']==6
assert census[2]['source_dimension']==0 and census[2]['nonzero_matrices']==0
out['exact_N3_R1_feature_census']=census

# C. Necessary parameter ledgers from the explicit family.
# A public key-sensitive scalar character from rank rho has bias q^{-r rho}.
# Using rho <= m(R+m+1), suppressing this one bias below 2^-lambda requires
# r*m(R+m+1)*log2(q) >= lambda.
# The family contains 2^(N-R-m) distinct nonproportional directions, so
# suppressing just its squared Fourier mass below 2^-2lambda requires the
# stronger displayed inequality.
ledger=[]
for N,R,m,r,qbits,lam in [
    (256,8,2,15,16,128),(256,8,4,15,16,128),(256,8,8,15,16,128),
    (1024,10,4,31,16,128),(1024,10,8,31,16,128),(1024,10,16,31,16,128),
]:
    rho=m*(R+m+1)
    log2_bias_upper_exponent=-(r*rho*qbits) # bias >= 2^(this) when q<=2^qbits is not rigorous; ledger uses q=2^qbits model.
    spectral_log2_lower=(N-R-m)-2*r*rho*qbits
    ledger.append({
        'N':N,'R':R,'m':m,'r':r,'qbits_model':qbits,'lambda':lam,
        'explicit_rank_upper_bound':rho,
        'single_character_log2_bias_lower_model':log2_bias_upper_exponent,
        'family_log2_squared_spectral_mass_lower_model':spectral_log2_lower,
        'single_bias_below_2^-lambda_necessary_in_model':r*rho*qbits>=lam,
        'family_mass_below_2^-2lambda_necessary_in_model':2*r*rho*qbits >= (N-R-m)+2*lam,
    })
out['parameter_ledger_q_equals_2_power_qbits_model']=ledger

# D. Direct-table size if one raises m beyond N-R so this generalized family
# cannot choose s=R+m free Boolean coordinates. This is NOT a security theorem;
# it is the representation cost of escaping only this explicit construction.
size=[]
for N in [32,64,128,256,512,1024]:
    R=int(math.log2(N)); m=N-R+1
    K=(2*N*R+1)*math.comb(2*R,R)
    rows=(N+1)*K; cols=(N+1)*m; entries=rows*cols
    min_field_bits=N+1  # because this product-feature label uses p>2^N
    packed_bytes_lower=entries*min_field_bits/8
    size.append({'N':N,'R':R,'m_first_outside_attack_range':m,
                 'base_rows':rows,'aug_columns':cols,'aug_field_entries':entries,
                 'minimum_field_bits_from_p_gt_2^N':min_field_bits,
                 'raw_packed_bytes_lower_bound':packed_bytes_lower})
out['direct_table_cost_at_m_equals_N_minus_R_plus_1']=size

# E. Extension-field packing bit-cost control: packing m base-field coordinates
# into one F_{q^m} coordinate does not reduce raw information bits: one packed
# symbol carries m*log2(q) bits. (Only arithmetic/metadata shape changes.)
packing=[]
for qbits,m in [(16,2),(16,8),(32,16),(64,32)]:
    packing.append({'base_field_bits':qbits,'m':m,
                    'm_base_symbols_bits':m*qbits,
                    'one_extension_symbol_bits':m*qbits})
out['extension_field_raw_bit_cost_controls']=packing

out['status']='PASS'
print(json.dumps(out,indent=2,sort_keys=True))
