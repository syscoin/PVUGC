#!/usr/bin/env python3
import itertools, json, math, random, importlib.util, pathlib
SEED=202609242316
rng=random.Random(SEED)

candidates=[
    pathlib.Path('research/pq-wkem/literature-20260924/rank_field_extensions.py'),
    pathlib.Path(__file__).with_name('rank_field_extensions_dependency.py'),
    pathlib.Path('/mnt/data/run82_tmp/rank_field_extensions_dependency.py'),
]
for dep in candidates:
    if dep.exists():
        spec=importlib.util.spec_from_file_location('rfe',dep)
        rfe=importlib.util.module_from_spec(spec); spec.loader.exec_module(rfe); break
else:
    raise FileNotFoundError('rank_field_extensions.py dependency not found')

def mat_add(A,B,F,ca=1,cb=1):
    return [[F.add[F.mul[ca][x]][F.mul[cb][y]] for x,y in zip(ra,rb)] for ra,rb in zip(A,B)]

def mat_scale(A,a,F):
    return [[F.mul[a][x] for x in row] for row in A]

def mat_lincomb(mats,coeffs,F):
    if not mats:return []
    Z=[[0]*len(mats[0][0]) for _ in mats[0]]
    for a,M in zip(coeffs,mats):
        if a: Z=mat_add(Z,M,F,1,a)
    return Z

def mult_weight(b,c,F):
    z=1
    for bi,ci in zip(b,c):
        if bi:z=F.mul[z][ci]
    return z

def weighted_block(terms,c,F,N):
    n=N+1
    G=[[0]*n for _ in range(n)]
    for b,lam,qv in terms:
        v=[1]+list(b); g=mult_weight(b,c,F)
        a=F.mul[lam][g]
        for i in range(n):
            if not v[i]:continue
            for j in range(n):
                if v[j]:
                    G[i][j]=F.add[G[i][j]][a]
    return G

def violation(terms,c,F):
    z=0
    for b,lam,qv in terms:
        g=mult_weight(b,c,F)
        z=F.add[z][F.mul[lam][F.mul[g][qv]]]
    return z

def augmented_matrix(A,terms,cs,F,N):
    rows=[row[:] for row in A]
    for c in cs:
        rows += weighted_block(terms,c,F,N)
    return rows

def fd_codeword(N,R,p,T,zbits):
    F=rfe.Field(p); S=rfe.spec(N,R,F); s=R+1;T=tuple(T)
    outside=[i for i in range(N) if i not in T]
    z=dict(zip(outside,zbits))
    vec=[0]*len(rfe.encode((0,)*N,S)); terms=[]
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
    return F,S,rfe.reshape(vec,N+1),terms

def anchor(A): return A[0][0]

def flat(A): return [x for row in A for x in row]

def nullspace(A,F,ncols):
    return rfe.nullspace(A,F,ncols)

def challenge_transition_block(b,c,i,F):
    # G=g(b) vv^T, assumes b_i=0. Fixed linear update should equal G' exactly.
    n=len(b)+1; v=[1]+list(b);g=mult_weight(b,c,F)
    G=[[F.mul[g][F.mul[vi][vj]] for vj in v] for vi in v]
    # same vv^T linear update used by the base compiler: replace matrix coord i+1 with coord 0.
    idx=i+1
    H=[[0]*n for _ in range(n)]
    for r in range(n):
        for col in range(n):
            rr=0 if r==idx else r
            cc=0 if col==idx else col
            H[r][col]=F.mul[c[i]][G[rr][cc]]
    bp=list(b);bp[i]=1;vp=[1]+bp;gp=mult_weight(bp,c,F)
    Want=[[F.mul[gp][F.mul[x][y]] for y in vp] for x in vp]
    return H,Want

out={'seed':SEED,'scope':'actual Hair-Sahai false-family algebra plus compact multiplicative-weight repair audit; classical attacks imply QPT attacks; no security proof'}

# 1. Polynomial transition checks for multiplicative blocks.
trans=0
for N,p in [(4,19),(6,29),(8,67)]:
    F=rfe.Field(p)
    for _ in range(120):
        c=[rng.randrange(2,p) for _ in range(N)]
        c=[x if x!=1 else 2 for x in c]
        b=[rng.randrange(2) for _ in range(N)]
        zeros=[i for i,x in enumerate(b) if x==0]
        if not zeros: b[rng.randrange(N)]=0; zeros=[i for i,x in enumerate(b) if x==0]
        i=rng.choice(zeros)
        H,W=challenge_transition_block(tuple(b),c,i,F)
        assert H==W
        trans+=1
out['multiplicative_block_linear_transition_checks']=trans

# 2. Single multiplicative block: it kills every original member individually,
#    but an explicit 2-member recombination survives, has nonzero anchor,
#    and rank <= R+4.
single=[]
for N,R,p in [(5,2,23),(6,2,29),(8,3,67),(10,3,83)]:
    s=R+1;T=tuple(range(s)); outside=[i for i in range(N) if i not in T]
    assert len(outside)>=2
    F,S,A0,terms0=fd_codeword(N,R,p,T,(0,)*len(outside))
    # Choose arbitrary nonzero/non-one multipliers, including an all-equal case
    # on alternating fixtures to exercise the pair fallback.
    if N%2:
        c=[(i+2)%p or 2 for i in range(N)]
        c=[2 if x in (0,1) else x for x in c]
    else:
        c=[3]*N
    v0=violation(terms0,c,F); assert v0!=0
    a0=anchor(A0); assert a0!=0
    r1=F.mul[anchor(fd_codeword(N,R,p,T,tuple([1]+[0]*(len(outside)-1)))[2])][F.inv[a0]]
    chosen=None
    # singleton if challenge ratio differs from anchor ratio
    for pos,j in enumerate(outside):
        z=[0]*len(outside);z[pos]=1
        F2,S2,Az,tz=fd_codeword(N,R,p,T,tuple(z)); assert F2.q==F.q
        vz=violation(tz,c,F); assert vz!=0
        g_ratio=F.mul[vz][F.inv[v0]]
        a_ratio=F.mul[anchor(Az)][F.inv[a0]]
        if g_ratio!=a_ratio:
            chosen=(tuple(z),Az,tz,g_ratio,a_ratio,1);break
    if chosen is None:
        # all singleton ratios aligned; any pair must disagree because
        # r1^2 != a_2/a_0 when p>N+1 and s+1 !=0.
        z=[0]*len(outside);z[0]=z[1]=1
        F2,S2,Az,tz=fd_codeword(N,R,p,T,tuple(z))
        vz=violation(tz,c,F);g_ratio=F.mul[vz][F.inv[v0]]
        a_ratio=F.mul[anchor(Az)][F.inv[a0]]
        assert g_ratio!=a_ratio
        chosen=(tuple(z),Az,tz,g_ratio,a_ratio,2)
    z,Az,tz,g_ratio,a_ratio,w=chosen
    # g_ratio*A0 - Az cancels the challenge constraint
    Aug0=augmented_matrix(A0,terms0,[c],F,N)
    Augz=augmented_matrix(Az,tz,[c],F,N)
    Attack=mat_add(mat_scale(Aug0,g_ratio,F),Augz,F,1,F.neg[1])
    comb_violation=F.sub(F.mul[g_ratio][v0],violation(tz,c,F))
    assert comb_violation==0
    anch=F.sub(F.mul[g_ratio][a0],anchor(Az)); assert anch!=0
    rr=rfe.rank(Attack,F)
    assert rr<=R+2+w<=R+4
    # each original member by itself is indeed rejected by the new source constraint
    assert violation(terms0,c,F)!=0 and violation(tz,c,F)!=0
    single.append({'N':N,'R':R,'p':p,'outside_bits':len(outside),
                   'chosen_outside_weight':w,'attack_rank':rr,'rank_upper_bound':R+2+w,
                   'anchor_nonzero':True,'individual_challenge_violations_nonzero':True,
                   'challenge_ratio':g_ratio,'anchor_ratio':a_ratio})
out['single_multiplicative_challenge_anchor_sensitive_recombination']=single

# 3. Arbitrary L extra scalar-weight blocks: L+1 independent finite-difference
#    members always yield a nonzero survivor, rank <= R+L+2.
multi=[]
for N,R,p,L in [(6,2,29,1),(7,2,31,2),(8,2,37,3),(9,2,43,4)]:
    s=R+1;T=tuple(range(s)); outside=[i for i in range(N) if i not in T]
    assert len(outside)>=L
    F=rfe.Field(p)
    cs=[]
    for h in range(L):
        c=[]
        for i in range(N):
            x=2+((h+2)*(i+3)+h)%max(2,p-3)
            x%=p
            if x in (0,1):x=2
            c.append(x)
        cs.append(c)
    members=[]
    # z=0 plus L singleton outside assignments
    zlist=[(0,)*len(outside)]
    for pos in range(L):
        z=[0]*len(outside);z[pos]=1;zlist.append(tuple(z))
    for z in zlist:
        F2,S,A,terms=fd_codeword(N,R,p,T,z)
        members.append((A,terms))
    # original matrices are independent
    orig_flats=[flat(A) for A,_ in members]
    assert len(rfe.span(orig_flats,F))==L+1
    C=[[violation(terms,c,F) for A,terms in members] for c in cs]
    ker=nullspace(C,F,L+1)
    assert ker
    # choose a kernel vector whose original matrix is nonzero (guaranteed by independence)
    theta=next(v for v in ker if any(v))
    Orig=mat_lincomb([A for A,_ in members],theta,F)
    assert any(any(row) for row in Orig)
    # full augmented combination and exact new constraints
    Augs=[augmented_matrix(A,terms,cs,F,N) for A,terms in members]
    Full=mat_lincomb(Augs,theta,F)
    for h,c in enumerate(cs):
        z=F.sum(F.mul[a][violation(terms,c,F)] for a,(A,terms) in zip(theta,members))
        assert z==0
    rr=rfe.rank(Full,F)
    assert rr<=R+L+2
    multi.append({'N':N,'R':R,'p':p,'extra_blocks_L':L,
                  'family_members_used':L+1,'kernel_dimension':len(ker),
                  'survivor_rank':rr,'theorem_rank_upper_bound':R+L+2,
                  'survivor_anchor_nonzero':anchor(Full)!=0})
out['arbitrary_L_block_survivor_controls']=multi

# 4. Exact small augmented-space census: the one-block repair greatly reduces
#    but does not remove low-rank false matrices.
# N=3,R=1,p=7 is small enough to enumerate the whole constrained space.
def build_augmented_space(N,R,p,cs):
    F=rfe.Field(p);S=rfe.spec(N,R,F);words=list(itertools.product((0,1),repeat=N))
    base_enc=[rfe.encode(w,S) for w in words]; n=N+1; stride=n*n
    base_blocks=len(S['ts'])*len(S['aa'])
    enc=[]; weights=[]
    for w,e in zip(words,base_enc):
        rows=rfe.reshape(e,n)
        ws=[e[h*stride] for h in range(base_blocks)]
        for c in cs:
            g=mult_weight(w,c,F);v=[1]+list(w)
            rows += [[F.mul[g][F.mul[x][y]] for y in v] for x in v]
            ws.append(g)
        enc.append(flat(rows));weights.append(ws)
    q=[F.sub(F.sum(w),N+1) for w in words]
    eqs=[[F.mul[weights[j][h]][q[j]] for j in range(len(words))] for h in range(len(weights[0]))]
    coeffs=rfe.nullspace(eqs,F,len(words))
    B=rfe.span([rfe.lincomb(enc,c,F) for c in coeffs],F)
    return F,B,n

F0,B0,n=build_augmented_space(3,1,7,[])
c1=[[2,3,4]]
F1,B1,n=build_augmented_space(3,1,7,c1)
hist=[]
for label,F,B in [('base',F0,B0),('one_mult',F1,B1)]:
    H={}
    for cc in itertools.product(range(F.q),repeat=len(B)):
        if not any(cc):continue
        M=rfe.reshape(rfe.lincomb(B,cc,F),n)
        rr=rfe.rank(M,F);H[rr]=H.get(rr,0)+1
    hist.append({'case':label,'dimension':len(B),'rank_histogram':H})
assert hist[0]['rank_histogram'].get(3)==84
assert hist[1]['rank_histogram'].get(3)==6
out['exact_small_augmented_space_census']=hist

# 5. Generic parameter implication of the arbitrary-L theorem.
rows=[]
for N in [256,1024,4096,16384]:
    R=int(math.log2(N))
    for L in [1,4,16,64,256]:
        if L<=N-R-1:
            rows.append({'N':N,'R':R,'extra_scalar_blocks_L':L,
                         'explicit_false_minrank_upper_bound':R+L+2,
                         'overhead_blocks':L})
out['generic_rank_upper_bound_ledger']=rows
out['status']='PASS'
print(json.dumps(out,indent=2,sort_keys=True))
