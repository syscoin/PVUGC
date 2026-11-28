#!/usr/bin/env python3
import itertools, json, math, random, importlib.util, pathlib

SEED = 202609250216
rng = random.Random(SEED)

dep = pathlib.Path('/mnt/data/run86/rank_field_extensions_dependency.py')
sp = importlib.util.spec_from_file_location('rfe', dep)
rfe = importlib.util.module_from_spec(sp); sp.loader.exec_module(rfe)

# Multilinear Boolean polynomials are dictionaries mask -> coefficient.
def poly_eval(poly, w, F):
    out = 0
    for mask, c in poly.items():
        ok = True
        for i in range(len(w)):
            if (mask >> i) & 1 and not w[i]:
                ok = False; break
        if ok:
            out = F.add[out][c]
    return out

def rand_poly(N, d, F, terms=10):
    masks = [m for m in range(1 << N) if m.bit_count() <= d]
    if len(masks) <= terms:
        chosen = masks
    else:
        chosen = rng.sample(masks, terms)
    out = {}
    for m in chosen:
        c = rng.randrange(F.q)
        if c:
            out[m] = c
    if not out:
        out[0] = 1
    return out

def features_random_low_degree(N,d,m,F):
    feats=[{0:1}]
    for _ in range(m-1):
        feats.append(rand_poly(N,d,F,terms=min(12,sum(math.comb(N,k) for k in range(d+1)))))
    return feats

def feature_vals(w, feats, F):
    return [poly_eval(p,w,F) for p in feats]

def aug_encode(w,S,feats):
    F=S['F']; n=S['N']+1
    base=rfe.reshape(rfe.encode(w,S), n)
    fv=feature_vals(w,feats,F)
    out=[]
    for row in base:
        for a in fv:
            out.extend(F.mul[a][x] for x in row)
    return out

def split_blocks(vec,S,m):
    n=S['N']+1; ncols=m*n
    M=rfe.reshape(vec,ncols)
    return [[row[j*n:(j+1)*n] for row in M] for j in range(m)]

def aug_constraint_matrix(S, eqs, feats):
    N=S['N']; F=S['F']; m=len(feats)
    words=list(itertools.product((0,1),repeat=N))
    base=[rfe.encode(w,S) for w in words]
    n=N+1; stride=n*n; blocks=len(S['ts'])*len(S['aa'])
    FV=[feature_vals(w,feats,F) for w in words]
    rows=[]
    # each row is restriction of h(b)*phi_j(b)*f_e(b)
    for eq in eqs:
        ev=[eq(w,F) for w in words]
        for hidx in range(blocks):
            hs=[e[hidx*stride] for e in base]
            for j in range(m):
                rows.append([F.mul[F.mul[hs[z]][FV[z][j]]][ev[z]] for z in range(len(words))])
    return words,rows,base,FV

def subcube_words(N,T,zbits):
    T=tuple(T); outside=[i for i in range(N) if i not in T]
    z=dict(zip(outside,zbits))
    out=[]
    for xb in itertools.product((0,1),repeat=len(T)):
        b=[0]*N
        for i,v in z.items(): b[i]=v
        for i,v in zip(T,xb): b[i]=v
        out.append(tuple(b))
    return out

def fd_mu_on_cube(s,F):
    return [1 if sum(x)%2==0 else F.neg[1] for x in itertools.product((0,1),repeat=s)]

def dot(a,b,F):
    return F.sum(F.mul[x][y] for x,y in zip(a,b))

def row_rank(rows,F,ncols):
    return len(rfe.span(rows,F)) if rows else 0

def in_span(rows,v,F):
    n=len(v)
    return row_rank(rows,F,n) == row_rank(rows+[v],F,n)

def reciprocal_false_eq(w,F,N):
    f=F.sub(F.sum(w),N+1)
    assert f
    return F.inv[f]

def construct_fd_coeff(N,R,d,F,T,zbits,words):
    pos={w:i for i,w in enumerate(words)}
    C=subcube_words(N,T,zbits)
    c=[0]*len(words); mu=[]; g=[]
    for b in C:
        f=F.sub(F.sum(b),N+1); assert f
        sign=1 if sum(b[i] for i in T)%2==0 else F.neg[1]
        c[pos[b]]=F.mul[sign][F.inv[f]]
        mu.append(sign); g.append(F.inv[f])
    return C,c,mu,g

def restriction_products(S,feats,C):
    # Span W = {h|C * phi_j|C}; h evaluations are read from actual HS table block anchors.
    F=S['F']; N=S['N']; n=N+1; stride=n*n; blocks=len(S['ts'])*len(S['aa'])
    enc=[rfe.encode(w,S) for w in C]
    FV=[feature_vals(w,feats,F) for w in C]
    rows=[]
    for hidx in range(blocks):
        hs=[e[hidx*stride] for e in enc]
        for j in range(len(feats)):
            rows.append([F.mul[hs[z]][FV[z][j]] for z in range(len(C))])
    return rows

def anchor_closed_form(N,s,w,F):
    a=N+1-w
    num=F.integer(math.factorial(s))
    if (s+1)%2: num=F.neg[num]
    den=1
    for j in range(s+1): den=F.mul[den][F.integer(a-j)]
    assert den
    return F.mul[num][F.inv[den]]

out={
  'seed':SEED,
  'scope':'general bounded-Boolean-degree feature-lift barrier and exact subcube-span criterion; finite algebra only; no cryptographic security inferred'
}

# A. Generic low-degree feature sets over the actual weighted-table compiler.
cases=[]; members=0; span_checks=0
for N,R,d,m,p in [
    (4,1,1,5,37),
    (5,1,2,4,67),
    (6,2,1,6,131),
    (6,1,3,4,131),
    (7,2,2,5,257),
]:
    s=R+d+1
    assert s<=N
    F=rfe.Field(p); S=rfe.spec(N,R,F)
    feats=features_random_low_degree(N,d,m,F)
    # Ensure max degree really <= d and a constant coordinate exists.
    assert feats[0]=={0:1}
    assert all(max((mask.bit_count() for mask in q),default=0)<=d for q in feats)
    eq=lambda w,F,N=N:F.sub(F.sum(w),N+1)
    words,Cmat,base,FV=aug_constraint_matrix(S,[eq],feats)
    enc=[aug_encode(w,S,feats) for w in words]
    T=tuple(range(s)); outside=N-s
    ranks=[]; anchors=[]; distinct=[]
    for zb in itertools.product((0,1),repeat=outside):
        C,c,mu,g=construct_fd_coeff(N,R,d,F,T,zb,words)
        # Exact source constraints.
        residual=[dot(row,c,F) for row in Cmat]
        assert not any(residual)
        # Exact subcube criterion: g=1/f is not in W, and finite-difference mu witnesses separation.
        W=restriction_products(S,feats,C)
        assert not in_span(W,g,F)
        for row in W:
            assert dot(mu,row,F)==0
        ag=dot(mu,g,F)
        assert ag!=0
        # Anchor of lambda equals mu dot 1/f and closed form.
        anchor=F.sum(c); assert anchor==ag
        assert anchor==anchor_closed_form(N,s,sum(zb),F)
        # Actual augmented matrix rank bound. Refine m to the rank of the
        # feature-evaluation span on this cube: an invertible feature-coordinate
        # change can zero all but rPhi feature blocks on C.
        feat_rows=[[feature_vals(w,feats,F)[j] for w in C] for j in range(m)]
        rPhi=row_rank(feat_rows,F,len(C))
        vec=rfe.lincomb(enc,c,F)
        A=rfe.reshape(vec,m*(N+1)); rr=rfe.rank(A,F)
        assert rr<=rPhi*(s+1)
        assert rPhi<=sum(math.comb(s,k) for k in range(min(d,s)+1))
        ranks.append(rr); anchors.append(anchor); distinct.append(tuple(vec))
        members+=1; span_checks+=1
    assert len(set(distinct))==2**outside
    C0=subcube_words(N,T,(0,)*outside)
    feat_rows0=[[feature_vals(w,feats,F)[j] for w in C0] for j in range(m)]
    rPhi0=row_rank(feat_rows0,F,len(C0))
    cases.append({'N':N,'R':R,'max_feature_degree_d':d,'feature_count_m':m,'p':p,
                  'free_cube_dimension_s':s,'family_size':2**outside,
                  'feature_eval_rank_on_cube':rPhi0,
                  'degree_d_function_space_dimension_on_cube':sum(math.comb(s,k) for k in range(min(d,s)+1)),
                  'refined_rank_upper_bound_rPhi_times_splus1':rPhi0*(s+1),
                  'coarse_rank_upper_bound_m_times_splus1':m*(s+1),
                  'observed_ranks':ranks,'all_anchors_nonzero':all(anchors),
                  'reciprocal_outside_feature_weight_span':True})
out['generic_low_degree_cases']=cases
out['generic_family_members_checked']=members
out['subcube_span_criterion_checks']=span_checks

# B. Sharpness of exact span criterion on a small cube.
# Adding g=1/f itself to W forces every W-perp vector to have zero anchor.
N,R,d,m,p=4,1,1,3,37
s=R+d+1; F=rfe.Field(p); S=rfe.spec(N,R,F)
feats=features_random_low_degree(N,d,m,F); T=tuple(range(s)); zb=(0,)*(N-s)
C=subcube_words(N,T,zb); W=restriction_products(S,feats,C)
g=[reciprocal_false_eq(w,F,N) for w in C]
assert not in_span(W,g,F)
nullW=rfe.nullspace(W,F,len(C))
assert any(dot(mu,g,F)!=0 for mu in nullW)
Wg=W+[g]
assert in_span(Wg,g,F)
nullWg=rfe.nullspace(Wg,F,len(C))
assert all(dot(mu,g,F)==0 for mu in nullWg)
out['exact_span_criterion_sharpness']={
    'cube_points':len(C),'rank_W':row_rank(W,F,len(C)),'rank_W_plus_g':row_rank(Wg,F,len(C)),
    'nullity_W':len(nullW),'nullity_W_plus_g':len(nullWg),
    'anchor_sensitive_null_vector_exists_before_g':True,
    'all_null_vectors_anchor_zero_after_adding_g':True,
}

# C. PPT support-size ledger for generic evaluable degree d = c log2 N.
# With R=floor(log2 N), direct enumeration uses 2^(R+d+1) <= 2*N^(c+1) for N powers of two.
ppt=[]
for N in [64,128,256,512,1024,2048]:
    R=int(math.log2(N))
    for c in [0,1,2]:
        d=c*R
        s=R+d+1
        support=2**s
        ppt.append({'N':N,'R':R,'degree_d':d,'c_multiple_of_log2N':c,
                    'cube_dimension_s':s,'support_assignments':support,
                    'support_over_N_power_cplus1':support/(N**(c+1))})
out['direct_enumeration_ppt_ledger']=ppt

# D. Degree floor to escape this explicit family by dimension alone.
degree_floor=[]
for N in [32,64,128,256,512,1024]:
    R=int(math.log2(N))
    degree_floor.append({'N':N,'R':R,
                         'largest_degree_still_attacked':N-R-1,
                         'first_degree_outside_this_cube_attack':N-R})
out['degree_floor_ledger']=degree_floor

# E. Rank-mask necessary-condition ledger for a compact polynomial feature family.
# For rank B=m(R+d+2), one explicit key-sensitive character has magnitude >= q^(-rB).
ledger=[]
for N,R,d,m,r,qbits,lam in [
    (256,8,8,16,15,16,128),
    (256,8,16,32,15,16,128),
    (1024,10,10,32,31,16,128),
    (1024,10,20,64,31,16,128),
]:
    B=m*(R+d+2)
    s=R+d+1
    family_exp=max(0,N-s)
    ledger.append({'N':N,'R':R,'d':d,'m':m,'r':r,'qbits_model':qbits,'lambda':lam,
                   'explicit_rank_upper_bound_B':B,
                   'family_size_lower_bound_power_of_two_exponent':family_exp,
                   'single_character_log2_bias_lower_model':-r*B*qbits,
                   'family_log2_squared_spectral_mass_lower_model':family_exp-2*r*B*qbits,
                   'single_bias_below_2^-lambda_necessary_in_model':r*B*qbits>=lam,
                   'family_mass_below_2^-2lambda_necessary_in_model':2*r*B*qbits>=family_exp+2*lam})
out['rank_mask_parameter_ledger_q_equals_2_power_qbits_model']=ledger

out['status']='PASS'
print(json.dumps(out,indent=2,sort_keys=True))
