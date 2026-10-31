#!/usr/bin/env python3
"""Public, deterministic canonical quotient gauge for the EXACT pivot--Schur gate.

This file depends on the verbatim, pinned quotient_recurrence_check.py, bundled
next to it for reproducibility. The output is a local *algebraic* validation,
not a key hiding or a QPT security proof.
"""
from __future__ import annotations
import hashlib
import json
import random
import quotient_recurrence_check as prior

TALLY=0

def check(ok, msg):
    global TALLY
    TALLY+=1
    if not ok:
        raise AssertionError(f'canonical check {TALLY}: {msg}')


def transpose(A):
    return list(map(list,zip(*A)))


def append_independent_standard_columns(A):
    """Public deterministic full basis whose first r columns equal A."""
    n=len(A)
    r=len(A[0])
    basis=[ [A[i][j] for i in range(n)] for j in range(r) ]
    old=r
    for j in range(n):
        e=[int(i==j) for i in range(n)]
        cand=transpose(basis+[e])
        if prior.rank(cand)==old+1:
            basis.append(e)
            old+=1
        if old==n:break
    check(old==n,'columns extend to a full public basis')
    return transpose(basis)


def append_independent_standard_rows(B):
    n=len(B[0]);r=len(B)
    basis=[row[:] for row in B]
    old=r
    for j in range(n):
        e=[int(i==j) for i in range(n)]
        if prior.rank(basis+[e])==old+1:
            basis.append(e)
            old+=1
        if old==n:break
    check(old==n,'rows extend to a full public basis')
    return basis


def block_diag(S,h):
    r=len(S);n=r+h
    M=prior.zeros(n,n)
    for i in range(r):
        for j in range(r):M[i][j]=S[i][j]
    for j in range(h):M[r+j][r+j]=1
    return M


def polynomial_value(rho,xi):
    val=0
    for c in reversed(rho):
        val=prior.E[val][xi]^c
    return val


def public_projectors(T,roots):
    """The ordinary CRT idempotents P_e(T), using only PUBLIC T, nodes."""
    R=len(T);I=prior.ident(R)
    projs=[]
    for e,root in enumerate(roots):
        acc=I
        denom=1
        for f,other in enumerate(roots):
            if f==e:continue
            acc=prior.mm(acc,prior.madd(T,prior.mscale(other,I)))
            denom=prior.E[denom][root^other]
        check(denom!=0,'distinct public quotient spectrum')
        acc=prior.mscale(prior.INV[denom],acc)
        check(prior.rank(acc)==2,'rank-two public node projector')
        check(prior.mm(acc,acc)==acc,'projector idempotence')
        projs.append(acc)
    check(sum_matrices(projs,R)==I,'projectors partition entire quotient space')
    for i,P in enumerate(projs):
        check(prior.mm(T,P)==prior.mscale(roots[i],P),'public spectral equation')
        for j,Q in enumerate(projs):
            if i<j:check(prior.mm(P,Q)==prior.zeros(R,R),'spectral orthogonality')
    return projs


def sum_matrices(mats,n):
    M=prior.zeros(n,n)
    for A in mats:M=prior.madd(M,A)
    return M


def public_eigenbasis(projectors):
    r=len(projectors[0])
    vecs=[]
    for P in projectors:
        _,pivot_cols=prior.rref_with_pivots(P)
        check(len(pivot_cols)==2,'each eigenspace dimension two')
        for j in pivot_cols:vecs.append([P[i][j] for i in range(r)])
    check(len(vecs)==r,'basis has expected dimension')
    S=transpose(vecs)
    check(prior.rank(S)==r,'public eigenbasis invertible')
    return S


def normalize_quotient(Q0,Q1,roots):
    """Entirely public transform P,Q: P Q_j Q = diag(D^j,0)."""
    n=len(Q0)
    a,b,left,right=prior.rank_factor(Q0)
    r=len(b);h=n-r
    check(r==2*len(roots),'known rank 2L')
    T=prior.mm(prior.mm(left,Q1),right)
    check(prior.mm(prior.mm(a,T),b)==Q1,'Q1 shares quotient support')
    projectors=public_projectors(T,roots)
    S=public_eigenbasis(projectors)
    Sinv=prior.invmat(S)
    Cbasis=append_independent_standard_columns(a)
    Rbasis=append_independent_standard_rows(b)
    P0=prior.invmat(Cbasis)
    Q0right=prior.invmat(Rbasis)
    P=prior.mm(block_diag(Sinv,h),P0)
    Q=prior.mm(Q0right,block_diag(S,h))
    I=prior.zeros(n,n)
    D=prior.zeros(n,n)
    for e,x in enumerate(roots):
        for t in (2*e,2*e+1):
            I[t][t]=1;D[t][t]=x
    check(prior.mm(prior.mm(P,Q0),Q)==I,'normalizes Q0 exactly')
    check(prior.mm(prior.mm(P,Q1),Q)==D,'normalizes Q1 to labeled D')
    return P,Q,projectors


def canonicalize(full, public_nodes, *, n_orig=prior.N_ORIG, verified=True, context=None):
    """Standalone PUBLIC BuildCanonical. Returns ONLY transformed originals and W.

    The normalization matrices and hidden setup are not part of the capsule.
    If caller has arbitrary malformed full tensors, use verified=True + raw fallback.
    """
    prefix=n_orig+1
    Q0,Q1=full[prefix:prefix+2]
    roots=[prior.fpow(e,8) for e in public_nodes]
    try:
        P,Q,_=normalize_quotient(Q0,Q1,roots)
        if verified:
            # Preserve all inconsistent/malicious raw tensors as a fallback, rather
            # than claiming to fix malicious N-of-N setup cryptographically.
            for j,M in enumerate(full[prefix:]):
                target=prior.zeros(len(M),len(M))
                for e,root in enumerate(roots):
                    t=2*e
                    target[t][t]=target[t+1][t+1]=prior.fpow(root,j)
                if prior.mm(prior.mm(P,M),Q)!=target:
                    raise ValueError('late quotient slice inconsistent')
        transformed=[prior.mm(prior.mm(P,M),Q) for M in full[:prefix]]
        W=prior.mm(P,Q)
        check(prior.rank(W)==len(W),'public key metric W invertible')
        return {'kind':'canonical','original':transformed,'W':W,
                'roots':roots,'N':len(W),'R':2*len(roots),'context':context}
    except (ValueError,IndexError,AssertionError,ZeroDivisionError):
        if not verified:raise
        return {'kind':'raw','full':full,'context':context}


def canonical_eval(pkg,y):
    if pkg['kind']=='raw':return prior.public_eval(pkg['full'],y)
    n=pkg['N'];r=pkg['R']
    prefix=len(pkg['original'])
    orig=y[:prefix];rho=y[prefix:]
    out=prior.zeros(n,n)
    for t,c in enumerate(orig):
        if c:out=prior.madd(out,prior.mscale(c,pkg['original'][t]))
    for e,root in enumerate(pkg['roots']):
        f=polynomial_value(rho,root)
        out[2*e][2*e]^=f
        out[2*e+1][2*e+1]^=f
    return out


def rank_shift(pkg,C,lambda_,z=1):
    metric=pkg['W'] if pkg['kind']=='canonical' else prior.ident(len(C))
    return prior.rank(prior.madd(C,prior.mscale(prior.E[lambda_][z],metric)))


def projected_key_tensor_check(nodes,key,full,pkg,P,Q):
    """Exact PUBLIC observable bottom-right and private-side identity in checker."""
    n=prior.N;R=pkg['R'];h=n-R
    Left=[row[:] for row in P[R:]]
    Right=[[Q[i][j] for j in range(R,n)] for i in range(n)]
    Wbr=prior.mm(Left,Right)
    check(prior.rank(Wbr)==h,'generic quotient-annihilator metric nondegenerate')
    original_count=prior.N_ORIG+1
    for j in range(len(full)):
        observed=prior.mm(prior.mm(Left,full[j]),Right)
        transformed_bottom=[row[R:] for row in pkg['original'][j][R:]] if j<original_count else prior.zeros(h,h)
        check(observed==transformed_bottom,'public bottom-right block after normalization')
        prediction=prior.zeros(h,h)
        if j==0:
            prediction=prior.madd(prediction,prior.mscale(key,Wbr))
        y=tuple(int(j==t) for t in range(prior.K_DIM))
        for node in nodes:
            e,alpha,sl2,mu,orient,U,V=node
            pi=prior.gate(node,y)[1][1]
            leftu=[[U[i][1]] for i in range(n)]
            rightv=[V[1][:]]
            Xu=prior.mm(Left,leftu)
            vY=prior.mm(rightv,Right)
            prediction=prior.madd(prediction,prior.mscale(pi,prior.mm(Xu,vY)))
        check(observed==prediction,'exact pivot-only HH affine key equation')
        if j>=original_count:check(observed==prior.zeros(h,h),'all quotient mode projections vanish')
    return {'h':h,'metric_rank':prior.rank(Wbr)}


def digest_matrix(M):
    return hashlib.sha256(bytes(x for row in M for x in row)).hexdigest()


def run(seed):
    nodes,key=prior.setup(seed)
    full=prior.build_matrices(nodes,key)
    context={'relation_id':'toy-original-r1cs','claim_id':f'toy-utxo-{seed}',
             'branch':'disprove','anchors':'toy-BTC-SYS-window',
             'checking_key':'opaque-native-vk-bound-to-claim'}
    pkg=canonicalize(full,prior.NODES,context=context)
    check(pkg['context']==context,'complete branch/claim/key context copied unchanged')
    check(pkg['kind']=='canonical','honest exact quotient normal form')
    check(len(pkg['original'])==prior.N_ORIG+1,'canonical package removes quotient matrices')
    check('P' not in pkg and 'Q' not in pkg and 'Q0' not in pkg and 'Q1' not in pkg,'no private or quotient factors in output')
    roots=pkg['roots'];n=prior.N
    check(len(roots)==prior.L and len(set(roots))==len(roots),'public nodes distinct')
    P,Q,projectors=normalize_quotient(full[prior.N_ORIG+1],full[prior.N_ORIG+2],roots)
    for e,(node,projector) in enumerate(zip(nodes,projectors)):
        _,_,_,_,_,U,V=node
        # The exact per-node quotient contribution is a publicly computable
        # spectral projector: A P_e(T) B; compare with hidden proof-only UJV.
        A,B,left,right=prior.rank_factor(full[prior.N_ORIG+1])
        public_marker=prior.mm(prior.mm(A,projector),B)
        inner=prior.zeros(3,3);inner[0][2]=inner[2][0]=1
        expected=prior.mscale(prior.fpow(prior.zpoly(node[0]),8),prior.mm(prior.mm(U,inner),V))
        check(public_marker==expected,'public projector identifies full rank-two node marker')
    # The rank invariants and homogeneous affine key term are unchanged.
    rng=random.Random(seed^0xC0A0)
    for t in range(40):
        y=tuple(rng.randrange(256) for _ in range(prior.K_DIM))
        M=canonical_eval(pkg,y)
        old=prior.public_eval(full,y)
        check(M==prior.mm(prior.mm(P,old),Q),'exact E-typed full public operator')
        correct_key=prior.E[y[0]][key]
        check(prior.rank(prior.madd(M,prior.mscale(correct_key,pkg['W'])))==prior.rank(prior.madd(old,prior.mscale(correct_key,prior.ident(n)))),'all E-slice rank metrics identical')
    valid_sources=[(1,0,0,0,0,0,0),(1,1,1,0,0,0,0)]
    for y in valid_sources:
        M=canonical_eval(pkg,y)
        check(rank_shift(pkg,M,key)==2*prior.L,'valid ORIGINAL recovers the same protected K')
        check(any(rank_shift(pkg,M,key^d)>2*prior.L for d in (1,2,4,8)),'at least one wrong-key witness test rejects')
    # Arbitrary E-typed polynomial quotient probes are preserved.
    for _ in range(20):
        rho=[rng.randrange(256) for _ in range(prior.M_CONSTRAINT-1)]
        y=(0,0,0,*rho)
        M=canonical_eval(pkg,y)
        check(M==prior.mm(prior.mm(P,prior.public_eval(full,y)),Q),'arbitrary E quotient polynomial')
    hp=projected_key_tensor_check(nodes,key,full,pkg,P,Q)
    # Inconsistent late-quotient coefficients cannot be silently canonicalized.
    malicious=[[r[:] for r in M] for M in full]
    malicious[-1][0][0]^=1
    out=canonicalize(malicious,prior.NODES,verified=True,context=context)
    check(out['context']==context,'malformed-input fallback retains public context')
    check(out['kind']=='raw','malformed late quotient slice triggers exact raw fallback')
    check(canonical_eval(out,(1,0,0,0,0,0,1))==prior.public_eval(malicious,(1,0,0,0,0,0,1)),'malformed raw fallback exact')
    return {'seed':seed,'field':'GF16 subset GF256','nodes':prior.L,
            'ambient_dimension':n,'quotient_rank':2*prior.L,
            'canonical_matrix_count':len(pkg['original'])+1,
            'previous_two_slice_matrix_count':len(full[:prior.N_ORIG+3]),
            'metric_sha256':digest_matrix(pkg['W']),
            'source0_sha256':digest_matrix(pkg['original'][0]),
            'projected_affine_key_dimension':hp['h'],
            'malformed_input_fallback':'passed',
            'valid_original_witnesses':2}


def main():
    fixtures=[run(seed) for seed in (17011,17029,17041)]
    summary={'candidate':'pivot-SL2-Schur canonical quotient gauge',
             'claim_scope':'exact honest output functionality, public QPT data-processing, source acceptance; NOT key secrecy',
             'public_gate_version':'syscoin/PVUGC fb1772abab1597cd7821623927b2fb318cb2fa9b',
             'fixtures':fixtures,
             'canonical_assertions':TALLY,'vendored_prior_assertions':prior.COUNT,
             'total_assertions':TALLY+prior.COUNT}
    print(json.dumps(summary,sort_keys=True,indent=2))

if __name__=='__main__':main()
