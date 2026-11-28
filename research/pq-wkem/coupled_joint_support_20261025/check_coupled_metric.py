#!/usr/bin/env python3
"""Offline algebra validation of an experimental, NOT security-proved release repair.

Uses the exact archived GF(16) inside GF(256) arithmetic, quotient normalizer,
and R1CS examples. False fixtures are supplied-secret checks only. Honest
recovery enumeration is restricted to explicitly validated ORIGINAL witnesses.
No networking, production credentials, signing, or unauthorized-recovery code.
"""
from __future__ import annotations
import hashlib
import itertools
import json
import random
from pathlib import Path
import quotient_recurrence_check as f
import canonical_release_check as canon
import check_joint_schur as old

COUNT = 0

def check(ok: bool, label: str) -> None:
    global COUNT
    COUNT += 1
    if not ok:
        raise AssertionError(label)

def padd(a: list[int], b: list[int]) -> list[int]:
    out = [0] * max(len(a), len(b))
    for i, x in enumerate(a): out[i] ^= x
    for i, x in enumerate(b): out[i] ^= x
    while len(out) > 1 and out[-1] == 0: out.pop()
    return out

def pmul(a: list[int], b: list[int]) -> list[int]:
    out = [0] * (len(a) + len(b) - 1)
    for i, x in enumerate(a):
        for j, y in enumerate(b): out[i+j] ^= f.F[x][y]
    while len(out) > 1 and out[-1] == 0: out.pop()
    return out

def scale(a: list[int], x: int) -> list[int]:
    return [f.F[x][v] for v in a]

def peval(a: list[int], x: int) -> int:
    y = 0
    for c in reversed(a): y = f.F[y][x] ^ c
    return y

def interpolate(values: list[int]) -> list[int]:
    out = [0]
    for j, value in enumerate(values):
        basis, den = [1], 1
        for k in range(len(values)):
            if k != j:
                basis = pmul(basis, [k, 1])
                den = f.F[den][j ^ k]
        out = padd(out, scale(basis, f.F[value][f.INVF[den]]))
    return out

def pdiv(a: list[int], b: list[int]) -> tuple[list[int], list[int]]:
    if not b or not b[-1]: raise ValueError('nonzero divisor required')
    a = a[:]
    q = [0] * max(1, len(a) - len(b) + 1)
    while len(a) >= len(b) and any(a):
        d = len(a) - len(b)
        c = f.F[a[-1]][f.INVF[b[-1]]]
        q[d] = c
        for i, value in enumerate(b): a[i+d] ^= f.F[c][value]
        while len(a) > 1 and a[-1] == 0: a.pop()
    return q, a

def source_ok(rows, w: tuple[int, ...]) -> bool:
    y = [1, *w]
    return all(f.E[old.dot(a,y)][old.dot(b,y)] == old.dot(c,y)
               for a,b,c in zip(*rows))

def encode(rows, w: tuple[int, ...]) -> list[int]:
    if not source_ok(rows, w): raise ValueError('ORIGINAL witness rejected')
    z = [1, *w]
    polys = [interpolate([old.dot(row,z) for row in mat]) for mat in rows]
    numerator = padd(pmul(polys[0], polys[1]), polys[2])
    Z = [1]
    for t in range(len(rows[0])): Z = pmul(Z, [t,1])
    H, rem = pdiv(numerator,Z)
    check(not any(rem), 'honest QAP division remainder zero')
    H += [0] * (len(rows[0])-1-len(H))
    check(len(H) == len(rows[0])-1, 'honest quotient degree bound')
    return [1, *w, *(f.fpow(c,8) for c in H)]

def schur(c: int, a: int, b: int, s: int, pi: int) -> list[list[int]]:
    return [[c,a,s],[b,pi,0],[s,0,pi]]

def determinant3(M) -> int:
    result = 0
    for perm in itertools.permutations(range(3)):
        result ^= f.E[f.E[M[0][perm[0]]][M[1][perm[1]]]][M[2][perm[2]]]
    return result

def gate(node: dict, y: list[int], n: int) -> list[list[int]]:
    z = y[0]; w = y[1:n+1]; rho = y[n+1:]
    af,bf,cf = node['forms']
    a,b,c = (old.dot(row,[z,*w]) for row in (af,bf,cf))
    p,q,r,t = node['sl2']
    A = f.E[p][a] ^ f.E[q][b]
    B = f.E[r][a] ^ f.E[t][b]
    C = c
    for i, value in enumerate([z,*w]):
        coeff = f.E[f.F[p][r]][f.E[af[i]][af[i]]] ^ f.E[f.F[q][t]][f.E[bf[i]][bf[i]]]
        C ^= f.E[coeff][value]
    eta = 0
    for alpha,value in zip(node['alpha'],w):
        C ^= f.E[f.E[alpha][alpha]][value]
        eta ^= f.E[alpha][value]
    s = f.E[node['sqrtZ']][canon.polynomial_value(rho,node['xi'])] ^ eta
    mu = node['mu']
    if node['orientation'] == 0:
        pi, As, Bs = z ^ f.E[mu][A], A, B ^ f.E[mu][C]
    else:
        pi, As, Bs = z ^ f.E[mu][B], A ^ f.E[mu][C], B
    return schur(C,As,Bs,s,pi)

def setup(kind: str, seed: int, L: int=9, h: int=4):
    rows = old.source(kind); m = len(rows[0]); n = len(rows[0][0])-1
    N = 2*L+h; k = n+m
    rng = random.Random(seed); key = rng.randrange(256)
    nodes=[]
    for e in range(m,m+L):
        check(e < 16, 'distinct off-domain source points')
        forms=[]
        weights=old.interpolation_weights(e,m)
        for mat in rows:
            forms.append([old.dot(weights,[row[j] for row in mat]) for j in range(n+1)])
        Z=1
        for j in range(m): Z=f.F[Z][e^j]
        alpha=[]
        for i in range(n):
            a2=rng.randrange(16)^f.E[f.THETA][f.fpow(e,i)]
            alpha.append(f.epow(a2,128))
        nodes.append(dict(forms=forms,alpha=alpha,sl2=f.sl2(rng),mu=rng.randrange(16,256),
                          orientation=rng.randrange(2),sqrtZ=f.fpow(Z,8),xi=f.fpow(e,8),
                          U=[[rng.randrange(256) for _ in range(3)] for _ in range(N)],
                          V=[[rng.randrange(256) for _ in range(N)] for _ in range(3)]))
    baseline=[]
    for j in range(k):
        y=[int(i==j) for i in range(k)]
        M=f.zeros(N,N)
        for node in nodes: M=f.madd(M,f.mm(f.mm(node['U'],gate(node,y,n)),node['V']))
        baseline.append(M)
    # One honest classical trial. A singular public metric causes a PUBLIC
    # abort, not a hidden fixed-factor rejection loop. A retry of the proposed
    # Build algorithm must restart all independent setup coins.
    metric=f.zeros(N,N)
    for node in nodes:
        node['T']=schur(*(rng.randrange(256) for _ in range(5)))
        metric=f.madd(metric,f.mm(f.mm(node['U'],node['T']),node['V']))
    if f.rank(metric)!=N:
        raise RuntimeError('PUBLIC_SETUP_ABORT: singular coupled metric')
    attempt=1
    public=[M[:] for M in baseline]
    public[0]=f.madd(baseline[0],f.mscale(key,metric))
    return rows,nodes,baseline,public,metric,key,attempt

def meval(Cs,y):
    out=f.zeros(len(Cs[0]),len(Cs[0]))
    for c,M in zip(y,Cs): out=f.madd(out,f.mscale(c,M))
    return out

def honest_recover_fixture(rows,public,metric,w):
    """Small-field exhaustive implementation ONLY on a verified ORIGINAL witness.

    The proposed general algorithm uses finite-field eigenvalue factorization;
    that production algorithm is not implemented or benchmarked here.
    """
    if not source_ok(rows,w): raise ValueError('requires valid ORIGINAL witness')
    y=encode(rows,w); C=meval(public,y)
    L=(len(C)-4)//2
    return [value for value in range(256)
            if f.rank(f.madd(C,f.mscale(value,metric)))<=2*L]

def gate_census():
    sub=[x for x in range(16) if f.fpow(x,4)==x]
    counts=[0]*4
    for c,a,b,s,pi in itertools.product(sub,repeat=5):
        M=schur(c,a,b,s,pi)
        rr=f.rank(M); counts[rr]+=1
        check(determinant3(M)==f.E[pi][f.E[pi][c]^f.E[a][b]^f.E[s][s]],
              'exact local metric determinant')
    q=len(sub)
    expected=[1,2*q*q-q-1,2*q**4-q**3-2*q*q+q,(q-1)**2*q**3]
    check(counts==expected,'exact local-rank distribution counts')
    moment=sum(counts[rank]*q**(3-rank) for rank in range(4))
    check(moment<=3*q**5,'E[q^deficiency] <= 3, checked at q=4')
    return dict(field_size=q,rank_counts=counts,total=q**5,deficiency_exponential_moment_numerator=moment)

def fixture(kind,seed,L):
    rows,nodes,baseline,Cs,metric,key,attempts=setup(kind,seed,L)
    n=len(rows[0][0])-1; N=len(metric); k=len(Cs)
    witnesses=[w for w in itertools.product(range(16),repeat=n) if source_ok(rows,w)]
    check(len(witnesses)==(0 if kind=='false' else 3),'complete ORIGINAL source census')
    check(f.rank(metric)==N,'full-rank public metric')
    P,Q,_=canon.normalize_quotient(Cs[n+1],Cs[n+2],[v['xi'] for v in nodes])
    a=L//2
    ii=list(range(2*a))+list(range(2*L,N))
    jj=list(range(2*a,2*L))+list(range(2*L,N))
    pleft=[P[i] for i in ii]
    qright=[[row[j] for j in jj] for row in Q]
    project=lambda M:f.mm(f.mm(pleft,M),qright)
    Bcut=project(metric)
    check(f.rank(Bcut)<=L,'coupled key metric shares separated rank budget')
    check(f.rank(project(f.ident(N)))>L,'archived scalar metric remains outside budget in this fixture')
    for index,node in enumerate(nodes):
        U=f.mm(pleft,node['U']); V=f.mm(node['V'],qright)
        if index<a:
            check(all(x==0 for j in (0,2) for x in V[j]),'node A exposed rows annihilated')
        else:
            check(all(U[i][j]==0 for i in range(len(U)) for j in (0,2)),
                  'node B exposed columns annihilated')
        for T in [node['T'],gate(node,[1]+[0]*(k-1),n)]:
            check(f.rank(f.mm(f.mm(U,T),V))<=1,'per-node projected local span rank <=1')
    # Known-secret identity checks; no false-instance candidate-key search.
    rng=random.Random(seed^0x52455041)
    sources=[[1]+[0]*(k-1),[0]+[rng.randrange(256) for _ in range(k-1)]]
    sources += [[rng.randrange(256) for _ in range(k)] for _ in range(3)]
    probes=[0,1,key,key^1]+[rng.randrange(256) for _ in range(8)]
    for y in sources:
        M=meval(baseline,y); C=meval(Cs,y)
        check(C==f.madd(M,f.mscale(f.E[y[0]][key],metric)),'exact complete-public evaluation identity')
        for value in probes:
            delta=f.E[y[0]][key^value]
            shifted=f.madd(C,f.mscale(f.E[y[0]][value],metric))
            check(shifted==f.madd(M,f.mscale(delta,metric)),'exact candidate scalar displacement')
            check(f.rank(project(shifted))<=L,'separated projection rank budget for every tested scalar')
    recovered=[]
    for w in witnesses:
        y=encode(rows,w)
        for node in nodes:
            check(f.rank(gate(node,y,n))==2,'each honest local gate has rank two')
        C=meval(Cs,y)
        check(f.rank(f.madd(C,f.mscale(key,metric)))<=2*L,'honest common-key rank correctness')
        values=honest_recover_fixture(rows,Cs,metric,w)
        check(values==[key],'same unique capability recovered from valid ORIGINAL witness')
        recovered.append(dict(witness=list(w),accepted_count=len(values)))
    # Check classical randomness quality is NOT inferred from deterministic fixtures.
    return dict(kind=kind,seed=seed,L=L,N=N,source_coordinates=k,metric_trials=attempts,
                valid_witness_count=len(witnesses),honest_recoveries=recovered,
                supplied_secret_projection_checks=len(sources)*len(probes),
                coupled_projected_metric_rank=f.rank(Bcut),
                old_projected_identity_rank=f.rank(project(f.ident(N))),
                false_instance_key_recovery_attempted=False)

def parameter_certificate():
    # Exact integer upper bounds, not floating-point security estimates.
    field_bits=256; base_bits=128
    n,m,L,h=11000,16000,16374,165
    N=2*L+h; d=n+m-1
    deficiency_threshold=L-2*h+1
    denominator1=field_bits*deficiency_threshold-base_bits*d-field_bits
    numerator1=3**L
    denominator2=field_bits*h*h-base_bits*d-field_bits
    numerator2=16*(N+1)
    check(denominator1>0 and denominator2>0,'positive simultaneous-error exponents')
    # A rational a / 2**D is strictly below 2**(-b) if a*2**b < 2**D.
    bound1=denominator1-numerator1.bit_length()
    bound2=denominator2-numerator2.bit_length()
    check((numerator1 << bound1) < (1 << denominator1),'first error exact certificate')
    check((numerator2 << bound2) < (1 << denominator2),'second error exact certificate')
    combined=min(bound1,bound2)-1
    check(combined>128,'simultaneous supplied-F-pair wrong-key error below 2^-128')
    check(2*L+4 < 2**15,'public abort error < 2^-241')
    bytes_per_matrix=N*N*(field_bits//8)
    return dict(scope='HONEST_SETUP_SUPPLIED_F_SOURCE_PAIRS_ONLY_NOT_KEY_SECRECY',
                field_bits=field_bits,base_field_bits=base_bits,n=n,m=m,L=L,h=h,N=N,
                normalized_source_coordinates=d,deficiency_threshold=deficiency_threshold,
                error_term_1_denominator_power_of_two=denominator1,
                error_term_1_numerator='3^L',error_term_1_less_than_two_to_minus=bound1,
                error_term_2_denominator_power_of_two=denominator2,
                error_term_2_numerator=numerator2,error_term_2_less_than_two_to_minus=bound2,
                total_wrong_scalar_error_less_than_two_to_minus=combined,
                public_abort_error_less_than_two_to_minus=241,
                raw_dense_matrices=n+4,raw_dense_bytes=(n+4)*bytes_per_matrix,
                canonical_dense_matrices=n+2,canonical_dense_bytes=(n+2)*bytes_per_matrix,
                bytes_per_dense_matrix=bytes_per_matrix,
                cryptographic_size_matrices_executed=False)

def main():
    census=gate_census()
    certificate=parameter_certificate()
    runs=[fixture(kind,seed,L) for kind in ('true','false')
          for seed,L in ((20261025,9),(271828,10))]
    result=dict(status='EXPERIMENTAL_CARRIER_REPAIR_NOT_A_SECRECY_REDUCTION',
                exact_local_census=census,parameter_certificate=certificate,fixtures=runs,main_assertions=COUNT,
                dependency_assertions=dict(field=f.COUNT,normalizer=canon.TALLY,source=old.CHECKS),
                quantum_security_proved=False,arbitrary_recovery_extraction_proved=False,
                network_access=False,production_changes=False,
                source_hashes={p.name:hashlib.sha256(p.read_bytes()).hexdigest()
                  for p in sorted(Path(__file__).parent.glob('*.py'))})
    print(json.dumps(result,sort_keys=True,indent=2))
if __name__=='__main__': main()
