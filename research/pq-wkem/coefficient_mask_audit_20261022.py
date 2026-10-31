#!/usr/bin/env python3
"""Research-only audit of public polynomial-coefficient mask cancellation.
No secret extraction from a third-party system; all matrices are fresh toy fixtures.
The exact source-gate form is from PVUGC Run593; mask interfaces are Runs704/707.
Standard library only. Reproduce: python coefficient_mask_audit.py
"""
from __future__ import annotations
import hashlib
import itertools
import json
import random
from fractions import Fraction

Q = 101
COUNT = 0

def check(condition: bool) -> None:
    global COUNT
    COUNT += 1
    if not condition:
        raise AssertionError(f"check {COUNT} failed")

def solve(A: list[list[int]], b: list[int], q: int, width: int) -> list[int] | None:
    """One affine solution (free variables zero), or None. Empty A is allowed."""
    rows = [[v % q for v in row] + [rhs % q] for row, rhs in zip(A, b)]
    pivots = []
    for col in range(width):
        k = next((j for j in range(len(pivots), len(rows)) if rows[j][col]), None)
        if k is None:
            continue
        pos = len(pivots)
        rows[pos], rows[k] = rows[k], rows[pos]
        inv = pow(rows[pos][col], -1, q)
        rows[pos] = [v * inv % q for v in rows[pos]]
        for j in range(len(rows)):
            if j != pos and rows[j][col]:
                c = rows[j][col]
                rows[j] = [(v - c*w) % q for v, w in zip(rows[j], rows[pos])]
        pivots.append(col)
    if any(not any(row[:width]) and row[width] for row in rows):
        return None
    x = [0] * width
    for pos, col in enumerate(pivots):
        x[col] = rows[pos][width]
    return x

def dot(a: list[int], b: list[int], q: int) -> int:
    return sum(x*y for x, y in zip(a,b)) % q

def transpose(A: list[list[int]]) -> list[list[int]]:
    return [list(x) for x in zip(*A)]

def rank(A: list[list[int]], q: int) -> int:
    a = [[x % q for x in row] for row in A]
    pos = 0
    for col in range(len(a[0])):
        k = next((j for j in range(pos, len(a)) if a[j][col]), None)
        if k is None:
            continue
        a[pos], a[k] = a[k], a[pos]
        inv = pow(a[pos][col], -1, q)
        a[pos] = [x*inv % q for x in a[pos]]
        for j in range(pos+1, len(a)):
            c = a[j][col]
            a[j] = [(x-c*y) % q for x,y in zip(a[j],a[pos])]
        pos += 1
        if pos == len(a):
            break
    return pos

def eye(n: int) -> list[list[int]]:
    return [[int(i == j) for j in range(n)] for i in range(n)]

def add(*matrices: list[list[int]]) -> list[list[int]]:
    return [[sum(m[i][j] for m in matrices) % Q for j in range(len(matrices[0][0]))]
            for i in range(len(matrices[0]))]

def scale(a: int, M: list[list[int]]) -> list[list[int]]:
    return [[a*x % Q for x in row] for row in M]

def mul(A: list[list[int]], B: list[list[int]]) -> list[list[int]]:
    bt = transpose(B)
    return [[sum(x*y for x,y in zip(row,col)) % Q for col in bt] for row in A]

def inverse(A: list[list[int]]) -> list[list[int]]:
    n=len(A)
    cols=[solve(A,[int(i==j) for i in range(n)],Q,n) for j in range(n)]
    if any(c is None for c in cols):
        raise ValueError("singular frame")
    return transpose(cols)

def randmat(rng: random.Random, rows: int, cols: int) -> list[list[int]]:
    return [[rng.randrange(Q) for _ in range(cols)] for _ in range(rows)]

def mask(rng: random.Random, n: int, family: str, frame: list[list[int]] | None = None) -> list[list[int]]:
    if family == 'full':
        return randmat(rng,n,n)
    D=[[rng.randrange(Q) if i == j else 0 for j in range(n)] for i in range(n)]
    if family == 'diagonal':
        return D
    if frame is not None:
        return mul(mul(frame,D),inverse(frame))
    while True:
        U=randmat(rng,n,n)
        if rank(U,Q)==n:
            return mul(mul(U,D),inverse(U))

def gate(a: int, b: int, c: int, d: int, xi: int) -> list[list[int]]:
    return [[a,c,-xi,0],[d,b,0,xi],[0,0,b,c],[0,0,d,a]]

def combine(coefficients: list[list[list[int]]], lam: list[int]) -> list[list[int]]:
    return add(*(scale(v,C) for v,C in zip(lam,coefficients)))

def main() -> None:
    # r1=x^2-x, r2=x-2, feature order 1,x,x^2. This source has NO field witness.
    old_rows=[[0,-1,1],[-2,1,0]]
    new_rows=old_rows+[[0,-2,1]]  # independently mask x*r2 as well.
    e0=[1,0,0]
    lam=solve(old_rows+[e0],[0,0,1],Q,3)
    check(lam == [1,2,2])
    check(all(dot(row,lam,Q)==0 for row in old_rows))
    check(all((x*x-x)%Q or (x-2)%Q for x in range(Q)))
    check(dot(new_rows[-1],lam,Q) == Q-2)
    check(solve(new_rows+[e0],[0,0,0,1],Q,3) is None)
    check(solve(transpose(old_rows),e0,Q,2) is None)
    cert=solve(transpose(new_rows),e0,Q,3)
    check(cert == [51,50,50])
    check(all(sum(cert[j]*new_rows[j][i] for j in range(3))%Q == e0[i] for i in range(3)))
    # Exact alternative: normalized annihilator exists iff unit is NOT in row span.
    census=0
    for bits in itertools.product(range(3),repeat=6):
        rows=[list(bits[:3]),list(bits[3:])]
        functional=solve(rows+[e0],[0,0,1],3,3)
        certificate=solve(transpose(rows),e0,3,2)
        check((functional is not None) != (certificate is not None))
        census+=1
    # True Boolean source: arbitrary finite multiplier degree does not force evaluation.
    true_cases=[]
    for degree in range(9):
        ell=[1]+[2]*(degree+2)
        rows=[]
        for k in range(degree+1):
            row=[0]*(degree+3); row[k+1]=-1; row[k+2]=1; rows.append(row)
        check(all(dot(row,ell,Q)==0 for row in rows))
        check(ell[2] != ell[1]*ell[1]%Q)
        check(rank([[ell[0],ell[1]],[ell[1],ell[2]]],Q)==2)
        # It is the linear combination -Eval_0 + 2 Eval_1, for ALL included degrees.
        for j in range(len(ell)):
            check(ell[j] == (-pow(0,j,Q)+2*pow(1,j,Q))%Q)
        true_cases.append({'max_multiplier_degree':degree,'feature_count':len(ell)})
    # Complete public polynomial arrays for the actual typed-gate template.
    # m=2,b=1,s=5 -> N=9. At x=2 one gate invalid (rank4), one valid(rank2).
    n=9; K=67; I=eye(n)
    public_tag=hashlib.sha3_256(b'audit/claim/branch/' + K.to_bytes(2,'big')).digest()
    cases=[]
    wrong_evaluation_releases=0
    repaired_old_probe_releases=0
    for family in ['full','diagonal','conjugated_diagonal']:
        for seed in range(6):
            rng=random.Random(49000+seed+100*['full','diagonal','conjugated_diagonal'].index(family))
            LR=[(randmat(rng,n,4),randmat(rng,4,n),rng.randrange(Q),rng.randrange(Q)) for _ in range(2)]
            def source(x: int) -> list[list[int]]:
                gates=[gate(x,x,1,x,(LR[0][2]+LR[0][3]*x)%Q),
                       gate(x,1,2,1,(LR[1][2]+LR[1][3]*x)%Q)]
                return add(*(mul(mul(LR[i][0],gates[i]),LR[i][1]) for i in range(2)))
            M0=source(0); M1=add(source(1),scale(-1,M0)); M2=source(2)
            check(M2==add(M0,scale(2,M1)))
            shared_frame=None
            if family == 'conjugated_diagonal':
                while True:
                    shared_frame=randmat(rng,n,n)
                    if rank(shared_frame,Q)==n:
                        break
            A=mask(rng,n,family); B=mask(rng,n,family,shared_frame); D=mask(rng,n,family,shared_frame)
            old=[add(M0,scale(K,I),scale(-2,B)),add(M1,scale(-1,A),B),A]
            forged=combine(old,lam)
            check(forged==add(M2,scale(K,I)))
            mr=rank(M2,Q); check(mr<=6)
            check(rank(add(forged,scale(-K,I)),Q)==mr)
            # This source is false, but K is a root of the mask-cancelled operator.
            candidate_roots=[alpha for alpha in range(Q) if rank(add(forged,scale(-alpha,I)),Q)<n]
            check(K in candidate_roots)
            selected=[alpha for alpha in candidate_roots if hashlib.sha3_256(b'audit/claim/branch/' + alpha.to_bytes(2,'big')).digest()==public_tag]
            check(selected == [K])
            # Not an accepted SOURCE pair: the stricter rank <= N-s=4 test differs.
            point2=combine(old,[1,2,4])
            check(point2==add(M2,scale(K,I),scale(2,A)))
            wrong_evaluation_releases += int(rank(add(point2,scale(-K,I)),Q)<n)
            # Repair: expand Q2 from B to B+xD. Old probe now retains -2D.
            repaired=[old[0],add(old[1],scale(-2,D)),add(old[2],D)]
            check(combine(repaired,lam)==add(forged,scale(-2,D)))
            repaired_old_probe_releases += int(rank(add(combine(repaired,lam),scale(-K,I)),Q)<n)
            # Full coefficient coupling, not just query behaviour, for all key shifts.
            for delta in [1,7,35,100]:
                Ap=add(A,scale(-delta*51,I))
                Bp=add(B,scale(delta*51,I))
                Dp=add(D,scale(delta*51,I))
                shifted=[add(M0,scale(K+delta,I),scale(-2,Bp)),
                         add(M1,scale(-1,Ap),Bp,scale(-2,Dp)),add(Ap,Dp)]
                check(shifted==repaired)
            cases.append({'family':family,'seed':seed,'baseline_rank_at_2':mr,
                          'cancelled_operator_roots':candidate_roots,
                          'key_is_root':K in candidate_roots,'tag_selected_key':selected[0],
                          'passes_supplied_rank_test':mr<=4})
    result={
      'checkpoint':'coefficient-mask-audit-20261022',
      'field':Q,'matrix_dimension':n,'source_constraints':['x^2-x=0','x-2=0'],
      'source_has_witness':False,'normalized_canceller':lam,
      'repair_certificate_coefficients':cert,
      'repaired_normalized_canceller_exists':False,
      'duality_census_cases':census,'true_source_multiplier_cases':true_cases,
      'spectral_cases':cases,
      'total_spectral_cases':len(cases),'key_roots_after_cancellation':sum(c['key_is_root'] for c in cases),
      'cancelled_cases_passing_supplied_rank_test':sum(c['passes_supplied_rank_test'] for c in cases),
      'point2_eigenvalue_incidents':wrong_evaluation_releases,
      'old_probe_eigenvalue_incidents_after_repair':repaired_old_probe_releases,
      'assertions':COUNT,
      'limits':['The restricted false-source mask-space repair is exact, not a general PQ WKEM proof.',
                'Small-field root enumeration validates roots, not cryptographic-scale runtime.',
                'The generic public quotient fact was already documented in QUOTIENT_AND_PROBE.md.',
                'A public rank-check rejection does not prevent direct credential use.',
                'No quantum algorithm was executed; formal cancellation is already classical.',
                'The parameter family tested is allowed by Run707, not a claim about a deployed instance.'],
      'checker_sha256':hashlib.sha256(open(__file__,'rb').read()).hexdigest()
    }
    print(json.dumps(result,sort_keys=True,indent=2))

if __name__=='__main__':
    main()
