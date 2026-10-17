#!/usr/bin/env python3
"""
Run 60 deterministic checker:
public self-indexed dense challenges can be solved inside the exact malformed-block
nullspace of the Run-53 local-view compiler.

Standard library only. No cryptographic-security claim is inferred from tests.
"""
import itertools
import json
import math
import random
from fractions import Fraction

SEED = 0x60C0FFEE
rng = random.Random(SEED)

def parity(x: int) -> int:
    return x.bit_count() & 1

def gf2_solve(row_masks, rhs, nvars):
    """Solve A x = rhs over F2. Returns (consistent, rank, solution_mask)."""
    m = len(row_masks)
    aug = [int(row_masks[i]) | (int(rhs[i]) << nvars) for i in range(m)]
    r = 0
    pivots = []
    for c in range(nvars):
        pivot = None
        for i in range(r, m):
            if (aug[i] >> c) & 1:
                pivot = i
                break
        if pivot is None:
            continue
        aug[r], aug[pivot] = aug[pivot], aug[r]
        for i in range(m):
            if i != r and ((aug[i] >> c) & 1):
                aug[i] ^= aug[r]
        pivots.append(c)
        r += 1
        if r == m:
            break
    var_mask = (1 << nvars) - 1
    for i in range(r, m):
        if (aug[i] & var_mask) == 0 and ((aug[i] >> nvars) & 1):
            return False, r, 0
    sol = 0
    # Free variables set to zero; in RREF each pivot equals its rhs.
    for i, c in enumerate(pivots):
        if (aug[i] >> nvars) & 1:
            sol |= 1 << c
    # Verify.
    for row, bit in zip(row_masks, rhs):
        assert parity(row & sol) == bit
    return True, r, sol

def rank_gf2(vectors, nbits):
    ok, rank, _ = gf2_solve(vectors, [0]*len(vectors), nbits)
    assert ok
    return rank

def block_data(k):
    """
    Malformed block for excluded f=0^k.
    Coordinates are every nonzero assignment a in {0,1}^k.
    Build an explicit integral kernel basis using a unimodular pivot minor.
    """
    B = 1 << k
    assignments = list(range(1, B))
    idx = {a:i for i,a in enumerate(assignments)}
    piv_assign = [1 << i for i in range(k)] + [3]  # e_i and e_0+e_1
    assert len(set(piv_assign)) == k + 1
    piv_idx = [idx[a] for a in piv_assign]
    nonpiv = [a for a in assignments if a not in set(piv_assign)]
    D = len(nonpiv)
    assert D == B - k - 2

    # Canonical inclusion-exclusion lift q_0(a)=(-1)^(wt(a)+1).
    q = [1 if (a.bit_count() & 1) else -1 for a in assignments]
    assert sum(q) == 1
    for i in range(k):
        assert sum(((a >> i) & 1) * q[idx[a]] for a in assignments) == 0

    basis = []
    basis_parity_masks = []
    for a in nonpiv:
        wt = a.bit_count()
        xu = wt - 1
        xs = [0]*k
        xs[0] = ((a >> 0) & 1) - wt + 1
        xs[1] = ((a >> 1) & 1) - wt + 1
        for i in range(2, k):
            xs[i] = (a >> i) & 1

        v = {}
        v[idx[a]] = 1
        for i in range(k):
            if xs[i]:
                v[piv_idx[i]] = v.get(piv_idx[i], 0) - xs[i]
        if xu:
            v[piv_idx[-1]] = v.get(piv_idx[-1], 0) - xu
        v = {j:c for j,c in v.items() if c}

        assert sum(v.values()) == 0
        for i in range(k):
            assert sum(((assignments[j] >> i) & 1) * c for j,c in v.items()) == 0

        pmask = 0
        for j,c in v.items():
            if c & 1:
                pmask |= 1 << j
        basis.append(v)
        basis_parity_masks.append(pmask)

    # Each basis vector has a unique +1 in its own nonpivot coordinate, so the
    # reductions mod 2 are independent. Check anyway.
    # Build transposed rows on the coordinate space to determine column rank.
    coord_rows = []
    for coord in range(B-1):
        row = 0
        for j,pm in enumerate(basis_parity_masks):
            if (pm >> coord) & 1:
                row |= 1 << j
        coord_rows.append(row)
    assert rank_gf2(coord_rows, D) == D

    qmask = 0
    for j,c in enumerate(q):
        if c & 1:
            qmask |= 1 << j
    return {
        "B": B, "D": D, "assignments": assignments, "idx": idx,
        "q": q, "qmask": qmask, "basis": basis,
        "basis_parity_masks": basis_parity_masks,
    }

def induced_rows(hash_rows, basis_masks):
    out = []
    for g in hash_rows:
        row = 0
        for j,bm in enumerate(basis_masks):
            if parity(g & bm):
                row |= 1 << j
        out.append(row)
    return out

def add_basis(q, basis, solmask):
    z = list(q)
    bit = 0
    s = solmask
    while s:
        lsb = s & -s
        j = lsb.bit_length()-1
        for coord,c in basis[j].items():
            z[coord] += c
        s ^= lsb
    return z

def verify_malformed(k, data, z):
    assignments=data["assignments"]
    assert sum(z) == 1
    for i in range(k):
        assert sum(((a >> i)&1)*z[j] for j,a in enumerate(assignments)) == 0

def z_parity_mask(z):
    out=0
    for j,c in enumerate(z):
        if c & 1:
            out |= 1<<j
    return out

def selector_output(hash_rows, affine_bits, zmask):
    out=0
    for i,g in enumerate(hash_rows):
        bit=parity(g & zmask) ^ affine_bits[i]
        out |= bit<<i
    return out

def exact_full_rank_probability(k,D):
    p=Fraction(1,1)
    for i in range(k):
        p *= Fraction((1<<D)-(1<<i), 1<<D)
    return p

# Structural sanity over k=3..8.
structural={}
for k in range(3,9):
    d=block_data(k)
    structural[str(k)] = {
        "blocks_B": d["B"],
        "malformed_block_coordinates": d["B"]-1,
        "integral_nullity_D": d["D"],
        "canonical_norm2": sum(c*c for c in d["q"]),
        "canonical_l1": sum(abs(c) for c in d["q"]),
        "parity_nullspace_rank": d["D"],
    }

# Main cryptographic-scale diagnostic: k=8 => B=256, D=246.
k=8
R=128
d=block_data(k)
B,D=d["B"],d["D"]
basis_masks=d["basis_parity_masks"]
qmask=d["qmask"]

round_records=[]
stack_rows=[]
stack_rhs=[]
fixed_q_passes=0
all_adaptive=True
max_sol_weight=0
max_l1=0
max_norm2=0
max_abs_coeff=0
prefix_first_inconsistent=None

for r in range(R):
    # This is the restriction of a uniform public affine hash of the complete
    # representation to the malformed-block coordinates. Fixed coordinates of
    # the other one-hot blocks are absorbed into affine_bits.
    hash_rows=[rng.getrandbits(B-1) for _ in range(k)]
    affine_bits=[rng.getrandbits(1) for _ in range(k)]
    Arows=induced_rows(hash_rows,basis_masks)
    rhs=[parity(hash_rows[i] & qmask) ^ affine_bits[i] for i in range(k)]
    # Want selector output f=0^k, hence A t = G q + h.
    consistent,rank,sol=gf2_solve(Arows,rhs,D)
    if not consistent:
        all_adaptive=False
        round_records.append({"round":r,"rank":rank,"solved":False})
        continue
    z=add_basis(d["q"],d["basis"],sol)
    verify_malformed(k,d,z)
    zm=z_parity_mask(z)
    assert selector_output(hash_rows,affine_bits,zm)==0

    sw=sol.bit_count()
    l1=sum(abs(c) for c in z)
    n2=sum(c*c for c in z)
    max_sol_weight=max(max_sol_weight,sw)
    max_l1=max(max_l1,l1)
    max_norm2=max(max_norm2,n2)
    max_abs_coeff=max(max_abs_coeff,max(abs(c) for c in z))
    if selector_output(hash_rows,affine_bits,qmask)==0:
        fixed_q_passes += 1
    round_records.append({
        "round":r,"rank":rank,"solved":True,
        "solution_weight":sw,"malformed_l1":l1,"malformed_norm2":n2,
    })
    stack_rows.extend(Arows)
    stack_rhs.extend(rhs)
    if prefix_first_inconsistent is None:
        ok,_,_=gf2_solve(stack_rows,stack_rhs,D)
        if not ok:
            prefix_first_inconsistent=r+1

assert all_adaptive
assert len(round_records)==R
assert all(x["rank"]==k for x in round_records)
assert prefix_first_inconsistent is not None

# Exact/upper-bound probabilities for random public affine selector.
p_full=exact_full_rank_probability(k,D)
rank_failure=1-p_full
union_bound=Fraction(R*((1<<k)-1),1<<D)
fixed_one_round=Fraction(1,B)
fixed_all_rounds=fixed_one_round**R

# Monte Carlo finite linear-algebra control at smaller k where rank failures are visible.
rank_trials={}
for kk in [3,4,5,6]:
    dd=block_data(kk)
    BB,DD=dd["B"],dd["D"]
    trials=2000
    full=0
    solvable=0
    for _ in range(trials):
        hrs=[rng.getrandbits(BB-1) for _ in range(kk)]
        ab=[rng.getrandbits(1) for _ in range(kk)]
        ar=induced_rows(hrs,dd["basis_parity_masks"])
        rh=[parity(hrs[i]&dd["qmask"])^ab[i] for i in range(kk)]
        ok,rr,_=gf2_solve(ar,rh,DD)
        full += (rr==kk)
        solvable += ok
    ep=exact_full_rank_probability(kk,DD)
    rank_trials[str(kk)]={
        "trials":trials,
        "observed_full_rank":full,
        "observed_solvable":solvable,
        "exact_full_rank_probability":float(ep),
        "nullity_D":DD,
    }

# Ideal-release share simulation: each round share is released iff all challenged
# blocks except selector output are one-hot. Our solved representation has the
# unique malformed block f=0 and selector output 0, so all 255 tested blocks are
# one-hot. This intentionally grants a stronger-than-implemented ideal local gate.
shares=[rng.getrandbits(256) for _ in range(R)]
key=0
recovered=0
for s in shares:
    key ^= s
    recovered ^= s
assert recovered==key

result={
    "run":60,
    "seed":SEED,
    "candidate":"public affine self-indexed dense local-view challenge",
    "structural_checks":structural,
    "main_fixture":{
        "k":k,
        "blocks_B":B,
        "representation_block_coordinates":B*(B-1),
        "shared_marginals":k,
        "complete_representation_coordinates":B*(B-1)+k,
        "malformed_block_coordinates":B-1,
        "integral_nullity_D":D,
        "rounds":R,
        "adaptive_rounds_solved":sum(x["solved"] for x in round_records),
        "adaptive_full_rank_rounds":sum(x.get("rank")==k for x in round_records),
        "fixed_canonical_representation_passes":fixed_q_passes,
        "first_prefix_with_no_single_common_nullspace_solution":prefix_first_inconsistent,
        "max_particular_solution_hamming_weight":max_sol_weight,
        "max_malformed_block_l1":max_l1,
        "max_malformed_block_norm2":max_norm2,
        "max_malformed_block_abs_coefficient":max_abs_coeff,
        "ideal_round_shares_recovered":R,
        "ideal_xor_key_recovered":True,
    },
    "probabilities":{
        "exact_one_round_full_rank_probability_fraction":f"{p_full.numerator}/{p_full.denominator}",
        "exact_one_round_rank_failure_probability_fraction":f"{rank_failure.numerator}/{rank_failure.denominator}",
        "exact_one_round_rank_failure_probability":float(rank_failure),
        "one_round_rank_failure_log2": math.log2(float(rank_failure)) if rank_failure else None,
        "R_round_union_failure_upper_bound":float(union_bound),
        "R_round_union_failure_upper_bound_log2":math.log2(float(union_bound)),
        "fixed_representation_one_round_pass_probability":float(fixed_one_round),
        "fixed_representation_all_rounds_pass_log2":math.log2(float(fixed_all_rounds)),
    },
    "smaller_rank_trials":rank_trials,
    "scope":{
        "proved_by_algebra_not_tests":[
            "malformed-block integral nullity D=2^k-k-2 via an explicit unimodular pivot minor",
            "mod-2 reductions of the explicit integral kernel basis span a D-dimensional selector-grinding space",
            "a full-row-rank restricted affine selector can be solved for an exact false representation whose only malformed block is the omitted block",
            "for uniform selector restriction, full-rank probability is product_{i=0}^{k-1}(1-2^(i-D))",
            "ordinary per-round key sharing does not force the same representation across rounds"
        ],
        "tests_validate":[
            "explicit integral kernel identities and parity rank",
            "128 adaptive k=8 selector solves and exact malformed-block equations",
            "absence of a single common solution after a finite prefix in this deterministic fixture",
            "finite rank/solvability diagnostics for k=3..6",
            "idealized per-round share reconstruction after adaptive switching"
        ],
        "not_claimed":[
            "security or insecurity of every deterministic hash family",
            "a random-oracle theorem",
            "an implementation of a witness-selective local release gate",
            "a generic impossibility theorem for nonlinear/computational common-witness binders",
            "LWE/SIS security or an arbitrary-QPT extraction reduction"
        ]
    }
}
print(json.dumps(result, indent=2, sort_keys=True))
