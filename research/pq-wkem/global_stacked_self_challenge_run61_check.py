#!/usr/bin/env python3
import json, math, random
SEED = 0x61A11CE
rng = random.Random(SEED)

def solve_status(A_rows, c_bits, nvars):
    basis = {}  # pivot -> augmented row
    contradiction = False
    rhs_mask = 1 << nvars
    var_mask = rhs_mask - 1
    for row, bit in zip(A_rows, c_bits):
        x = row | ((bit & 1) << nvars)
        while True:
            v = x & var_mask
            if not v:
                if x & rhs_mask:
                    contradiction = True
                break
            p = v.bit_length() - 1
            if p in basis:
                x ^= basis[p]
            else:
                basis[p] = x
                break
        if contradiction:
            return False, len(basis)
    return True, len(basis)

def random_system(m, D):
    return [rng.getrandbits(D) for _ in range(m)], [rng.getrandbits(1) for _ in range(m)]

def count_solutions_exhaustive(A, c, D):
    count = 0
    for u in range(1 << D):
        good = True
        for row, bit in zip(A, c):
            if ((row & u).bit_count() & 1) != bit:
                good = False
                break
        count += good
    return count

def predicted_solution_count(A,c,D):
    ok,r = solve_status(A,c,D)
    return (1 << (D-r)) if ok else 0

results={"run":61,"seed":SEED,"model":"globally stacked affine self-challenges on one-bad-block affine false fibers","tests":{}}

small={}
for k in (3,4):
    B=1<<k; D=B-k-2
    fixtures=80 if k==3 else 40
    per={}
    for m in sorted(set([max(1,D-1),D,D+1,D+k])):
        mism=surv=0
        for _ in range(fixtures):
            A,c=random_system(m,D)
            ex=count_solutions_exhaustive(A,c,D)
            pr=predicted_solution_count(A,c,D)
            surv += int(ex>0)
            mism += int(ex!=pr)
        per[str(m)]={"systems":fixtures,"survivors":surv,"count_mismatches":mism}
    small[str(k)]={"B":B,"D":D,"per_m":per}
results["tests"]["small_exact_enumeration"]=small

k=8; B=1<<k; D=B-k-2; R=48; m=R*k
joint={"k":k,"B":B,"D":D,"R":R,"stacked_bits":m,"union_bound_log2":k+D-m,
       "fibers":B,"surviving_fibers":0,"full_column_rank_fibers":0,"inconsistent_fibers":0}
for _ in range(B):
    A,c=random_system(m,D)
    ok,r=solve_status(A,c,D)
    joint["surviving_fibers"] += int(ok)
    joint["full_column_rank_fibers"] += int(r==D)
    joint["inconsistent_fibers"] += int(not ok)
results["tests"]["run60_joint_global"]=joint

roundwise={"k":k,"D":D,"rounds":32,"fibers_per_round":B,"systems":0,"solvable":0,"full_row_rank":0,"unsolved":0}
for _ in range(roundwise["rounds"]):
    for _ in range(B):
        A,c=random_system(k,D)
        ok,r=solve_status(A,c,D)
        roundwise["systems"]+=1; roundwise["solvable"]+=int(ok); roundwise["unsolved"]+=int(not ok); roundwise["full_row_rank"]+=int(r==k)
results["tests"]["roundwise_separable"]=roundwise

phase={}
for m in [232,240,246,248,256,264]:
    trials=250; sol=0; ranks={}
    for _ in range(trials):
        A,c=random_system(m,D)
        ok,r=solve_status(A,c,D)
        sol+=int(ok); ranks[str(r)]=ranks.get(str(r),0)+1
    phase[str(m)]={"trials":trials,"solvable":sol,"fraction":sol/trials,"simple_upper_bound":min(1.0,2.0**(D-m)),"rank_histogram":ranks}
results["tests"]["phase_transition"]=phase

overheads={}
for lam in [64,96,128,192]:
    Rneed=math.ceil((D+k+lam)/k)
    overheads[str(lam)]={"R_min_union_bound":Rneed,"stacked_bits":Rneed*k,"union_bound_log2":k+D-Rneed*k}
results["tests"]["overhead"]=overheads

assert all(all(vv["count_mismatches"]==0 for vv in v["per_m"].values()) for v in small.values())
assert joint["surviving_fibers"]==0
assert roundwise["unsolved"]==0
assert overheads["128"]["R_min_union_bound"]==48 and overheads["128"]["union_bound_log2"]<=-128
print(json.dumps(results,indent=2,sort_keys=True))
