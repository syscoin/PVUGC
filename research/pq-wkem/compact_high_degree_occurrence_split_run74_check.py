#!/usr/bin/env python3
import itertools
import json
import random

SEED = 740074001
P = 257

# literal = (variable_index, positive_bool)
def lit_sat(lit, assignment):
    i, positive = lit
    return assignment[i] == (1 if positive else 0)

def clause_sat(clause, assignment):
    return any(lit_sat(lit, assignment) for lit in clause)

def formula_sat(formula, assignment):
    return all(clause_sat(c, assignment) for c in formula)

def witness_count(formula, n):
    return sum(formula_sat(formula, a)
               for a in itertools.product((0,1), repeat=n))

def clause_unsat_indicator(clause, assignment):
    # Product of literal-falsity bits; exact over integers/any field.
    u = 1
    for i, positive in clause:
        literal_value = assignment[i] if positive else (1-assignment[i])
        u *= (1-literal_value)
    return u

def compact_accept(formula, assignment):
    # High-degree compact circuit:
    # A(w)=product_c (1-u_c(w)); size O(total literal occurrences).
    A = 1
    for c in formula:
        A *= 1 - clause_unsat_indicator(c, assignment)
    return A

def satisfy_clause_locally(clause, n):
    # Every nonempty CNF clause has a local satisfying assignment.
    a = [0]*n
    i, positive = clause[0]
    a[i] = 1 if positive else 0
    return tuple(a)

def split_accept(formula, local_assignments):
    assert len(formula) == len(local_assignments)
    A = 1
    for c, a in zip(formula, local_assignments):
        A *= 1 - clause_unsat_indicator(c, a)
    return A

def all_local_splice(formula, n):
    locals_ = [satisfy_clause_locally(c, n) for c in formula]
    return locals_, split_accept(formula, locals_)

def eq_bit(a,b):
    return 1 if a == b else 0

def repeated_read_equality_repair_x_notx(num_eq_checks):
    # Formula is (x) AND (not x). Clause-block reads are independent.
    # Each equality checker also gets fresh occurrence reads, so it can be
    # satisfied locally without constraining the clause-block reads.
    clause1_read = 1
    clause2_read = 0
    accept = clause1_read * (1-clause2_read)
    equality_reads = []
    for j in range(num_eq_checks):
        left = j & 1
        right = j & 1
        equality_reads.append((left,right))
        accept *= eq_bit(left,right)
    return accept, clause1_read, clause2_read, equality_reads

def random_unsat_formula(rng, n, extra_clauses):
    # Contradictory unit pair guarantees false; all clauses nonempty and
    # individually satisfiable.
    F = [((0, True),), ((0, False),)]
    for _ in range(extra_clauses):
        width = rng.randint(1, min(4,n))
        vars_ = rng.sample(range(n), width)
        c = tuple((i, bool(rng.getrandbits(1))) for i in vars_)
        F.append(c)
    return F

def alternating_cube_identity(r):
    # Control tying this run to Run 73: compact degree-r product exists
    # without monomial expansion, but occurrence splitting bypasses it.
    # A(x)=prod_i (1-x_i) * (1-prod_i(1-x_i)) is identically zero for the
    # false family (AND not x_i) AND (OR x_i).
    vals = {}
    for w in itertools.product((0,1), repeat=r):
        first = 1
        for x in w:
            first *= (1-x)
        or_sat = 1 - first
        vals[w] = first * or_sat
    return vals

def hidden_operator_share_control(rng, operators, formula, n):
    # Semantic N-of-N control: each operator masks its own target share, but
    # if its public program accepts the same occurrence-split schedule then
    # every share is released. This does not model crypto security; it
    # validates only that operator replication does not repair semantic split.
    locals_, ok = all_local_splice(formula, n)
    assert ok == 1
    shares = [rng.randrange(P) for _ in range(operators)]
    released = [s if split_accept(formula, locals_) == 1 else None for s in shares]
    return shares, released

def run():
    rng = random.Random(SEED)
    report = {
        "seed": SEED,
        "prime_for_share_control": P,
        "claim_scope": (
            "exact semantics/algebra tests only; no cryptographic security is "
            "inferred from passing tests"
        ),
    }

    # 1. Exact compact-circuit semantics on random formulas.
    compact_semantics = 0
    for n in range(2,7):
        for _ in range(80):
            m = rng.randint(1,8)
            F = []
            for _ in range(m):
                width = rng.randint(1,min(4,n))
                vars_ = rng.sample(range(n), width)
                F.append(tuple((i,bool(rng.getrandbits(1))) for i in vars_))
            for a in itertools.product((0,1), repeat=n):
                assert compact_accept(F,a) == int(formula_sat(F,a))
                compact_semantics += 1

    # 2. Explicit false fixtures: consistent evaluation always rejects,
    # occurrence-split evaluation accepts.
    fixtures = [
        ([((0,True),), ((0,False),)], 1),
        ([((0,False),), ((1,False),), ((0,True),(1,True))], 2),
        ([((0,True),), ((0,False),), ((1,True),(2,False))], 3),
    ]
    explicit_false_checks = 0
    for F,n in fixtures:
        assert witness_count(F,n) == 0
        for a in itertools.product((0,1), repeat=n):
            assert compact_accept(F,a) == 0
            explicit_false_checks += 1
        locals_, ok = all_local_splice(F,n)
        assert ok == 1
        assert all(clause_sat(c,a) for c,a in zip(F,locals_))

    # 3. Random guaranteed-false CNFs: every local clause can still be
    # satisfied independently.
    random_false_formulas = 0
    random_split_accepts = 0
    total_local_blocks = 0
    for n in range(2,7):
        for _ in range(100):
            F = random_unsat_formula(rng,n,rng.randint(0,8))
            assert witness_count(F,n) == 0
            locals_, ok = all_local_splice(F,n)
            assert ok == 1
            assert all(clause_sat(c,a) for c,a in zip(F,locals_))
            random_false_formulas += 1
            random_split_accepts += ok
            total_local_blocks += len(F)

    # 4. Compact high-degree false family, r=2..12. The consistent circuit is
    # identically zero although its degree grows with r; occurrence splitting
    # accepts by choosing a local assignment for every conjunct.
    compact_high_degree_families = 0
    max_degree_proxy = 0
    for r in range(2,13):
        vals = alternating_cube_identity(r)
        assert set(vals.values()) == {0}
        F = [((i,False),) for i in range(r)]
        F.append(tuple((i,True) for i in range(r)))
        assert witness_count(F,r) == 0
        _, ok = all_local_splice(F,r)
        assert ok == 1
        compact_high_degree_families += 1
        # Literal-occurrence degree upper bound of direct acceptance product.
        max_degree_proxy = max(max_degree_proxy, 2*r)

    # 5. Equality/checksum repair regression: any number of local equality
    # blocks can be satisfied on fresh reads while the two clause reads differ.
    equality_repair_checks = 0
    for k in list(range(0,65)) + [128,256,512]:
        accept,c1,c2,reads = repeated_read_equality_repair_x_notx(k)
        assert c1 != c2
        assert accept == 1
        assert all(a == b for a,b in reads)
        equality_repair_checks += 1

    # 6. N-of-N semantic replication does not repair the split.
    operator_controls = 0
    operator_shares_released = 0
    F = [((0,True),), ((0,False),)]
    for N in range(2,17):
        for _ in range(20):
            shares,released = hidden_operator_share_control(rng,N,F,1)
            assert released == shares
            operator_controls += 1
            operator_shares_released += len(released)

    # 7. Polynomial-size accounting for the direct compact source circuit.
    # For a CNF with L literal occurrences and m clauses:
    # - clause-unsat products need sum_c(|C_c|-1) multiplications;
    # - clause satisfaction conversions are m subtractions;
    # - final product needs m-1 multiplications.
    # Total multiplication count <= L-1 when m>0 (empty/singleton edge cases
    # only improve it); public branch reads = L if every occurrence is read.
    resource_controls = 0
    max_L = 0
    for n in range(2,8):
        for _ in range(80):
            m = rng.randint(1,12)
            F = []
            for _ in range(m):
                width = rng.randint(1,min(5,n))
                vars_ = rng.sample(range(n),width)
                F.append(tuple((i,bool(rng.getrandbits(1))) for i in vars_))
            L = sum(len(c) for c in F)
            mult_clause = sum(max(0,len(c)-1) for c in F)
            mult_final = max(0,m-1)
            assert mult_clause + mult_final == L-1
            max_L = max(max_L,L)
            resource_controls += 1

    report.update({
        "compact_semantics_assignment_checks": compact_semantics,
        "explicit_false_consistent_assignment_checks": explicit_false_checks,
        "random_guaranteed_false_formulas": random_false_formulas,
        "random_occurrence_split_accepts": random_split_accepts,
        "random_local_blocks_satisfied": total_local_blocks,
        "compact_high_degree_false_families_r_2_through_12": compact_high_degree_families,
        "max_direct_degree_proxy_in_family": max_degree_proxy,
        "local_equality_repair_cases": equality_repair_checks,
        "n_of_n_operator_controls": operator_controls,
        "operator_shares_released_under_split": operator_shares_released,
        "resource_accounting_cases": resource_controls,
        "max_literal_occurrences_in_resource_cases": max_L,
        "status": "PASS",
    })
    return report

if __name__ == "__main__":
    print(json.dumps(run(), sort_keys=True, indent=2))
