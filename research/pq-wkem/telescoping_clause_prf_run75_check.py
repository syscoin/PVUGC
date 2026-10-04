#!/usr/bin/env python3
import hashlib
import itertools
import json
import random

SEED = 750075001

# ---------- CNF utilities ----------
# literal = (var_index, positive)
def lit_sat(lit, w):
    i, pos = lit
    return w[i] == (1 if pos else 0)

def clause_sat(clause, w):
    return any(lit_sat(l, w) for l in clause)

def formula_sat(formula, w):
    return all(clause_sat(c, w) for c in formula)

def assignments(n):
    return list(itertools.product((0,1), repeat=n))

def satisfying_set(clause, n):
    return [w for w in assignments(n) if clause_sat(clause, w)]

# ---------- GF(2) linear algebra with row bitsets ----------
def gf2_rank(rows):
    rows = [int(r) for r in rows if r]
    rank = 0
    while rows:
        p = max(rows)
        bit = p.bit_length() - 1
        rows.remove(p)
        new = []
        for r in rows:
            if (r >> bit) & 1:
                r ^= p
            if r:
                new.append(r)
        rows = new
        rank += 1
    return rank

def gf2_in_span(columns, target, out_dim):
    # columns are output vectors represented as ints of out_dim bits.
    # target is same.
    return gf2_rank(columns) == gf2_rank(columns + [target])

# ---------- Ideal difference-only construction ----------
def ideal_linear_map(formula, n):
    """
    Build the complete-output affine map:
      D_c(w)=R_{c-1}(w) xor R_c(w) on satisfying w,
      R_0=0, R_m=K.
    Each hidden R_j(w), 1<=j<m, is an independent random bit.
    Returns columns for hidden random bits and target vector for K.
    """
    m = len(formula)
    W = assignments(n)
    outputs = []
    for c, clause in enumerate(formula, start=1):
        for wi, w in enumerate(W):
            if clause_sat(clause, w):
                outputs.append((c, wi))
    out_index = {ow:i for i,ow in enumerate(outputs)}
    out_dim = len(outputs)

    hidden_cols = []
    # one variable R_j(w) for every interior layer and witness point
    for j in range(1, m):
        for wi, w in enumerate(W):
            col = 0
            # appears in edge j at w if clause j satisfied
            if clause_sat(formula[j-1], w):
                col ^= 1 << out_index[(j, wi)]
            # appears in edge j+1 at w if clause j+1 satisfied
            if clause_sat(formula[j], w):
                col ^= 1 << out_index[(j+1, wi)]
            hidden_cols.append(col)

    key_vec = 0
    if m >= 1:
        for wi, w in enumerate(W):
            if clause_sat(formula[m-1], w):
                key_vec ^= 1 << out_index[(m, wi)]
    return outputs, hidden_cols, key_vec

def ideal_key_hidden(formula, n):
    outs, cols, kv = ideal_linear_map(formula, n)
    return gf2_in_span(cols, kv, len(outs))

def ideal_decap(formula, w, internal_values, keybit):
    # internal_values[(j,w)] bit, where j in 1..m-1
    m = len(formula)
    acc = 0
    for c in range(1,m+1):
        if not clause_sat(formula[c-1], w):
            raise ValueError("w not accepted by clause")
        left = 0 if c == 1 else internal_values[(c-1,w)]
        right = keybit if c == m else internal_values[(c,w)]
        acc ^= left ^ right
    return acc

# ---------- Prefix-cover for complement of a clause's falsifying subcube ----------
def falsifying_pattern(clause):
    # Return dict var->bit that falsifies all literals, or None for tautology.
    pat = {}
    for i,pos in clause:
        b = 0 if pos else 1
        if i in pat and pat[i] != b:
            return None  # tautology: no falsifying assignment
        pat[i] = b
    return pat

def prefix_cover_complement_subcube(order, pattern):
    """
    Disjoint prefix cover of assignments that do NOT match `pattern`
    on all constrained variables. `order` is a variable permutation.
    Prefix is tuple of bits in that order.
    """
    if pattern is None:
        return [tuple()]  # tautology: all domain
    pos = {v:i for i,v in enumerate(order)}
    fixed_positions = sorted((pos[v], bit) for v,bit in pattern.items())
    if not fixed_positions:
        return []  # empty clause: satisfying domain empty
    cover = []
    # Enumerate first constrained mismatch, with free earlier coordinates explicit.
    for idx,(p,bit) in enumerate(fixed_positions):
        earlier_fixed = {pp:bb for pp,bb in fixed_positions[:idx]}
        free = [j for j in range(p) if j not in earlier_fixed]
        for free_bits in itertools.product((0,1), repeat=len(free)):
            prefix = [None]*(p+1)
            for pp,bb in earlier_fixed.items():
                prefix[pp] = bb
            for pp,bb in zip(free,free_bits):
                prefix[pp] = bb
            prefix[p] = 1-bit
            assert all(x is not None for x in prefix)
            cover.append(tuple(prefix))
    return cover

def prefix_matches(prefix, w, order):
    return all(w[order[i]] == b for i,b in enumerate(prefix))

def cover_accepts(cover, w, order):
    return any(prefix_matches(p,w,order) for p in cover)

# ---------- Toy PRF values and component-leak attack ----------
def toy_value(seed, layer, w):
    # deterministic bit; cryptographic security is NOT claimed.
    h = hashlib.sha256(seed + layer.to_bytes(4,'big') + bytes(w)).digest()
    return h[0] & 1

def component_leak_attack(formula, n, rng):
    """
    Idealized audit of the naive GGM realization that exposes component
    constrained evaluators. We do not need the internal seed representation:
    the complete public view gives R_j(w) on every w satisfying either
    adjacent clause. Final difference D_m is also evaluable on S_m.
    For any locally satisfiable last clause, choose w in S_m and recover
    K = D_m(w) xor R_{m-1}(w).
    """
    m = len(formula)
    if m == 1:
        # D_1(w)=K directly on S_1.
        S = satisfying_set(formula[0], n)
        if not S:
            return None
        return 1  # caller compares via explicit generation separately
    Slast = satisfying_set(formula[-1], n)
    if not Slast:
        return None
    w = rng.choice(Slast)
    key = rng.randrange(2)
    seeds = {j:rng.randbytes(16) for j in range(1,m)}
    rlast = toy_value(seeds[m-1], m-1, w)
    dlast = rlast ^ key
    recovered = dlast ^ rlast
    return key, recovered, w

# ---------- Exact XOR-key-homomorphic explicit-output PRF barrier ----------
def random_bitmatrix(out_bits, key_bits, rng):
    # Rows represented as key-bit masks.
    rows = []
    for _ in range(out_bits):
        rows.append(rng.getrandbits(key_bits))
    return rows

def mat_apply_rows(rows, key):
    y = 0
    for i,row in enumerate(rows):
        if (row & key).bit_count() & 1:
            y |= 1 << i
    return y

def stacked_columns(matrices, key_bits, out_bits):
    # Build image columns for stacked transcript over matrices.
    cols = []
    for j in range(key_bits):
        col = 0
        shift = 0
        for M in matrices:
            y = mat_apply_rows(M, 1<<j)
            col |= y << shift
            shift += out_bits
        cols.append(col)
    return cols

def homomorphic_membership_trial(key_bits, out_bits, queries, rng):
    matrices = [random_bitmatrix(out_bits,key_bits,rng) for _ in range(queries)]
    cols = stacked_columns(matrices,key_bits,out_bits)
    key = rng.getrandbits(key_bits)
    transcript = 0
    shift = 0
    for M in matrices:
        transcript |= mat_apply_rows(M,key) << shift
        shift += out_bits
    assert gf2_in_span(cols, transcript, queries*out_bits)
    # Return image rank and random-membership control.
    rank = gf2_rank(cols)
    random_y = rng.getrandbits(queries*out_bits)
    random_in = gf2_in_span(cols, random_y, queries*out_bits)
    return rank, random_in

# ---------- Formula generation ----------
def random_clause(rng, n, width=None):
    if width is None:
        width = rng.randint(1,min(3,n))
    vars_ = rng.sample(range(n), width)
    return tuple((i,bool(rng.getrandbits(1))) for i in vars_)

def random_formula(rng,n,m):
    return [random_clause(rng,n) for _ in range(m)]

def guaranteed_false_formula(rng,n,m):
    # contradictory unit pair plus nonempty random clauses
    F = [((0,True),), ((0,False),)]
    while len(F)<m:
        F.append(random_clause(rng,n))
    return F

def run():
    rng = random.Random(SEED)
    report = {
        "seed": SEED,
        "scope": "finite algebra/semantics validation only; no cryptographic security inferred from tests",
    }

    # 1. Ideal complete-output theorem: hidden iff false, revealed iff true.
    ideal_cases = 0
    false_hidden = 0
    true_revealed = 0
    for n in range(1,5):
        for _ in range(180):
            m = rng.randint(1,5)
            F = random_formula(rng,n,m)
            sat = any(formula_sat(F,w) for w in assignments(n))
            hidden = ideal_key_hidden(F,n)
            assert hidden == (not sat)
            ideal_cases += 1
            false_hidden += int((not sat) and hidden)
            true_revealed += int(sat and (not hidden))

    # Explicit false fixtures including Run-74 minimal split example.
    false_fixtures = [
        ([((0,True),),((0,False),)],1),
        ([((0,False),),((1,False),),((0,True),(1,True))],2),
        ([((0,True),),((0,False),),((1,True),(2,False))],3),
    ]
    for F,n in false_fixtures:
        assert not any(formula_sat(F,w) for w in assignments(n))
        assert ideal_key_hidden(F,n)

    # 2. Honest same-witness telescope.
    honest_decaps = 0
    for n in range(1,5):
        for _ in range(100):
            # Force a satisfiable formula by sampling clauses satisfied by target.
            target = tuple(rng.randrange(2) for _ in range(n))
            m = rng.randint(1,6)
            F=[]
            for _ in range(m):
                while True:
                    c=random_clause(rng,n)
                    if clause_sat(c,target):
                        F.append(c); break
            internal={}
            for j in range(1,m):
                for w in assignments(n):
                    internal[(j,w)] = rng.randrange(2)
            k=rng.randrange(2)
            got=ideal_decap(F,target,internal,k)
            assert got==k
            honest_decaps += 1

    # 3. Prefix-cover compactness/correctness with per-interior-function
    # permutations putting variables from its two adjacent clauses first.
    cover_cases=0
    max_cover=0
    max_union=0
    for n in range(3,13):
        for _ in range(120):
            c1=random_clause(rng,n, rng.randint(1,min(3,n)))
            c2=random_clause(rng,n, rng.randint(1,min(3,n)))
            union=[]
            for c in (c1,c2):
                for v,_ in c:
                    if v not in union:
                        union.append(v)
            rest=[v for v in range(n) if v not in union]
            rng.shuffle(union); rng.shuffle(rest)
            order=union+rest
            max_union=max(max_union,len(union))
            for c in (c1,c2):
                pat=falsifying_pattern(c)
                cover=prefix_cover_complement_subcube(order,pat)
                max_cover=max(max_cover,len(cover))
                for w in assignments(min(n,8)):
                    if n>8:
                        # embed tested prefix and random suffix
                        ww=list(w)+[rng.randrange(2) for _ in range(n-8)]
                        wfull=tuple(ww)
                    else:
                        wfull=w
                    assert cover_accepts(cover,wfull,order)==clause_sat(c,wfull)
                    cover_cases += 1

    # 4. Natural component constrained-key audit: last-edge component exposure
    # plus intended D_m evaluation gives K on false statements.
    component_attacks=0
    for n in range(1,7):
        for _ in range(150):
            m=rng.randint(2,8)
            F=guaranteed_false_formula(rng,n,m)
            assert not any(formula_sat(F,w) for w in assignments(n))
            result=component_leak_attack(F,n,rng)
            # last random clause is nonempty and satisfiable
            assert result is not None
            key,rec,_=result
            assert rec==key
            component_attacks += 1

    # 5. Exact explicit-XOR-homomorphic PRF transcript membership barrier.
    hom_cases=0
    prf_in=0
    random_in=0
    ranks=[]
    for key_bits,out_bits,queries in [
        (8,4,4),(12,4,5),(16,8,4),(20,8,5),(24,8,6)
    ]:
        # t*out_bits > key_bits for every case.
        assert queries*out_bits > key_bits
        for _ in range(250):
            rank,rin=homomorphic_membership_trial(key_bits,out_bits,queries,rng)
            ranks.append((key_bits,out_bits,queries,rank))
            prf_in += 1
            random_in += int(rin)
            hom_cases += 1

    # 6. Theoretical random-function membership upper bounds for same cases.
    bounds=[]
    for key_bits,out_bits,queries in [
        (8,4,4),(12,4,5),(16,8,4),(20,8,5),(24,8,6)
    ]:
        # rank <= key_bits, so random transcript membership <= 2^(k-q*l)
        bounds.append({
            "key_bits":key_bits,
            "out_bits":out_bits,
            "queries":queries,
            "upper_bound_random_membership": 2.0**(key_bits-queries*out_bits)
        })

    report.update({
        "ideal_complete_output_cases": ideal_cases,
        "ideal_false_instances_perfectly_hidden": false_hidden,
        "ideal_true_instances_key_revealed": true_revealed,
        "explicit_false_fixtures_hidden": len(false_fixtures),
        "honest_telescope_decaps": honest_decaps,
        "prefix_cover_assignment_checks": cover_cases,
        "max_adjacent_clause_variable_union": max_union,
        "max_prefix_cover_nodes_observed": max_cover,
        "component_constrained_key_false_instance_attacks": component_attacks,
        "explicit_xor_homomorphic_membership_cases": hom_cases,
        "homomorphic_transcripts_in_public_image": prf_in,
        "random_transcripts_in_public_image_observed": random_in,
        "homomorphic_random_membership_bounds": bounds,
        "max_homomorphic_image_rank_observed": max(r[-1] for r in ranks),
        "status": "PASS"
    })
    return report

if __name__ == "__main__":
    print(json.dumps(run(), sort_keys=True, indent=2))
