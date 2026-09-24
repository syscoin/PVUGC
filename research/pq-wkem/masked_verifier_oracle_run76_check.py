#!/usr/bin/env python3
import itertools, json, math, random

SEED = 760076001
rng = random.Random(SEED)

def lit_sat(lit, w):
    i, pos = lit
    return w[i] == (1 if pos else 0)

def clause_sat(c, w):
    return any(lit_sat(l, w) for l in c)

def formula_sat(F, w):
    return all(clause_sat(c, w) for c in F)

def masked_eval(F, w, K, U):
    return K if formula_sat(F, w) else U

def random_formula(n, m, rng):
    F=[]
    for _ in range(m):
        width=rng.randint(1,min(3,n))
        vs=rng.sample(range(n), width)
        F.append(tuple((i,bool(rng.getrandbits(1))) for i in vs))
    return F

def guaranteed_false_formula(n, extra, rng):
    F=[((0,True),), ((0,False),)]
    F.extend(random_formula(n, extra, rng))
    return F

def guaranteed_true_formula(n, extra, rng):
    w=tuple(rng.randrange(2) for _ in range(n))
    F=[]
    for _ in range(extra):
        width=rng.randint(1,min(3,n))
        vs=rng.sample(range(n), width)
        lits=[]
        # choose arbitrary signs, then if all false, flip first sign
        for i in vs:
            lits.append((i,bool(rng.getrandbits(1))))
        if not clause_sat(tuple(lits),w):
            i,_=lits[0]
            lits[0]=(i,bool(w[i]))
        F.append(tuple(lits))
    return F,w

def parity_accept(w):
    return (sum(w) & 1) == 0

def pure_prefix(prefix, n, accept_fn):
    vals=set()
    rem=n-len(prefix)
    for tail in itertools.product((0,1), repeat=rem):
        vals.add(bool(accept_fn(prefix+tail)))
        if len(vals)>1:
            return None
    return next(iter(vals))

def minimal_prefix_cover(prefix, n, accept_fn, want=True):
    status=pure_prefix(prefix,n,accept_fn)
    if status is not None:
        return [prefix] if status == want else []
    return (minimal_prefix_cover(prefix+(0,),n,accept_fn,want)+
            minimal_prefix_cover(prefix+(1,),n,accept_fn,want))

def extend_prefix(prefix,n,fill=0):
    return prefix + (fill,)*(n-len(prefix))

def grover_two_dim(N, M, Q):
    # Two-dimensional Grover amplitudes: |good>, |bad>.
    # O0 leaves uniform invariant under the diffusion step.
    assert 0 < M < N
    a=math.sqrt(M/N)
    b=math.sqrt((N-M)/N)
    theta=math.asin(a)
    # after Q Grover iterations (oracle then diffusion)
    good1=math.sin((2*Q+1)*theta)
    bad1=math.cos((2*Q+1)*theta)
    good0=a
    bad0=b
    normdiff=math.hypot(good1-good0,bad1-bad0)
    S=Q*(M/N)  # sum of O0 query masses on good set
    hybrid=2*math.sqrt(Q*S) if Q else 0.0
    p1=good1*good1
    p0=M/N
    delta=max(0.0,p1-p0)
    extraction_lb=(delta*delta)/(4*Q*Q) if Q else 0.0
    return normdiff,hybrid,p1,p0,extraction_lb,M/N

def run():
    report={"seed":SEED, "claim_scope":"finite semantic/combinatorial/numerical validation only; theorems are proved separately"}

    # Ideal one-pad false complete-table hiding.
    false_cases=0
    false_table_key_pairs=0
    for n in range(1,7):
        for _ in range(60):
            F=guaranteed_false_formula(n,rng.randint(0,6),rng)
            allw=list(itertools.product((0,1),repeat=n))
            assert not any(formula_sat(F,w) for w in allw)
            U=rng.randrange(2**16)
            keys=[rng.randrange(2**16) for _ in range(4)]
            tables=[]
            for K in keys:
                table=tuple(masked_eval(F,w,K,U) for w in allw)
                assert set(table)=={U}
                tables.append(table)
            assert all(t==tables[0] for t in tables)
            false_cases+=1
            false_table_key_pairs += len(keys)-1

    # True completeness: every satisfying witness receives same K.
    true_cases=0
    satisfying_evals=0
    for n in range(1,8):
        for _ in range(60):
            F,w0=guaranteed_true_formula(n,rng.randint(1,8),rng)
            assert formula_sat(F,w0)
            K=rng.randrange(2**32); U=rng.randrange(2**32)
            sats=[w for w in itertools.product((0,1),repeat=n) if formula_sat(F,w)]
            assert sats
            for w in sats:
                assert masked_eval(F,w,K,U)==K
                satisfying_evals+=1
            true_cases+=1

    # Minimal pure-prefix cover for parity, both accepting and rejecting.
    parity_rows=[]
    parity_prefix_checks=0
    for n in range(1,11):
        acc=minimal_prefix_cover(tuple(),n,parity_accept,True)
        rej=minimal_prefix_cover(tuple(),n,parity_accept,False)
        assert len(acc)==2**(n-1)
        assert len(rej)==2**(n-1)
        assert all(len(p)==n for p in acc+rej)
        # Every proper prefix is mixed.
        for d in range(n):
            for p in itertools.product((0,1),repeat=d):
                assert pure_prefix(p,n,parity_accept) is None
                parity_prefix_checks += 1
        parity_rows.append({"n":n,"accept_tokens":len(acc),"reject_tokens":len(rej)})

    # Witness extraction from any explicit nonempty accepting prefix cover.
    explicit_cover_extractions=0
    cover_size_total=0
    for n in range(2,9):
        for _ in range(40):
            # Easy nonempty predicate: CNF known to have a planted witness.
            F,w0=guaranteed_true_formula(n,rng.randint(1,6),rng)
            fn=lambda w,F=F: formula_sat(F,w)
            cover=minimal_prefix_cover(tuple(),n,fn,True)
            assert cover
            p=cover[0]
            w=extend_prefix(p,n,0)
            assert fn(w)
            explicit_cover_extractions += 1
            cover_size_total += len(cover)

    # Numerical controls for the quantum query hybrid / extractor loss.
    grover_controls=0
    worst_norm_slack=1e9
    worst_extract_slack=1e9
    for N in (8,16,32,64,128,256):
        for M in (1,2):
            if M>=N: continue
            for Q in range(1,8):
                nd,hb,p1,p0,lb,actual=grover_two_dim(N,M,Q)
                # Hybrid state bound.
                assert nd <= hb + 1e-12
                # Random-query measurement under O0 finds a witness with actual M/N,
                # which must exceed theorem lower bound based on this event gap.
                assert actual + 1e-12 >= lb
                worst_norm_slack=min(worst_norm_slack,hb-nd)
                worst_extract_slack=min(worst_extract_slack,actual-lb)
                grover_controls+=1

    # Resource estimates for parity prefix programming.
    estimates=[]
    for n in (32,64,128,256):
        tokens=1<<(n-1)
        bytes32=tokens*32
        estimates.append({
            "n":n,
            "tokens_each_side":str(tokens),
            "bytes_at_32_per_token":str(bytes32),
            "log2_bytes_at_32_per_token":n+4
        })

    report.update({
        "false_one_pad_complete_table_cases":false_cases,
        "false_table_key_equality_checks":false_table_key_pairs,
        "true_one_pad_cases":true_cases,
        "satisfying_witness_evaluations":satisfying_evals,
        "parity_min_prefix_cover_rows":parity_rows,
        "proper_parity_prefixes_checked_mixed":parity_prefix_checks,
        "explicit_accepting_cover_witness_extractions":explicit_cover_extractions,
        "explicit_cover_total_tokens_in_controls":cover_size_total,
        "grover_hybrid_numeric_controls":grover_controls,
        "minimum_hybrid_bound_slack":worst_norm_slack,
        "minimum_extraction_bound_slack":worst_extract_slack,
        "parity_resource_estimates":estimates,
        "status":"PASS"
    })
    return report

if __name__=="__main__":
    print(json.dumps(run(),sort_keys=True,indent=2))
