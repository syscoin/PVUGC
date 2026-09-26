#!/usr/bin/env python3
import itertools, json, math, random, hashlib
from collections import Counter

SEED = 530053
rng = random.Random(SEED)
Q = 1000003
MU = 200000
W = 10000
ACCEPT = 15000
REPS = 20


def falsifier(clause):
    # clause is tuple of signed 1-based variable ids; return dict var->bit that falsifies each literal
    return {abs(l)-1: (0 if l > 0 else 1) for l in clause}


def clause_vars(clause):
    return tuple(sorted(abs(l)-1 for l in clause))


def local_tuple(assign, vs):
    return tuple(assign[v] for v in vs)


def clause_satisfied(assign, clause):
    for lit in clause:
        b = assign[abs(lit)-1]
        if (lit > 0 and b == 1) or (lit < 0 and b == 0):
            return True
    return False


def allowed_rows(clause):
    vs = clause_vars(clause)
    out=[]
    for bits in itertools.product((0,1), repeat=len(vs)):
        a={v:b for v,b in zip(vs,bits)}
        if clause_satisfied(a, clause):
            out.append(bits)
    return vs, out


def signed_clause_lift(assign, clause):
    """Return coefficient dict over satisfying local rows.
    If assign satisfies clause: delta at local row.
    If it falsifies: inclusion-exclusion signed measure matching total and first moments.
    """
    vs, rows = allowed_rows(clause)
    t = local_tuple(assign, vs)
    if clause_satisfied(assign, clause):
        return {r: (1 if r == t else 0) for r in rows}
    # t is unique excluded row. q_t(a)=(-1)^(Hamming(a,t)+1)
    out={}
    for r in rows:
        d=sum(x!=y for x,y in zip(r,t))
        out[r] = 1 if d % 2 == 1 else -1
    return out


def block_norm2(coeffs):
    return sum(v*v for v in coeffs.values())


def verify_local_lift(assign, clauses, lifts):
    # Normalization and shared marginals must match assign exactly over Z.
    for c, coeffs in zip(clauses, lifts):
        vs, rows = allowed_rows(c)
        assert set(coeffs)==set(rows)
        assert sum(coeffs.values()) == 1
        for j,v in enumerate(vs):
            m=sum(r[j]*coeffs[r] for r in rows)
            assert m == assign[v]
    return True


def relation_matrix(clauses, nvars):
    # Coordinates: each clause's satisfying-row coefficients, then master marginals p_i.
    block_rows=[]; block_indices=[]; coord=0
    for c in clauses:
        vs, rows=allowed_rows(c)
        ids=list(range(coord, coord+len(rows)))
        coord += len(rows)
        block_rows.append((vs, rows))
        block_indices.append(ids)
    p_indices=list(range(coord, coord+nvars)); coord += nvars
    rowsA=[]; rhs=[]
    # per-block normalization
    for ids in block_indices:
        row=[0]*coord
        for i in ids: row[i]=1
        rowsA.append(row); rhs.append(1)
    # each occurrence marginal = shared p_v
    for b,(vs, rows) in enumerate(block_rows):
        ids=block_indices[b]
        for j,v in enumerate(vs):
            row=[0]*coord
            for rr,bits in enumerate(rows):
                if bits[j]: row[ids[rr]]=1
            row[p_indices[v]]=-1
            rowsA.append(row); rhs.append(0)
    return rowsA, rhs, block_rows, block_indices, p_indices


def vector_from_assignment(assign, clauses, nvars):
    A,d,block_rows,block_indices,p_indices=relation_matrix(clauses,nvars)
    y=[0]*len(A[0])
    lifts=[]
    for b,c in enumerate(clauses):
        coeffs=signed_clause_lift(assign,c); lifts.append(coeffs)
        vs,rows=block_rows[b]
        for j,r in enumerate(rows): y[block_indices[b][j]]=coeffs[r]
    for v,i in enumerate(p_indices): y[i]=assign[v]
    return y,lifts,(A,d,block_rows,block_indices,p_indices)


def matvec(A,y):
    return [sum(a*b for a,b in zip(row,y)) for row in A]


def circ_dist(x,c,q=Q):
    d=(x-c)%q
    return min(d, q-d)


def decode_bit(residue):
    d0=circ_dist(residue,0)
    d1=circ_dist(residue,MU)
    ok0=d0 < ACCEPT
    ok1=d1 < ACCEPT
    if ok0 == ok1:
        return None
    return 0 if ok0 else 1


def capsule(A,d,block_indices,target,share_bit):
    r=len(A); N=len(A[0])
    s=[rng.randrange(Q) for _ in range(r)]
    e=[rng.choice((-1,0,1)) for _ in range(N)]
    extra=[0]*N
    for i in block_indices[target]:
        extra[i]=rng.choice((-1,0,1))
    e0=rng.choice((-1,0,1))
    a=[]
    for j in range(N):
        val=sum(A[i][j]*s[i] for i in range(r)) + e[j] + W*extra[j]
        a.append(val%Q)
    c=(sum(d[i]*s[i] for i in range(r)) + e0 + MU*share_bit)%Q
    return a,c,e,extra,e0


def contract(y,a,c):
    return (c - sum((yy%Q)*aa for yy,aa in zip(y,a)))%Q


def exact_noise(y,e,extra,e0):
    return e0 - sum(yy*ee for yy,ee in zip(y,e)) - W*sum(yy*xx for yy,xx in zip(y,extra))


def nearest_rep_assignment_for_target(target_clause, clauses, nvars):
    # deterministic lexicographically first assignment satisfying target clause
    for bits in itertools.product((0,1), repeat=nvars):
        if clause_satisfied(bits, clauses[target_clause]):
            return bits
    raise AssertionError("proper clause should be satisfiable")


def direct_extract_if_all_norm1(y, clauses, nvars, meta):
    A,d,block_rows,block_indices,p_indices=meta
    assignment=[None]*nvars
    for b,(vs,rows) in enumerate(block_rows):
        vals=[y[i] for i in block_indices[b]]
        if sum(v*v for v in vals)!=1 or sum(vals)!=1:
            return None
        ones=[j for j,v in enumerate(vals) if v==1]
        if len(ones)!=1: return None
        row=rows[ones[0]]
        for j,v in enumerate(vs):
            if assignment[v] is None: assignment[v]=row[j]
            elif assignment[v]!=row[j]: return None
    for v,pidx in enumerate(p_indices):
        if assignment[v] is None: assignment[v]=y[pidx]
        if y[pidx]!=assignment[v]: return None
    if all(clause_satisfied(assignment,c) for c in clauses):
        return tuple(assignment)
    return None


def main():
    result={"seed":SEED,"q":Q,"mu":MU,"target_weight":W,"accept_radius":ACCEPT,"repetitions":REPS}

    # 1. Exact integer block gap sanity: normalized integer vectors in [-2,2]^m.
    mins={}; checked=0; norm1_bad=0; norm2_seen=0
    for m in range(2,8):
        mn=None
        for z in itertools.product(range(-2,3), repeat=m):
            if sum(z)!=1: continue
            checked+=1
            n2=sum(v*v for v in z)
            is_basis=(z.count(1)==1 and all(v in (0,1) for v in z))
            if n2==1 and not is_basis: norm1_bad+=1
            if not is_basis:
                mn=n2 if mn is None else min(mn,n2)
            if n2==2: norm2_seen+=1
        mins[str(m)]=mn
    assert norm1_bad==0 and norm2_seen==0
    assert all(v>=3 for v in mins.values())
    result["integer_block_gap"]={"vectors_checked":checked,"min_nononehot_norm2":mins,
                                  "bad_norm1":norm1_bad,"norm2_vectors":norm2_seen}

    # 2. Inclusion-exclusion excluded-row identity for k=2..6, every excluded point.
    ie_cases=0
    for k in range(2,7):
        for f in itertools.product((0,1), repeat=k):
            rows=[a for a in itertools.product((0,1), repeat=k) if a!=f]
            coeff={}
            for a in rows:
                h=sum(x!=y for x,y in zip(a,f))
                coeff[a]=1 if h%2==1 else -1
            assert sum(coeff.values())==1
            for j in range(k):
                assert sum(a[j]*coeff[a] for a in rows)==f[j]
            assert sum(v*v for v in coeff.values())==2**k-1
            ie_cases+=1
    result["inclusion_exclusion_identity"]={"cases":ie_cases,"status":"pass"}

    # 3. Unsat 3-CNF core: all 8 sign patterns on 3 variables.
    clauses=[]
    for signs in itertools.product((1,-1), repeat=3):
        clauses.append(tuple(signs[i]*(i+1) for i in range(3)))
    sats=[]
    for t in itertools.product((0,1), repeat=3):
        if all(clause_satisfied(t,c) for c in clauses): sats.append(t)
    assert not sats

    core_lifts=0; switching=0
    bad_norm_hist=Counter()
    for t in itertools.product((0,1), repeat=3):
        y,lifts,meta=vector_from_assignment(t,clauses,3)
        A,d,block_rows,block_indices,p_indices=meta
        assert matvec(A,y)==d
        verify_local_lift(t,clauses,lifts)
        norms=[block_norm2(x) for x in lifts]
        assert norms.count(7)==1 and norms.count(1)==7
        bad_norm_hist.update(norms)
        core_lifts+=1
        assert direct_extract_if_all_norm1(y,clauses,3,meta) is None

    for b in range(8):
        for t in itertools.product((0,1), repeat=3):
            if not clause_satisfied(t, clauses[b]): continue
            y,lifts,meta=vector_from_assignment(t,clauses,3)
            assert block_norm2(lifts[b])==1
            assert matvec(meta[0],y)==meta[1]
            switching+=1
    assert switching==56
    result["unsat_core"]={"assignments_lifted":core_lifts,"target_onehot_switching_representations":switching,
                            "block_norm_histogram":dict(sorted(bad_norm_hist.items()))}

    # 4. Random larger unsat formulas containing the 8-clause core; every target gets one-hot via a different signed lift.
    larger_targets=0; larger_relations=0
    for fixture in range(20):
        n=6
        cs=list(clauses)
        # add 12 random proper 3-clauses on distinct vars
        for _ in range(12):
            vs=sorted(rng.sample(range(1,n+1),3))
            sg=[rng.choice((1,-1)) for _ in range(3)]
            cs.append(tuple(v*s for v,s in zip(vs,sg)))
        for b,c in enumerate(cs):
            t=nearest_rep_assignment_for_target(b,cs,n)
            y,lifts,meta=vector_from_assignment(t,cs,n)
            assert matvec(meta[0],y)==meta[1]
            assert block_norm2(lifts[b])==1
            # core ensures at least one violated clause -> at least one malformed block
            assert any(block_norm2(x)>1 for x in lifts)
            larger_targets+=1; larger_relations+=1
    result["larger_unsat_fixtures"]={"fixtures":20,"target_components_checked":larger_targets,
                                       "exact_relation_checks":larger_relations}

    # 5. Honest extractor control on true formula: remove one core clause. Its excluded assignment satisfies remaining seven.
    true_clauses=clauses[1:]
    missing_f=falsifier(clauses[0]); honest=tuple(missing_f[i] for i in range(3))
    assert all(clause_satisfied(honest,c) for c in true_clauses)
    yh,lh,metah=vector_from_assignment(honest,true_clauses,3)
    assert all(block_norm2(x)==1 for x in lh)
    assert direct_extract_if_all_norm1(yh,true_clauses,3,metah)==honest
    result["true_extractor_control"]={"witness":honest,"blocks":len(true_clauses),"status":"pass"}

    # 6. Full public capsule contraction attack on false core with N-of-N XOR shares.
    # Each share is locally amplified with REPS independent tests of its target block.
    # Honest/target-onehot noise is always within ACCEPT. A malformed 7-row clause block
    # passes one repetition iff the signed ternary sum lies in {-1,0,1}.
    A,d,block_rows,block_indices,p_indices=relation_matrix(clauses,3)
    trials=100
    share_decodes=0; key_decodes=0; residual_identities=0; max_abs_noise=0
    for _ in range(trials):
        shares=[rng.randrange(2) for _ in range(8)]
        K=0
        for bit in shares: K ^= bit
        rec=[]
        for b in range(8):
            t=nearest_rep_assignment_for_target(b,clauses,3)
            y,lifts,meta=vector_from_assignment(t,clauses,3)
            assert block_norm2(lifts[b])==1
            rep_bits=[]
            for _rep in range(REPS):
                a,c,e,extra,e0=capsule(A,d,block_indices,b,shares[b])
                r=contract(y,a,c)
                noise=exact_noise(y,e,extra,e0)
                expected=(MU*shares[b]+noise)%Q
                assert r==expected
                residual_identities+=1
                max_abs_noise=max(max_abs_noise,abs(noise))
                rep_bits.append(decode_bit(r))
            bit=shares[b] if all(x==shares[b] for x in rep_bits) else None
            rec.append(bit)
            if bit==shares[b]: share_decodes+=1
        if all(x is not None for x in rec):
            Kr=0
            for bit in rec: Kr ^= bit
            if Kr==K: key_decodes+=1
    assert share_decodes==trials*8 and key_decodes==trials
    # Switching representation has l1<=17, target l1=1, |e0|<=1.
    switching_bound=1+17+W
    assert max_abs_noise<=switching_bound
    assert switching_bound < ACCEPT

    # Exact local rejection law if the SAME representation is forced to have target block malformed.
    ternary_sums=Counter(sum(v) for v in itertools.product((-1,0,1), repeat=7))
    one_rep_accept=sum(ternary_sums[t] for t in (-1,0,1))
    one_rep_total=3**7
    assert one_rep_accept==1107 and one_rep_total==2187
    forced_pass=(one_rep_accept/one_rep_total)**REPS
    # Baseline contribution is <=18, so |sum|<=1 is always accepted and |sum|>=2 always rejected:
    assert W+18 < ACCEPT and 2*W-18 > ACCEPT
    assert MU-(7*W+18) > ACCEPT and (Q-MU)-(7*W+18) > ACCEPT

    result["component_switching_capsule_attack"]={
        "trials":trials,"repetitions_per_share":REPS,
        "share_decodes":share_decodes,"share_total":trials*8,
        "xor_key_decodes":key_decodes,"residual_identities":residual_identities,
        "max_observed_abs_noise":max_abs_noise,"switching_deterministic_abs_noise_bound":switching_bound,
        "accept_radius":ACCEPT,
        "forced_malformed_one_repeat_accept_numerator":one_rep_accept,
        "forced_malformed_one_repeat_accept_denominator":one_rep_total,
        "forced_malformed_all_repetitions_accept_probability":forced_pass
    }

    # 7. Honest capsule control on satisfiable 7-clause formula, same dense-baseline/local-extra form.
    Ah,dh,brh,bih,pih=relation_matrix(true_clauses,3)
    honest_trials=100; honest_decodes=0; honest_components=0
    for _ in range(honest_trials):
        for b in range(len(true_clauses)):
            bit=rng.randrange(2)
            okay=True
            for _rep in range(REPS):
                a,c,e,extra,e0=capsule(Ah,dh,bih,b,bit)
                r=contract(yh,a,c)
                assert r==(MU*bit+exact_noise(yh,e,extra,e0))%Q
                okay &= (decode_bit(r)==bit)
            honest_decodes += okay
            honest_components += 1
    assert honest_decodes==honest_components
    result["honest_capsule_control"]={"trials":honest_trials,"repetitions_per_share":REPS,
                                       "component_decodes":honest_decodes,
                                       "component_total":honest_components}

    # 8. Resource formulas for k=3 local-view compiler.
    resource=[]
    for m,n in [(100,60),(1000,600),(10000,6000)]:
        coords=7*m+n
        equations=4*m
        # nnz: normalization 7; each of 3 marginal rows has 4 row coefficients + one p coefficient =5
        nnz=(7+3*5)*m
        resource.append({"clauses":m,"variables":n,"representation_coordinates":coords,
                         "linear_equations":equations,"matrix_nonzeros_upper_bound":nnz})
    result["resources_3cnf"]=resource

    blob=json.dumps(result,sort_keys=True,separators=(",",":"))
    result["canonical_result_sha256_without_self_field"]=hashlib.sha256(blob.encode()).hexdigest()
    print(json.dumps(result,indent=2,sort_keys=True))

if __name__=='__main__':
    main()
