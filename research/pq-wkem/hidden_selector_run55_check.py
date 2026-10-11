#!/usr/bin/env python3
import itertools, json, math, random, hashlib
from collections import Counter

SEED = 550055
rng = random.Random(SEED)
Q = 4093
MU = 2046
W = 10000
ACCEPT = 15000
REPS = 20

# Run 55 checker: hidden local selectors, public pseudowitness-list enumeration,
# public residual landscape, and dense-test tradeoff.
TARGET_COMPLETENESS = 1 - 2**-20
TRIALS = 20000


def clause_satisfied(assign, clause):
    for lit in clause:
        b = assign[abs(lit)-1]
        if (lit > 0 and b == 1) or (lit < 0 and b == 0):
            return True
    return False


def clause_vars(clause):
    return tuple(sorted(abs(l)-1 for l in clause))


def allowed_rows(clause):
    vs = clause_vars(clause)
    rows=[]
    for bits in itertools.product((0,1), repeat=len(vs)):
        a={v:b for v,b in zip(vs,bits)}
        if clause_satisfied(a, clause):
            rows.append(bits)
    return vs, rows


def signed_clause_lift(assign, clause):
    vs, rows = allowed_rows(clause)
    t = tuple(assign[v] for v in vs)
    if clause_satisfied(assign, clause):
        return {r:(1 if r==t else 0) for r in rows}
    out={}
    for r in rows:
        h=sum(x!=y for x,y in zip(r,t))
        out[r]=1 if h%2==1 else -1
    return out


def relation_matrix(clauses, nvars):
    block_rows=[]; block_indices=[]; coord=0
    for c in clauses:
        vs,rows=allowed_rows(c)
        ids=list(range(coord, coord+len(rows)))
        coord += len(rows)
        block_rows.append((vs,rows)); block_indices.append(ids)
    p_indices=list(range(coord,coord+nvars)); coord+=nvars
    A=[]; d=[]
    for ids in block_indices:
        row=[0]*coord
        for i in ids: row[i]=1
        A.append(row); d.append(1)
    for b,(vs,rows) in enumerate(block_rows):
        ids=block_indices[b]
        for j,v in enumerate(vs):
            row=[0]*coord
            for rr,bits in enumerate(rows):
                if bits[j]: row[ids[rr]]=1
            row[p_indices[v]]=-1
            A.append(row); d.append(0)
    return A,d,block_rows,block_indices,p_indices


def vector_from_assignment(assign, clauses, nvars):
    A,d,block_rows,block_indices,p_indices=relation_matrix(clauses,nvars)
    y=[0]*len(A[0]); lifts=[]
    for b,c in enumerate(clauses):
        coeff=signed_clause_lift(assign,c); lifts.append(coeff)
        vs,rows=block_rows[b]
        for j,r in enumerate(rows): y[block_indices[b][j]]=coeff[r]
    for v,i in enumerate(p_indices): y[i]=assign[v]
    return y,lifts,(A,d,block_rows,block_indices,p_indices)


def matvec(A,y):
    return [sum(a*b for a,b in zip(row,y)) for row in A]


def dot(a,b):
    return sum(x*y for x,y in zip(a,b))


def ternary_dist(n):
    c=Counter({0:1})
    for _ in range(n):
        d=Counter()
        for x,a in c.items():
            for e in (-1,0,1): d[x+e]+=a
        c=d
    return c,3**n


def min_threshold(n,target):
    c,den=ternary_dist(n)
    for T in range(n+1):
        good=sum(v for x,v in c.items() if abs(x)<=T)
        if good/den >= target:
            return T,good,den
    raise AssertionError


def modrank(M,q=101):
    A=[[x%q for x in row] for row in M]
    if not A: return 0
    m=len(A); n=len(A[0]); r=0
    for c in range(n):
        piv=None
        for i in range(r,m):
            if A[i][c]%q:
                piv=i; break
        if piv is None: continue
        A[r],A[piv]=A[piv],A[r]
        inv=pow(A[r][c],-1,q)
        A[r]=[(v*inv)%q for v in A[r]]
        for i in range(m):
            if i!=r and A[i][c]%q:
                f=A[i][c]%q
                A[i]=[(A[i][j]-f*A[r][j])%q for j in range(n)]
        r+=1
        if r==m: break
    return r


def main():
    result={"seed":SEED,"q":Q,"mu":MU,"target_completeness":TARGET_COMPLETENESS}
    # all eight 3-CNF sign patterns: each assignment falsifies exactly one clause
    clauses=[]
    for signs in itertools.product((1,-1),repeat=3):
        clauses.append(tuple(signs[i]*(i+1) for i in range(3)))
    assigns=list(itertools.product((0,1),repeat=3))
    assert not [p for p in assigns if all(clause_satisfied(p,c) for c in clauses)]
    ys={}; malformed={}
    meta=None
    for p in assigns:
        y,lifts,meta=vector_from_assignment(p,clauses,3)
        A,d,block_rows,block_indices,p_indices=meta
        assert matvec(A,y)==d
        norms=[sum(v*v for v in L.values()) for L in lifts]
        assert norms.count(7)==1 and norms.count(1)==7
        bad=norms.index(7)
        ys[p]=y; malformed[p]=bad
    assert sorted(malformed.values())==list(range(8))
    result["false_core"]={"representations":8,"relation_shape":[len(A),len(A[0])],"malformed_block_bijection":True}

    # Ideal hidden one-block selector: 7 of 8 public pseudorepresentations return the actual bit.
    ideal_trials=4000; recovered=0
    hist=Counter()
    for _ in range(ideal_trials):
        share=rng.randrange(2); J=rng.randrange(8)
        outs=[]
        for p in assigns:
            if malformed[p] != J:
                outs.append(share)
            else:
                # worst-case single tested output flips the bit
                outs.append(1-share)
        ones=sum(outs); guess=1 if ones>4 else 0
        if guess==share: recovered+=1
        hist[sum(1 for x in outs if x==share)]+=1
    assert recovered==ideal_trials and hist==Counter({7:ideal_trials})
    result["ideal_hidden_one_block_selector"]={"trials":ideal_trials,"share_recoveries":recovered,"correct_outputs_per_share_histogram":dict(hist),"attack":"majority over 8 public exact pseudorepresentations"}

    # Exhaust worst-case binary outputs for hidden tested subsets of size s.
    subset_guarantees={}
    for s in range(0,9):
        guaranteed=True; cases=0; min_correct=8
        for Sidx in itertools.combinations(range(8),s):
            S=set(Sidx)
            for share in (0,1):
                # tested outputs may be arbitrary bits; exhaust all 2^s assignments for small s, but combinatorially all s<=8 is fine
                for badbits in itertools.product((0,1),repeat=s):
                    badmap=dict(zip(Sidx,badbits))
                    outs=[]
                    for p in assigns:
                        j=malformed[p]
                        outs.append(badmap[j] if j in S else share)
                    correct=sum(x==share for x in outs)
                    min_correct=min(min_correct,correct); cases+=1
                    # strict binary majority of 8 requires at least 5 correct
                    if correct<5: guaranteed=False
        subset_guarantees[str(s)]={"cases":cases,"min_correct_outputs":min_correct,"strict_majority_guaranteed":guaranteed}
    result["hidden_subset_worst_case_binary"] = subset_guarantees
    assert all(subset_guarantees[str(s)]["strict_majority_guaranteed"] for s in range(0,4))
    assert not any(subset_guarantees[str(s)]["strict_majority_guaranteed"] for s in range(4,9))

    # Actual public additive semantic capsule identity: selector secrecy cannot stop evaluation of all y_p.
    residual_checks=0; pairwise_checks=0; fixtures=500
    for _ in range(fixtures):
        t=[rng.randrange(Q) for _ in range(len(A))]
        E=[rng.choice((-1,0,1)) for _ in range(len(A[0]))]
        J=rng.randrange(8)
        # hidden amplified selector noise on block J, still just part of public additive error
        for idx in block_indices[J]:
            E[idx]+=17*rng.choice((-1,0,1))
        e0=rng.choice((-1,0,1)); K=rng.randrange(2)
        c=[(sum(A[i][j]*t[i] for i in range(len(A)))+E[j])%Q for j in range(len(A[0]))]
        beta=(sum(d[i]*t[i] for i in range(len(A)))+e0+MU*K)%Q
        residues={}
        for p,y in ys.items():
            rho=(beta-dot(y,c))%Q
            expected=(MU*K+e0-dot(y,E))%Q
            assert rho==expected
            residues[p]=rho; residual_checks+=1
        for p in assigns:
            for q in assigns:
                lhs=(residues[p]-residues[q])%Q
                yp,yq=ys[p],ys[q]
                rhs=(-dot([a-b for a,b in zip(yp,yq)],c))%Q
                assert lhs==rhs
                pairwise_checks+=1
    result["public_residual_landscape"]={"fixtures":fixtures,"residual_identities":residual_checks,"pairwise_difference_identities":pairwise_checks}

    # Local-selector quotient visibility control: enumerate +/-1 patterns on each 7-row clause block.
    invisible_counts=[]; visible_counts=[]
    for b,(vs,rows) in enumerate(block_rows):
        # columns are local rows; local constraint feature matrix F has rows 1,x1,x2,x3
        FT=[[1,*r] for r in rows]  # 7 x 4 = F^T
        base_rank=modrank(FT,101)
        assert base_rank==4
        inv=0
        for eta in itertools.product((-1,1),repeat=7):
            aug=[FT[i]+[eta[i]] for i in range(7)]
            if modrank(aug,101)==base_rank:
                inv+=1
        invisible_counts.append(inv); visible_counts.append(128-inv)
    assert invisible_counts==[8]*8
    result["local_selector_quotient"]={"blocks":8,"rademacher_patterns_per_block":128,"invisible_affine_patterns_per_block":invisible_counts,"visible_to_local_kernel_quotient_per_block":visible_counts}

    # Dense hidden-test tradeoff in the generous scalar ternary model.
    dense=[]
    for s in range(1,9):
        T,hgood,hden=min_threshold(s,TARGET_COMPLETENESS)
        cf,fden=ternary_dist(s+6)
        fgood=sum(v for x,v in cf.items() if abs(x)<=T)
        dense.append({"tested_blocks":s,"threshold":T,"honest_success_num":hgood,"honest_success_den":hden,"honest_success":hgood/hden,"malformed_success_num":fgood,"malformed_success_den":fden,"malformed_success":fgood/fden,"guaranteed_untested_representations":8-s})
    result["dense_test_exact_ternary"] = dense
    assert dense[6]["threshold"]==7 and abs(dense[6]["malformed_success"]-0.9909641898159909)<1e-15
    assert dense[7]["threshold"]==8 and abs(dense[7]["malformed_success"]-0.99584024065387)<1e-15

    # Correlated full-list Monte Carlo for s=1,4,7,8; diagnostic only.
    mc={}
    for s in (1,4,7,8):
        acc_hist=Counter()
        for _ in range(TRIALS):
            S=set(rng.sample(range(8),s))
            block_noise={}
            for b in S:
                rows=block_rows[b][1]
                block_noise[b]={r:rng.choice((-1,0,1)) for r in rows}
            accepted=0
            for p in assigns:
                y=ys[p]
                z=0
                for b in S:
                    ids=block_indices[b]; rows=block_rows[b][1]
                    z += sum(y[idx]*block_noise[b][r] for idx,r in zip(ids,rows))
                if abs(z)<=s:
                    accepted+=1
            acc_hist[accepted]+=1
        mc[str(s)]={"trials":TRIALS,"accepted_representation_histogram":dict(sorted(acc_hist.items())),"mean_accepted":sum(k*v for k,v in acc_hist.items())/TRIALS,"prob_at_least_5":sum(v for k,v in acc_hist.items() if k>=5)/TRIALS}
    result["correlated_full_list_monte_carlo_diagnostic"] = mc

    print(json.dumps(result,sort_keys=True,indent=2))

if __name__=='__main__':
    main()
