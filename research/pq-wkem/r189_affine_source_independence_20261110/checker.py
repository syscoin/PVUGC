#!/usr/bin/env python3
"""R189: exact finite-field separation for R188's unauthenticated affine source share.

This enumerates algebraic distributions, not Bitcoin/Syscoin evidence, and is
NOT an authenticated source evaluator, witness-KEM, or QPT security experiment.
"""
import hashlib, json
from collections import Counter, defaultdict

P = 7
assert all((a*b)%P == 1 for a,b in ((1,1),(2,4),(3,5),(4,2),(5,3),(6,6)))
checks = Counter()

def chk(c, lab):
    assert c,lab
    checks[lab]+=1

def evalf(k,a,z): return (k+a*z)%P

def reconstruct(s0,s1,z0,z1):
    return ((z1*s0-z0*s1)*pow(z1-z0,-1,P))%P

def run():
    # One uniform masked baseline: distribution of future evaluation, even
    # conditional on any publicly selected genuine/fake source value z != z0.
    z0=2
    for observed_s0 in range(P):
        possibilities=[(k,a) for k in range(P) for a in range(P)
                       if evalf(k,a,z0)==observed_s0]
        chk(len(possibilities)==P,'single_baseline_preimages')
        for z in range(P):
            if z==z0: continue
            distribution=Counter(evalf(k,a,z) for k,a in possibilities)
            chk(all(distribution[s]==1 for s in range(P)),
                'hidden_evaluation_uniform_per_distinct_semantic_z')
        # The source can choose its alternative z *adaptively from s0*.
        # This source choice is public and contains no secret (K,a).
        z=(observed_s0+1)%P
        if z==z0: z=(z+1)%P
        distribution=Counter(evalf(k,a,z) for k,a in possibilities)
        chk(all(distribution[s]==1 for s in range(P)),
            'adaptive_public_source_choice_uninformative')
    # For independent slopes and common K, public baseline tuples are uniform
    # and independent of K, but hypothetical future share vectors are jointly
    # rank-one after fixing baselines; never assert independent hidden shares.
    z0s=[2,4]
    zs=[3,6]
    for s0vec in ((a,b) for a in range(P) for b in range(P)):
        compatible=[]
        for k in range(P):
            slopes=[((s0vec[i]-k)*pow(z0s[i],-1,P))%P for i in range(2)]
            compatible.append((k,slopes))
        chk(len(compatible)==P,'two_baselines_common_K_preimages')
        for i in range(2):
            distr=Counter(evalf(k,aa[i],zs[i]) for k,aa in compatible)
            chk(all(distr[t]==1 for t in range(P)), 'each_hidden_share_uniform')
        joint=Counter(tuple(evalf(k,aa[i],zs[i]) for i in range(2))
                      for k,aa in compatible)
        chk(len(joint)==P and all(v==1 for v in joint.values()),
            'hidden_share_vector_has_rank_one_support')
        # Once ANY such hypothetical evaluation leaks, the attacker can
        # recover the FULL intercept K; genuine source evidence cannot be
        # replaced with a private_TEST_ONLY evaluator that knows the slope.
        for k,aa in compatible:
            for i in range(2):
                recovered=reconstruct(s0vec[i],evalf(k,aa[i],zs[i]),
                                      z0s[i],zs[i])
                chk(recovered==k,'full_key_recovery_from_one_hidden_eval')
    # A public checking digest correlated to K changes the exact conditional
    # distribution. A toy leak K mod 2 illustrates why the uniformity lemma
    # must NOT automatically be promoted to the FULL public capsule.
    for s0 in range(P):
        opts=[(k,a) for k in range(P) for a in range(P) if evalf(k,a,z0)==s0]
        for leaked in (0,1):
            sub=[(k,a) for k,a in opts if k%2==leaked]
            chk(len(sub) in (3,4), 'key_correlated_checker_changes_posterior')
            distribution=Counter(evalf(k,a,3) for k,a in sub)
            chk(max(distribution.values())==1 and len(distribution)==len(sub),
                'post_checker_eval_support_restricted')
    # Raw polynomial evaluation, if made public, releases K from ANY fabricated
    # second coordinate. Source authentication checked ONLY in honest Open
    # cannot stop a raw attacker bypassing it.
    for k in range(P):
        for a in range(P):
            s0=evalf(k,a,z0)
            for fake_z in range(P):
                if fake_z==z0: continue
                fake_s=evalf(k,a,fake_z)  # publicly readable raw evaluator
                chk(reconstruct(s0,fake_s,z0,fake_z)==k,
                    'raw_source_free_evaluator_leaks_K')
    # Hashing the witness and verifying it can authenticate the input to an
    # honest checker, but a valid synthetic proof cannot supply an unknown
    # setup-secret slope without an additional source-correlated capsule.
    synthetic_w=[b'BTC/SYS authentic path A', b'BTC/SYS authentic path B']
    labels=[hashlib.sha256(w).digest() for w in synthetic_w]
    chk(labels[0]!=labels[1],'distinct_witness_hashes_no_common_secret_identity')
    result={
       'field': P,
       'run': 'R189_source_affine_information_gap',
       'assertions':sum(checks.values()),
       'groups':dict(sorted(checks.items())),
       'claim':'scoped algebraic/probability identities, no source-dependent release',
       'not_proved':['full public with CK/D and quantum oracle correlations',
                     'SHA256/AuxPoW source verification','polynomial BuildSourceShare',
                     'public authenticated evaluator','native signature security']
    }
    return result

if __name__=='__main__':
    print(json.dumps(run(),indent=2,sort_keys=True))
