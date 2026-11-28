"""Toy exhaustive check of conditioned random-oracle patch coupling, NOT original-source evidence/FE."""
import itertools, json, hashlib
D=range(4); Y=range(4); TARGET={0}; Q={0}
H=list(itertools.product(Y, repeat=len(D)))
# For every chosen future input u, replacing that one hash with 0 gives
# exactly uniform RO distribution conditioned on a passing hash at u.
results={}
for t in (1,2):
    chosen=list(itertools.permutations(D,t))
    freq={}
    expected={}
    total=0
    no_build_query=0
    false_source_and_no_build_query=0
    for us in chosen:
        uset=set(us)
        for h in H:
            patched=list(h)
            for u in us: patched[u]=0
            key=(us,tuple(patched))
            freq[key]=freq.get(key,0)+1
            total+=1
            if Q.isdisjoint(uset):
                no_build_query+=1
                if all(h[u] not in TARGET for u in us):
                    false_source_and_no_build_query+=1
        # A truly uniform RO conditioned on H(u)=0 for each u has 4^(4-t)
        # possible tables. A patched table has exactly 4^t originals.
        for g in H:
            if all(g[u] in TARGET for u in us):
                expected[(us, g)]=len(Y)**t
    assert freq==expected
    assert total==len(H)*len(chosen)
    assert no_build_query/total==(4-t)/4
    assert false_source_and_no_build_query/total==((4-t)/4)*(3/4)**t
    results[str(t)]={
        'chosen_future_points':len(chosen),
        'patched_oracle_tables':len(expected),
        'conditioned_ro_exact_multiplicity':4**t,
        'total_source_oracle_trials':total,
        'setup_queries_miss_patch':no_build_query,
        'real_certificates_invalid_and_setup_misses':false_source_and_no_build_query,
        'invalid_and_miss_probability':false_source_and_no_build_query/total,
    }
results['scope']='exact uniform 4-point random-oracle conditional law only; no actual SHA, network, source certificate, release program, or QPT execution'
print(json.dumps(results,sort_keys=True,indent=2))
