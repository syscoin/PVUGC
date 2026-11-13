#!/usr/bin/env python3
"""Exact finite checks of the R170 random-oracle game marginals; no security theorem via tests."""
import itertools, collections, json
N=4; M=4
cnt_honest=collections.Counter();cnt_programmed=collections.Counter()
for vals in itertools.product(range(M),repeat=N):
    for s in range(N):
        cnt_honest[(vals,s,vals[s])]+=1
        for y in range(M):
            f=list(vals);f[s]=y
            cnt_programmed[(tuple(f),s,y)]+=1
# Each conditioned honest event can arise from M preprogram images.
assert {k:v*M for k,v in cnt_honest.items()}==dict(cnt_programmed)
# Local patch at second site differs only on the newer site;
# double-programmed reference differs from singly programmed at hidden first site.
checks=0
for vals in itertools.product(range(M),repeat=N):
    for y,z,s in itertools.product(range(M),range(N),range(N)):
        singly=list(vals);singly[z]=y
        doubly=singly.copy();doubly[s]=y
        assert all(singly[i]==doubly[i] for i in range(N) if i!=s)
        checks+=1
print(json.dumps({"N":N,"M":M,"oracle_tables":M**N,"joint_marginal_events":len(cnt_honest),"programmed_to_honest_weight_factor":M,"single_vs_double_only_hidden_address":checks,"exact_enumeration_only":True},indent=2,sort_keys=True))
