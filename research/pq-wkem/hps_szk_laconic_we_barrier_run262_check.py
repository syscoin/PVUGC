#!/usr/bin/env python3
import itertools, json, math
from fractions import Fraction

A = 0
def ck(cond, msg="assertion failed"):
    global A
    A += 1
    if not cond:
        raise AssertionError(msg)

def tv(p, q):
    return sum(abs(a-b) for a,b in zip(p,q))/2

def compositions(total, parts):
    if parts == 1:
        yield (total,)
        return
    for x in range(total+1):
        for rest in compositions(total-x, parts-1):
            yield (x,)+rest

def exhaustive_decoder_bound():
    cases = 0
    tight = 0
    # Distributions with masses in units of 1/D over m outcomes.
    for m,D in [(2,4),(3,4),(3,5),(4,4)]:
        dists = [tuple(Fraction(x,D) for x in c) for c in compositions(D,m)]
        for p0 in dists:
            for p1 in dists:
                delta = tv(p0,p1)
                for dec in itertools.product([0,1], repeat=m):
                    c0 = sum(p0[i] for i,b in enumerate(dec) if b == 0)
                    c1 = sum(p1[i] for i,b in enumerate(dec) if b == 1)
                    eps = max(1-c0, 1-c1)
                    lower = 1 - 2*eps
                    ck(delta >= lower, (m,D,p0,p1,dec,delta,lower))
                    if delta == lower:
                        tight += 1
                    cases += 1
    return cases, tight

def threshold_examples():
    rows=[]
    for eps_num,eps_den,delta_num,delta_den in [
        (0,1,0,1),(1,100,1,100),(1,10,1,10),(1,7,1,4),(1,6,1,3)
    ]:
        eps=Fraction(eps_num,eps_den); d=Fraction(delta_num,delta_den)
        far=1-2*eps
        rows.append({"eps":str(eps),"false_tv":str(d),"true_tv_lower":str(far),
                     "standard_SD_gap": bool(far>Fraction(2,3) and d<Fraction(1,3))})
    ck(rows[0]["standard_SD_gap"])
    ck(rows[1]["standard_SD_gap"])
    ck(rows[2]["standard_SD_gap"])
    ck(rows[3]["standard_SD_gap"])
    ck(not rows[4]["standard_SD_gap"])  # boundary, strict thresholds
    return rows

def fixed_instance_sampler_cost():
    rows=[]
    for h in [8,16,32,64,128,256]:
        p=Fraction(1, 1<<h)
        expected=1/p
        # Probability of at least one hit after T=poly(h)=h^4 trials is <= T p.
        T=h**4
        ub=min(Fraction(1,1), T*p)
        ck(expected == 1<<h)
        ck(ub <= Fraction(T,1<<h))
        rows.append({"min_entropy_bits":h,"target_probability":f"2^-{h}",
                     "expected_rejection_trials":str(expected),
                     "h^4_trials_hit_probability_union_bound":str(ub)})
    return rows

def route_classification_sanity():
    # Pure logical ledger checks, not cryptographic proofs.
    routes = {
        "statistical_hps": {"generic_np_escape": False, "reason":"statistical WE -> SZK"},
        "laconic_shvzk": {"generic_np_escape": False, "reason":"WE-equivalent in cited classical theorem"},
        "sampleable_gap_hps": {"fixed_instance_interface": False, "reason":"sampler supplies random yes instance+witness, not arbitrary fixed x"},
        "nonlaconic_nonhps_release": {"closed_by_this_run": False, "reason":"not covered"},
    }
    ck(routes["statistical_hps"]["generic_np_escape"] is False)
    ck(routes["laconic_shvzk"]["generic_np_escape"] is False)
    ck(routes["sampleable_gap_hps"]["fixed_instance_interface"] is False)
    ck(routes["nonlaconic_nonhps_release"]["closed_by_this_run"] is False)
    return routes

def main():
    cases,tight = exhaustive_decoder_bound()
    out = {
        "status":"PASS",
        "decoder_tv_cases":cases,
        "decoder_tv_tight_cases":tight,
        "threshold_examples":threshold_examples(),
        "fixed_instance_sampler_cost":fixed_instance_sampler_cost(),
        "route_classification":route_classification_sanity(),
        "assertions":A,
        "scope":"Finite distribution/combinatorics checks only; literature theorems and cryptographic/QPT hardness are not proved by this checker."
    }
    print(json.dumps(out,sort_keys=True,indent=2))

if __name__=="__main__":
    main()
