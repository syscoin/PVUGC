#!/usr/bin/env python3
"""Run 683: exact finite joint-SPH cancellation and independent-key tests."""
import json
from collections import Counter

P, Q, G, A = 23, 11, 2, 4
H = pow(G, A, P)
V = [pow(G, i, P) for i in range(Q)]
assert len(set(V)) == Q

def word(r, t):
    return pow(G, r % Q, P), pow(H, t % Q, P)

def hp(alpha, beta):
    return pow(G, (alpha + A * beta) % Q, P)

def hh(w, alpha, beta):
    return pow(w[0], alpha, P) * pow(w[1], beta, P) % P

def fiber(theta):
    return [((theta-A*b) % Q, b) for b in range(Q)]

w, wi = word(3, 7), word(-3, -7)
checks = 0
for theta in range(Q):
    ff = fiber(theta)
    assert all(hp(a, b) == pow(G, theta, P) for a, b in ff)
    for z in (w, wi):
        assert set(hh(z, a, b) for a, b in ff) == set(V)
        checks += 1
for m in V:
    for theta in range(Q):
        for a, b in fiber(theta):
            c1, c2 = m*hh(w, a, b)%P, m*hh(wi, a, b)%P
            assert pow(c1*c2%P, (Q+1)//2, P) == m
            checks += 1
for t1 in range(Q):
    for t2 in range(Q):
        pairs = Counter((hh(w,a,b),hh(wi,c,d))
                        for a,b in fiber(t1) for c,d in fiber(t2))
        assert len(pairs) == Q*Q and set(pairs.values()) == {1}
        checks += 1
for r in (2, 8):
    for a in range(Q):
        for b in range(Q):
            assert hh(word(r,r),a,b) == pow(hp(a,b),r,P)
            checks += 1
print(json.dumps({"run":683,"group_order":Q,"single_false_projection_cells":22,
 "shared_false_pair_recoveries":Q**3,
 "independent_joint_uniform_projection_pairs":Q**2,
 "valid_witness_equations":2*Q**2,"assertions":checks,
 "pq_security":"NOT ESTABLISHED; group DLog broken by Shor"},
 sort_keys=True,indent=2))
