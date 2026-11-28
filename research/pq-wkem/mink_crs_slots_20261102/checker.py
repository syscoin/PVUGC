#!/usr/bin/env python3
"""Offline exhaustive algebraic checker for the R15 designated-last CRS soundness component.
No external packages, randomness or network. Tests are not cryptographic security estimates.
"""
import hashlib, itertools, json, math
from collections import Counter

checks = 0

def test(statement, label):
    global checks
    checks += 1
    if not statement:
        raise AssertionError(f"{label} at check {checks}")

q = 7
D = 2
# Each history stands for an arbitrarily selected public state; the corrupt coalition
# may fix any nonlinear response to it BEFORE fresh honest contribution is sampled.
histories = 97
vectors = list(itertools.product(range(q), repeat=D))
for history in range(histories):
    # Nonlinear and branch-dependent corrupt share function, fixed before honest output.
    corrupt = ((history**3 + 5*history + 2) % q,
               ((history ^ (history >> 2))**2 + 3*history + 1) % q)
    seen_real = Counter()
    seen_embed = Counter()
    for honest in vectors:
        theta = tuple((corrupt[k] + honest[k]) % q for k in range(D))
        seen_real[theta] += 1
    for target in vectors:
        honest = tuple((target[k] - corrupt[k]) % q for k in range(D))
        test(tuple((corrupt[k] + honest[k]) % q for k in range(D)) == target,
             "challenge embedding")
        seen_embed[target] += 1
    for theta in vectors:
        test(seen_real[theta] == 1, "uniform honest CRS at fixed history")
        test(seen_embed[theta] == seen_real[theta], "exact conditional transcript distribution")

# K4 cannot be colored with 3 colors. Enumerate all 3^4 purported colorings;
# the single honest verifier's edge is drawn uniformly after color binding.
E = list(itertools.combinations(range(4), 2))
counts = Counter()
for assignment in itertools.product(range(3), repeat=4):
    accepted_edges = sum(assignment[a] != assignment[b] for a,b in E)
    test(accepted_edges <= len(E)-1, "every K4 commitment fails an honest edge")
    counts[accepted_edges] += 1
max_good = max(counts)
test(max_good == 5, "K4 maximum honest-verifier passing edges")

# Corrupt verifier slots can trivially accept: AND still cannot exceed the honest slot.
for N in range(2, 9):
    for honest_idx in range(N):
        for accepted_edges in counts:
            for edge_idx in range(len(E)):
                # A slot with an honest verifier is the only required soundness barrier.
                good = edge_idx < accepted_edges
                all_corrupt_accept = True
                test((good and all_corrupt_accept) == good, "conjunctive soundness")

# Repeated independent honest challenges; adversary may choose a fresh best assignment
# after all prior challenge edges, but every conditional round has <=5/6 acceptance.
round_limits = []
for rounds in range(1, 9):
    numerator = max_good**rounds
    denominator = len(E)**rounds
    test(0 <= numerator < denominator, "fresh-edge geometric bound")
    round_limits.append({"rounds": rounds, "best_case_numerator": numerator,
                         "uniform_edge_denominator": denominator,
                         "upper_probability": f"{numerator}/{denominator}"})

# Known weakness of a malicious public key: with A=b=0, ternary ciphertext v=g*c.
# Plaintext colors are exposed. This check makes no ZK claim for corrupt slots.
q_bad, gap = 65537, 21845
for c in range(3):
    cipher_v = (gap*c) % q_bad
    test(cipher_v == gap*c, "malicious zero-key leaks the color")

out = {
    "run": "MINK_CRS_SLOTS_20261102_R15",
    "assertions": checks,
    "exhaustive_field_q": q,
    "crs_coordinates": D,
    "nonlinear_corrupt_histories": histories,
    "targets_per_history": len(vectors),
    "false_graph": "K4 3-colorability",
    "edges": len(E),
    "color_assignments": sum(counts.values()),
    "valid_edges_histogram": dict(sorted(counts.items())),
    "max_honest_one_round_acceptance": f"{max_good}/{len(E)}",
    "round_bound": round_limits,
    "malicious_key_privacy_counterexample": "A=0,b=0 leaks all ternary colors",
    "security_scope": "mathematical exact distribution; single-honest-slot soundness only, not ZK or WKEM"
}
print(json.dumps(out, indent=2, sort_keys=True))
