#!/usr/bin/env python3
"""Run 684: exact finite SPHF selective-opening/cross-statement analysis.
No cryptographic security is inferred from tiny parameters. Standard library only.
"""
from __future__ import annotations
from collections import defaultdict, Counter
from hashlib import sha256
import json

P = 23
Q = 11
G = 2
A = 3
H = pow(G, A, P)
assert pow(G, Q, P) == 1 and all(pow(G, j, P) != 1 for j in range(1, Q))

checks = 0

def req(cond, label):
    global checks
    checks += 1
    if not cond:
        raise AssertionError(label)

def mult(*items):
    ans = 1
    for x in items:
        ans = ans * x % P
    return ans

def inv(x):
    return pow(x, P - 2, P)

def word(r, t):
    return (pow(G, r % Q, P), pow(H, t % Q, P))

def projection(alpha, beta):
    return mult(pow(G, alpha, P), pow(H, beta, P))

def projection_exponent(alpha, beta):
    return (alpha + A * beta) % Q

def secret_hash(W, alpha, beta):
    return mult(pow(W[0], alpha, P), pow(W[1], beta, P))

def group_pow_word(W, d):
    return (pow(W[0], d, P), pow(W[1], d, P))

W_FALSE = word(2, 5)
W_POWER = group_pow_word(W_FALSE, 2)
W_TRUE = word(7, 7)
req(W_FALSE[0] != pow(G, 5, P) or W_FALSE[1] != pow(H, 2, P), 'false-word fixture distinct')
req(W_FALSE != W_TRUE, 'false and true different')

# Run 683's single-word smoothness, included only as a control for the NEW attack.
one_word_cells = defaultdict(Counter)
for theta in range(Q):
    for m in range(Q):
        for beta in range(Q):
            alpha = (theta - A * beta) % Q
            req(projection_exponent(alpha, beta) == theta, 'fiber projection')
            C = mult(pow(G, m, P), secret_hash(W_FALSE, alpha, beta))
            one_word_cells[(theta, m)][C] += 1
for hist in one_word_cells.values():
    req(len(hist) == Q and set(hist.values()) == {1}, 'individual perfect smoothness')

# Novel selective-opening attack: target A has ONLY a false clause; B has
# one true OR clause and one false clause. Both have DISTINCT message keys.
# Reusing the same HPS hashing key across A and B makes B's legitimate
# witness-opening a known-plaintext oracle for the target's false slot.
shared_same_word = 0
shared_power_word = 0
for alpha in range(Q):
  for beta in range(Q):
    hp = projection(alpha, beta)
    tf = secret_hash(W_FALSE, alpha, beta)
    tp = secret_hash(W_POWER, alpha, beta)
    tt = secret_hash(W_TRUE, alpha, beta)
    req(tt == pow(hp, 7, P), 'true OR clause witness projection')
    req(tp == pow(tf, 2, P), 'hash homomorphism on word powering')
    for ma in range(Q):
      MA = pow(G, ma, P)
      CA = mult(MA, tf)
      for mb in range(Q):
        MB = pow(G, mb, P)
        CB_true = mult(MB, tt)
        opened_MB = mult(CB_true, inv(pow(hp, 7, P)))
        req(opened_MB == MB, 'legitimate B OR witness retrieves B key')
        CB_false = mult(MB, tf)
        forged_MA = mult(CA, opened_MB, inv(CB_false))
        req(forged_MA == MA, 'unauthorized target A extraction, same word')
        shared_same_word += 1
        CB_power = mult(MB, tp)
        known_Tp = mult(CB_power, inv(opened_MB))
        # 2^(-1) modulo group order Q = 6
        known_T = pow(known_Tp, pow(2, -1, Q), P)
        forged_MA_power = mult(CA, inv(known_T))
        req(forged_MA_power == MA, 'unauthorized target A, related false word')
        shared_power_word += 1

# Independent HPS keys per slot. For every fixed target MA, and for each
# observed target projection, B projection, B false capsule / legitimately
# opened B message, the target false capsule is exactly uniform on G.
# A correlated public checker of MA does not alter this pointwise law.
independent_fiber_cells = 0
uniform_cases = 0
for ma in range(Q):
    MA = pow(G, ma, P)
    MB = pow(G, 4, P)
    # Toy deterministic public checking tag for MA: not a signature.
    checking_tag = sha256(b'run684-domain|' + bytes([MA])).hexdigest()
    req(len(checking_tag) == 64, 'public correlated tag fixture')
    cells = defaultdict(Counter)
    for aa in range(Q):
      for ba in range(Q):
        pa = projection_exponent(aa, ba)
        CA = mult(MA, secret_hash(W_FALSE, aa, ba))
        for ab in range(Q):
          for bb in range(Q):
            pb = projection_exponent(ab, bb)
            CB = mult(MB, secret_hash(W_FALSE, ab, bb))
            cells[(pa, pb, CB)][CA] += 1
            independent_fiber_cells += 1
    req(len(cells) == Q**3, 'conditioned view count per target')
    for hist in cells.values():
        req(len(hist) == Q and set(hist.values()) == {1}, 'full conditional exact uniformity')
        uniform_cases += 1

out = {
    'run': 684,
    'model': 'finite prime-order DH smooth projective hash; NOT PQ',
    'parameters': {'p': P, 'q': Q, 'g': G, 'h': H, 'false_word': list(W_FALSE), 'related_false_word': list(W_POWER), 'true_or_word': list(W_TRUE)},
    'individual_false_capsule_cells': len(one_word_cells),
    'shared_hps_key_distinct_credential_attack_success_same_false_word': shared_same_word,
    'shared_hps_key_distinct_credential_attack_success_power_related_false_word': shared_power_word,
    'independent_hps_total_exhaustive_key_pairs': independent_fiber_cells,
    'independent_hps_uniform_conditional_cells': uniform_cases,
    'assertions': checks,
    'claim_limit': 'Exact small-group algebra only. No native signature, source compiler, PQ assumption, or malicious setup protocol implemented.'
}
print(json.dumps(out, sort_keys=True, indent=2))
