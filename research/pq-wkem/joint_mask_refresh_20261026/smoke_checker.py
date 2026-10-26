#!/usr/bin/env python3
"""Deterministic, exhaustive joint mask-leak/late-refresh smoke checker.
Research toy over F7: not a PQ secrecy test or a WKEM implementation.
"""
from collections import Counter
from itertools import product
import json

q = 7
checks = 0

def ck(ok):
    global checks
    assert ok
    checks += 1

def build(leak, key, refresh):
    hist = Counter()
    for s0, s1 in product(range(q), repeat=2):
        s = [s0, s1]
        t = tuple(s[i] for i in leak)
        e = [sum(t) % q, 2 * sum(t) % q, 0]
        for u in product(range(q), repeat=2 if refresh else 0):
            u0, u1 = u if refresh else (0, 0)
            y = ((s0 + u0 + s1 + u1 + e[0] + key) % q,
                 (s1 + u1 + e[1]) % q, 0)
            hist[(t, y)] += 1
    return hist

def main():
    safe0, safe1 = build((1,), 0, False), build((1,), 1, False)
    ck(safe0 == safe1)
    bad0, bad1 = build((0,), 0, False), build((0,), 1, False)
    ck(bad0 != bad1)
    ck(set(bad0).isdisjoint(bad1))
    seal0, seal1 = build((0, 1), 0, True), build((0, 1), 1, True)
    ck(seal0 == seal1)
    for key in (0, 1):
        for s0, s1 in product(range(q), repeat=2):
            t = s0
            y0 = (s0 + s1 + t + key) % q
            y1 = (s1 + 2 * t) % q
            ck((y0 - y1) % q == key)
    for k1, k2 in product((0, 1), repeat=2):
        shared = {(s + k1) % q - (s + k2) % q for s in range(q)}
        ck(len({v % q for v in shared}) == 1)
    return {"assertions": checks, "safe": True, "bad": True,
            "refresh": True, "shared_key_difference": True,
            "scope": "exhaustive F7 toy; no general QPT secrecy"}

if __name__ == "__main__":
    print(json.dumps(main(), indent=2, sort_keys=True))
