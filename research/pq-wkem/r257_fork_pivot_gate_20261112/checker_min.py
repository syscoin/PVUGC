#!/usr/bin/env python3
"""Minimal R257 synthetic SHA256d fork-pivot gate check; NOT an actual WKEM."""
import hashlib, json
H = lambda z: hashlib.sha256(hashlib.sha256(z).digest()).digest()
X = lambda a,b: bytes(x^y for x,y in zip(a,b))
context = H(b'R257 fixed claim and native cancel context')
sigma = H(b'R257 synthetic frozen cancellation authorization')
key = H(b'R257 synthetic builder-only pad')
E = X(sigma,key)
base = [H(b'R257 genesis')]
for h in range(1,81):
    base.append(H(b'child' + h.to_bytes(4,'little') + base[-1]))
releases = premature = future_failures = 0
for d in range(1,41):
    pivot = base[d-1]
    pad = H(b'pivot' + context + d.to_bytes(4,'little') + pivot)
    token = X(key,pad)
    # Raw public opening doesn't require a source witness, even for FALSE cases.
    assert X(E,X(token,pad)) == sigma
    premature += 1
    b1 = H(b'future' + d.to_bytes(4,'little') + pivot + b'1')
    b2 = H(b'future' + d.to_bytes(4,'little') + pivot + b'2')
    assert b1 != b2
    for b in (b1,b2):
        assert X(E,X(token,pad)) == sigma
        releases += 1
    # Attempted repair based on one future child SHA fails for another.
    p1 = H(b'child-pad' + context + b1)
    p2 = H(b'child-pad' + context + b2)
    assert p1 != p2
    assert X(E,X(X(key,p1),p2)) != sigma
    future_failures += 1
print(json.dumps({'run':'R257_MIN','synthetic_same_key':releases,
 'public_no_witness_recovery':premature,'future_child_nonconvergence':future_failures,
 'source':'synthetic SHA256d links only','security':'none'},sort_keys=True,indent=2))
