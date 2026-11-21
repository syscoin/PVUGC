#!/usr/bin/env python3
"""Run 519: exact finite commutator identity and public-prefix bypass checks.
Pure Python stdlib; deterministic; no cryptographic security claims."""
import itertools, json, random, hashlib

counts = {
    "S8_permutations": 0,
    "S8_commutator_cases": 0,
    "S8_false_terminal_identity_cases": 0,
    "S8_true_seed_recovery_cases": 0,
    "S32_sampled_frames": 0,
    "S32_action_identity_checks": 0,
    "S32_valid_witness_checks": 0,
    "S32_false_source_checks": 0,
    "S32_public_prefix_bypass_cases": 0,
    "S32_atomic_false_source_protection_cases": 0,
    "S32_sectors_reference_checks": 0,
}

def xor1(v,bit): return v ^ (1 << bit)

def invperm(p):
    out = [0] * len(p)
    for i, y in enumerate(p): out[y] = i
    return out

def conjugate(p,pi,fn,y):
    return p[fn(pi[y])]

# Exhaustive permutations on (k,b,t) with 3 bits, f either 0 or 1.
# E_f flips b if f; B flips t if k AND b.
def E8(v,f): return v ^ (2 if f else 0)
def B8(v): return v ^ (4 if ((v&1) and (v&2)) else 0)
def C8(v,f):
    for op in (lambda x:B8(x), lambda x:E8(x,f), lambda x:B8(x),lambda x:E8(x,f)):
        v=op(v)
    return v

for p in itertools.permutations(range(8)):
    inv=invperm(p)
    counts["S8_permutations"]+=1
    for f in (0,1):
        for v in range(8):
            y=p[v]
            A_E=lambda q: conjugate(p,inv,lambda t:E8(t,f),q)
            A_B=lambda q: conjugate(p,inv,B8,q)
            # E B E B in conventional composition order, rightmost B first
            via = A_E(A_B(A_E(A_B(y))))
            actual = conjugate(p,inv,lambda t:C8(t,f),y)
            expected=p[v ^ (4 if (f and (v&1)) else 0)]
            assert via==actual==expected
            counts["S8_commutator_cases"]+=1
            if not f:
                assert via==y
                counts["S8_false_terminal_identity_cases"]+=1
            else:
                assert (via!=y)==bool(v&1)
                counts["S8_true_seed_recovery_cases"]+=1

# S32 semantic bits: k 0, sector d 1, z 2, b 3, t 4.
def E(v,claim,fn):
    d=(v>>1)&1; z=(v>>2)&1
    return xor1(v,3) if d==claim and fn[z] else v

def B(v,claim):
    d=(v>>1)&1; k=v&1; b=(v>>3)&1
    return xor1(v,4) if d==claim and k and b else v

def C(v,claim,fn):
    v=B(v,claim)
    v=E(v,claim,fn)
    v=B(v,claim)
    v=E(v,claim,fn)
    return v

def anchor(k,d): return k|(d<<1)

def load(v,z): return v ^ ((z^((v>>2)&1))<<2)

rng=random.Random(51920261015)
for _ in range(192):
    p=list(range(32));rng.shuffle(p);inv=invperm(p)
    counts["S32_sampled_frames"]+=1
    for claim in (0,1):
        for f in ((0,0),(0,1),(1,0),(1,1)):
            for v in range(32):
                expected=v ^ (16 if (((v>>1)&1)==claim and (v&1) and f[(v>>2)&1]) else 0)
                assert C(v,claim,f)==expected
                # Conjugacy to E B E B, including arbitrary off-anchor b and t.
                y=p[v]
                ae=lambda u:conjugate(p,inv,lambda q:E(q,claim,f),u)
                ab=lambda u:conjugate(p,inv,lambda q:B(q,claim),u)
                assert ae(ab(ae(ab(y))))==p[expected]
                counts["S32_action_identity_checks"]+=1
                if not any(f) and ((v>>1)&1)==claim:
                    assert conjugate(p,inv,lambda q:C(q,claim,f),y)==y
                    counts["S32_false_source_checks"]+=1
        # Target false, known valid reference in the OTHER sector; no sector switch.
        for k in (0,1):
            a=p[anchor(k,claim)]
            # C and arbitrary b editing must not disclose from false target.
            toggled=conjugate(p,inv,lambda q:xor1(q,3),a)
            for z in (0,1):
                q=conjugate(p,inv,lambda v:load(v,z),toggled)
                assert conjugate(p,inv,lambda t:C(t,claim,(0,0)),q)==q
                counts["S32_atomic_false_source_protection_cases"]+=1
            # But accessing intermediate B after b edit discloses k.
            leaked=conjugate(p,inv,lambda q:B(q,claim),toggled)
            assert (leaked!=toggled)==bool(k)
            counts["S32_public_prefix_bypass_cases"]+=1
            # A reference C on the other sector cannot operate on this state.
            assert conjugate(p,inv,lambda t:C(t,1-claim,(1,1)),a)==a
            counts["S32_sectors_reference_checks"]+=1
            for f in ((0,1),(1,0),(1,1)):
                for z in (0,1):
                    y=conjugate(p,inv,lambda v:load(v,z),a)
                    result=conjugate(p,inv,lambda v:C(v,claim,f),y)
                    assert (result!=y)==bool(k and f[z])
                    if f[z]: counts["S32_valid_witness_checks"]+=1

payload={"run":519,"status":"PASS","model":"ideal conjugated reversible actions, no compact mixer", "counts":counts,"seed":51920261015,"theorem":"E_f B_k E_f B_k flips t iff k*f(z), independent of initial admission bit"}
print(json.dumps(payload,sort_keys=True,indent=2))
