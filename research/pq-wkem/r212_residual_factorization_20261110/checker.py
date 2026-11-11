#!/usr/bin/env python3
"""R212: public SHA residual-only release, two failed repairs.
Synthetic Boolean field relation only, NOT original BTC/SYS source or security.
"""
from __future__ import annotations
import hashlib
import json
from collections import Counter

Q = 257
C = Counter()

def assert_check(c, label):
    assert c, label
    C[label] += 1

def H(label, *parts):
    b = len(label).to_bytes(2, 'big') + label
    for p in parts:
        b += len(p).to_bytes(4, 'big') + p
    return hashlib.sha256(b).digest()

def enc(x):
    return x.to_bytes(2, 'big')

def xor(a,b):
    assert len(a)==len(b)
    return bytes(x^y for x,y in zip(a,b))

def residual(z):
    # Synthetic two-witness local Boolean test relation:
    # (a XOR b = 1) AND (c = a*b).
    a,b,c = z
    return ((a+b-2*a*b-1)%Q, (c-a*b)%Q,
            (a*a-a)%Q, (b*b-b)%Q, (c*c-c)%Q)

def encode_r(r):
    return b''.join(enc(v) for v in r)

SAT = [(0,1,0),(1,0,0)]
UNSAT = [(0,0,0),(1,1,1),(1,1,0),(0,0,1)]

def run():
    assert_check(all(all(x==0 for x in residual(z)) for z in SAT), 'two_satisfying_assignments')
    assert_check(all(any(x!=0 for x in residual(z)) for z in UNSAT), 'nonzero_invalid_residuals')
    for i in range(64):
        seed = i.to_bytes(4,'big')
        ctx = H(b'claim-and-graph-context', seed)
        # Source-independent synthetic frozen signature, NOT SLH-DSA.
        sigma = H(b'fixed-cancellation-capability',seed)
        check = H(b'check',ctx,sigma)
        public_salt = H(b'capsule-salt',seed)
        # FGR: any publicly evaluable non-linear function G of the
        # complete residual tuple remains evaluable at public 0.
        def G(r):return H(b'nonlinear-SHA256-pad',ctx,public_salt,encode_r(r))
        zero=(0,)*5
        E = xor(sigma,G(zero))
        for z in SAT:
            opened = xor(E,G(residual(z)))
            assert_check(opened==sigma, 'FGR_correct_for_each_valid_witness')
            assert_check(H(b'check',ctx,opened)==check, 'FGR_valid_checking_key')
        for z in UNSAT:
            opened = xor(E,G(residual(z)))
            assert_check(opened!=sigma, 'FGR_invalid_test_open_failure')
        # STRAIGHT LINE unauthorized attack, with no source witness.
        recovered = xor(E,G(zero))
        assert_check(recovered==sigma, 'FGR_unauthorized_public_zero_extraction')
        assert_check(H(b'check',ctx,recovered)==check, 'FGR_checking_key_confirms_attack')
        # Repair A binds SHA pad to FULL transcript. Build must freeze
        # value for one designated valid source witness; another valid
        # witness cannot open that key with its different transcript.
        def T(z):
            return H(b'synthetic-SHA-transcript',ctx,bytes(z))
        def GA(z):return H(b'trace-bound-pad',ctx,encode_r(residual(z)),T(z))
        E_A=xor(sigma,GA(SAT[0]))
        assert_check(xor(E_A,GA(SAT[0]))==sigma,'trace_designated_opens')
        assert_check(xor(E_A,GA(SAT[1]))!=sigma,'trace_alternate_valid_fails')
        # Repair B normalizes the transcript to a public fixed prefix.
        normalized = H(b'public-common-SYS-prefix',ctx)
        def GB(r):return H(b'normalized-SHA-pad',ctx,normalized,encode_r(r))
        E_B=xor(sigma,GB(zero))
        assert_check(all(xor(E_B,GB(residual(z)))==sigma for z in SAT),
                     'normalization_restores_completeness')
        assert_check(xor(E_B,GB(zero))==sigma,
                     'normalization_restores_early_extraction')
        # Repair C: keeping a private salt out of the public capsule
        # makes the modeled Open unable to compute the pad. Test that
        # a wrong public guess fails; this is NOT a generic impossibility
        # result for every hidden-salt/obfuscated implementation.
        secret_salt=H(b'private-salt',seed)
        E_C=xor(sigma,H(b'private-pad',ctx,secret_salt,encode_r(zero)))
        guessed_public_pad=H(b'private-pad',ctx,public_salt,encode_r(zero))
        assert_check(xor(E_C,guessed_public_pad)!=sigma,'secret_salt_not_publicly_derived')
        assert_check(H(b'private-pad',ctx,secret_salt,encode_r(zero)) != guessed_public_pad,
                     'private_salt_differs_from_public_salt')
    return {'run':'R212-residual-factorization',
            'counts':dict(sorted(C.items())),
            'assertions':sum(C.values()),
            'scope':'synthetic finite SHA256 algebra / direct public computation; NOT source-conditioned WE, a QPT proof, or a SHA break'}

if __name__=='__main__':
    print(json.dumps(run(),sort_keys=True,indent=2))
