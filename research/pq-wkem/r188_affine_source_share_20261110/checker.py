#!/usr/bin/env python3
"""R188 affine-source-share math. NOT a source oracle, WE, or QPT experiment.

The only secret 'share evaluation' function is PRIVATE TEST ONLY and is used
solely to test the proposed interpolation invariant. A real public source-
conditioned BuildSourceShare/OpenSourceShare is entirely missing.
"""
import hashlib, json
from collections import Counter

P = (1 << 521) - 1
checks = Counter()

def checked(v, name):
    assert v, name
    checks[name] += 1

def H(label, *parts):
    payload = label + b'\x00' + b''.join(len(p).to_bytes(4,'big')+p for p in parts)
    return hashlib.sha256(payload).digest()

def z_from_child(child):
    # Injective from actual 32-byte child ID into large positive field range.
    assert len(child)==32
    return int.from_bytes(child,'big')+1

def field_sample(label, seed):
    # For functional check only: deterministic pseudorandom field samples.
    return int.from_bytes(hashlib.shake_256(label+seed).digest(66),'big') % P

def private_TEST_ONLY_eval(K, a, z):
    # This must NOT be mistaken for a public source-dependent evaluator.
    return (K+a*z) % P

def interpolate(z0, u0, z, u):
    if z==z0:
        return None
    return ((z*u0-z0*u)*pow(z-z0,-1,P))%P

def test_large_field():
    for seednum in range(128):
        seed=seednum.to_bytes(4,'big')
        childA=H(b'claim-relevant-child-A',seed)
        z0=z_from_child(childA)
        checked(0<z0<P,'nonzero_injective_semantic_mapping')
        K=field_sample(b'key',seed)
        a=field_sample(b'slope',seed)
        u0=private_TEST_ONLY_eval(K,a,z0)
        for work_variant in range(5):
            # Changing parent WorkID leaves the *child* semantic ID invariant.
            new_parent_work_id=H(b'parent-work',seed,bytes([work_variant]))
            assert len(new_parent_work_id)==32
            zsame=z_from_child(childA)
            checked(zsame==z0,'parent_work_variant_same_semantic_child')
            checked(interpolate(z0,u0,zsame,private_TEST_ONLY_eval(K,a,zsame)) is None,
                    'same_semantic_child_does_not_release')
        for b in range(1,65):
            alt=H(b'claim-relevant-alternate-child',seed,bytes([b]))
            z=z_from_child(alt)
            checked(z!=z0,'distinct_toy_semantic_child')
            u=private_TEST_ONLY_eval(K,a,z)
            checked(interpolate(z0,u0,z,u)==K,'all_distinct_alternates_same_intercept')
            # This is the *fatal* case if a malicious public evaluator accepts
            # the field value without proving original source authentication.
            checked(interpolate(z0,u0,z,private_TEST_ONLY_eval(K,a,z))==K,
                    'fabricated_token_with_unguarded_eval_releases_early')
        checked((u0-a*z0)%P==K,'retained_source_slope_releases_early')
        checked(interpolate(z0,u0,z0,u0) is None,'baseline_share_alone_no_interpolation')

def test_exact_uniformity():
    p=7
    z0=2
    # A single observed public baseline share is uniform for each fixed K
    # if slope a is uniform in F_p.
    for K in range(p):
        histogram=Counter((K+a*z0)%p for a in range(p))
        checked(len(histogram)==p and set(histogram.values())=={1},
                'uniform_single_baseline_given_K')
    # For three independent slopes, all p^3 vectors occur exactly once.
    z_baselines=(2,3,4)
    for K in range(p):
        outcomes=Counter()
        for a in range(p):
            for b in range(p):
                for c in range(p):
                    slopes=(a,b,c)
                    observed=tuple((K+v*z)%p for v,z in zip(slopes,z_baselines))
                    outcomes[observed]+=1
        checked(len(outcomes)==p**3 and set(outcomes.values())=={1},
                'uniform_three_independent_baselines_given_K')
    # Reusing one slope across distinct semantic reference heights leaks K
    # via ordinary interpolation, even *without* a challenger source witness.
    for K in range(p):
        for a in range(p):
            u1=(K+a*z_baselines[0])%p
            u2=(K+a*z_baselines[1])%p
            recovered=((z_baselines[1]*u1-z_baselines[0]*u2)
                       *pow(z_baselines[1]-z_baselines[0],-1,p))%p
            checked(recovered==K,'reused_slope_two_public_baselines_leak_K')

def main():
    test_large_field()
    test_exact_uniformity()
    return {
        'run':'R188-AFFINE-SOURCE-SHARE-20261110',
        'total_checks':sum(checks.values()),
        'groups':dict(sorted(checks.items())),
        'field':'2^521-1',
        'full_public_source_gated_evaluator':'NOT CONSTRUCTED',
        'original_source_admission':'NOT IMPLEMENTED',
        'runtime_authentication':'PRIVATE TEST HELPER ONLY',
        'native_signature':'NOT IMPLEMENTED',
        'qpt_security':'NOT PROVED OR TESTED',
        'source_sha256':hashlib.sha256(open(__file__,'rb').read()).hexdigest()
    }

if __name__=='__main__':
    print(json.dumps(main(),sort_keys=True,indent=2))
