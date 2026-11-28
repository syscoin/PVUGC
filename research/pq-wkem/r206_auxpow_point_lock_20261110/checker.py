#!/usr/bin/env python3
"""R206: direct source-token hash point-lock test; NOT a bridge WKEM or QPT security test."""
import hashlib,json,random,sys
from collections import Counter
C=Counter()
def H(domain,*parts):
    d=domain.encode()+b'\x00'
    for p in parts:d+=len(p).to_bytes(4,'big')+p
    return hashlib.sha256(d).digest()
def X(a,b):return bytes(x^y for x,y in zip(a,b))
def test(v,label):
    if not v:raise AssertionError(label)
    C[label]+=1

def build(s,sigma,c):
    return {'ctx':c,'tag':H('H0',c,s),'sealed':X(sigma,H('H1',c,s)),'check':H('CK',c,sigma)}
def open_point(C,w):
    c=C['ctx']
    if H('H0',c,w)!=C['tag']:return None
    sigma=X(C['sealed'],H('H1',c,w))
    return sigma if H('CK',c,sigma)==C['check'] else None

def case(seed):
    seed=seed.to_bytes(4,'big');c=H('ctx',seed);sig=H('signature_fixture',seed)
    s=H('setup_secret',seed)
    cap=build(s,sig,c)
    test(open_point(cap,s)==sig,'point_preimage_correctness')
    test(open_point(cap,H('unrelated_evidence',seed)) is None,'wrong_point_no_open')
    # Existing source: baseline hash and child-prefix are public before any fault.
    baseline=H('baseline_child',seed)
    public_prefix=H('claim_prefix',baseline)
    alt1=H('future_alt1_child',seed)
    alt2=H('future_alt2_child',seed)
    parent_a=H('parent_work_a',seed)
    parent_b=H('parent_work_b',seed)
    # A constant source-token candidate from baseline is always public.
    baseline_token=H('tag_ancestor',baseline)
    cap_base=build(baseline_token,sig,c)
    test(open_point(cap_base,baseline_token)==sig,'public_baseline_opens_without_fault')
    test(H('tag_ancestor',baseline)==baseline_token,'same_child_tag_value_independent_of_parent_work')
    test(parent_a!=parent_b and baseline_token==H('tag_ancestor',baseline),
         'parent_work_variants_same_child_no_fork')
    cap_prefix=build(public_prefix,sig,c)
    test(open_point(cap_prefix,public_prefix)==sig,'public_prefix_opens_without_fault')
    # Variable future evidence cannot be pre-encrypted to one chosen point.
    s1=H('alternative_candidate',alt1)
    s2=H('alternative_candidate',alt2)
    cap_alt=build(s1,sig,c)
    test(open_point(cap_alt,s1)==sig,'first_alternative_opens')
    test(s1!=s2 and open_point(cap_alt,s2) is None,'second_qualified_alternative_fails_same_point')
    # Even a pair-dependent source token varies across possible fork witnesses.
    pair1=H('pair_normalized',baseline,alt1)
    pair2=H('pair_normalized',baseline,alt2)
    cap_pair=build(pair1,sig,c)
    test(open_point(cap_pair,pair1)==sig and open_point(cap_pair,pair2) is None,
         'pair_specific_token_fails_every_witness')
    # An invented precommitted setup nonce supplies a point lock only when
    # externally and truly delivered. If the source chooses/retains it, it can
    # open without any authenticated fork. Actual source has no such field.
    cap_source=build(s,sig,c)
    test(open_point(cap_source,s)==sig,'retained_source_secret_early_open')
    test(open_point(cap_source,baseline_token) is None and open_point(cap_source,s1) is None,
         'independent_setup_nonce_not_derived_from_actual_source')
    # Domain separation is essential: with tag itself as OTP pad, K is public.
    trivial_sealed=X(sig,H('H0',c,s))
    test(X(trivial_sealed,cap_source['tag'])==sig,'using_tag_as_pad_public_leak')

def main():
    for seed in range(128):case(seed)
    return {'run':'R206-AUXPOW-POINT-LOCK','functional_assertions':sum(C.values()),
            'checks':dict(sorted(C.items())),
            'source_sha256':hashlib.sha256(open(__file__,'rb').read()).hexdigest(),
            'scope':'Synthetic point-lock function and fork token timing tests only; no actual source compiler or QPT proof'}
if __name__=='__main__':print(json.dumps(main(),sort_keys=True,indent=2))
