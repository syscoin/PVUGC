#!/usr/bin/env python3
"""Finite exact OR-pad/algebra checks; NO ORIGINAL hash release, no QPT test."""
import itertools, json, hashlib

Q = 4

def xor(a,b): return a ^ b

def listrange(n): return range(n)

def exact_hybrid_check():
    # With all branch keys independent and uniform, every public pad vector D is
    # uniform for each chosen sigma. This checks H3 game algebra, not Enc security.
    counts = {}
    for sigma in range(Q):
        dcounts = {}
        for keys in itertools.product(range(Q),repeat=3):
            ds = tuple(xor(sigma,k) for k in keys)
            dcounts[ds] = dcounts.get(ds,0)+1
        assert len(dcounts)==Q**3
        assert set(dcounts.values())=={1}
        counts[str(sigma)]={'support':len(dcounts),'each_multiplicity':1}
    return counts

def perfect_marginal_joint_fail():
    # Enc1/Enc2 are not source encryption. Synthetic demonstration: uniform R,
    # C1=K XOR R, C2=R. Both marginals are uniform and hide K but (C1,C2)
    # recovers K exactly. Such a coupling needs malicious/shared setup randomness.
    prior={}; pairs=[]
    for K in range(Q):
        for R in range(Q):
            C1, C2=K^R, R
            prior.setdefault((K,C1),0)
            prior[(K,C1)]+=1
            pairs.append((K,C1,C2))
    for K in range(Q):
        assert [prior[(K,x)] for x in range(Q)]==[1]*Q
    assert all((a^b)==K for K,a,b in pairs)
    return {'individual_marginal_support':Q,'joint_key_recovery':len(pairs),'total':len(pairs)}

def branch_open_key_transfer():
    # Uniform independent K_j, native signature sigma is a synthetic value.
    # An authorized sig opening in any one branch implies every *raw* leaf K_j.
    count=0
    for sigma in range(Q):
        for keys in itertools.product(range(Q),repeat=3):
            D=tuple(sigma^k for k in keys)
            for opened_branch in range(3):
                recovered_sig=D[opened_branch]^keys[opened_branch]
                assert recovered_sig==sigma
                leaked_keys=tuple(d^recovered_sig for d in D)
                assert leaked_keys==keys
                count+=1
    return count

def opening_equivalence_class():
    # Two capsules referring to the SAME native signature and spending message
    # are the same authorized output once one is opened, regardless of
    # assertion/witness identifier. This tests R225 endpoint-scope algebra.
    examples=[]
    for sigma in range(Q):
        for k0 in range(Q):
            for k1 in range(Q):
                d0=sigma^k0;d1=sigma^k1
                assert (d0^k0)==(d1^k1)==sigma
                # even without opening capsule 1, sigma from opening 0 is its
                # native authorization, independent of capsule 1's statement.
                assert (d1^sigma)==k1
                examples.append((sigma,k0,k1))
    return len(examples)

def xor_leak_across_reused_key():
    # Reusing a raw OTP key in two signatures leaks XOR of their contents,
    # even if ciphertexts are individually uniformly distributed.
    cnt=0
    for s0 in range(Q):
        for s1 in range(Q):
            for k in range(Q):
                d0=s0^k;d1=s1^k
                assert d0^d1 == s0^s1
                assert d1^(d0^s0) == s1
                cnt+=1
    return cnt

def public_key_check_breaks_raw_ror():
    # Exact toy universe: any public checking hash of a raw encapsulated K
    # distinguishes the key itself from a uniform random candidate. This does
    # not constitute a source-dependent challenge scheme or QPT attack test.
    def check(k): return hashlib.sha256(b'ck\0'+k.to_bytes(2,'big')).digest()
    n=1<<12
    labels=[check(k) for k in range(n)]
    assert len(set(labels))==n # explicit checked finite set
    # For independent keys K,U, success under real is 1; random success 1/n.
    # Derive exact random success by counting equality in the checked set.
    counts={t:0 for t in labels}
    for t in labels: counts[t]+=1
    random_equal=sum(v*v for v in counts.values())
    assert random_equal==n
    return {'key_space':n,'real_accept_numerator':n*n,
      'uniform_accept_numerator':random_equal,'denominator':n*n,
      'distinguishing_advantage_numerator':n*n-random_equal}

def main():
    res={'run':'R226-CONTINUATION-20261111',
         'hybrid_final_pad_distribution':exact_hybrid_check(),
         'marginal_vs_joint_counterexample':perfect_marginal_joint_fail(),
         'authorized_openings_reveal_raw_sibling_keys':branch_open_key_transfer(),
         'same_native_signature_opening_equivalence':opening_equivalence_class(),
         'reused_key_two_slot_leakage':xor_leak_across_reused_key(),
         'raw_key_ror_with_public_check_hash':public_key_check_breaks_raw_ror(),
         'scope':'finite algebra only; NO hash-only original-dependent Enc/Open or quantum security proof'}
    return res

if __name__=='__main__':
    print(json.dumps(main(),sort_keys=True,indent=2))
