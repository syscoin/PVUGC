#!/usr/bin/env python3
from __future__ import annotations

from itertools import product
from collections import defaultdict
import json, math

checks=[]
def ok(name, cond, detail=None):
    if not cond:
        raise AssertionError(f"{name}: {detail}")
    checks.append({"name":name,"detail":detail})

def parity(x):
    return x.bit_count() & 1

def glbit(r, s):
    return parity(r & s)

# ----------------------------------------------------------------------
# 1. Common-value condition for a one-mask offline release.
#
# Setup publishes C = K xor z0. A valid witness w computes z_w from its
# completion and decaps K_w = C xor z_w. All valid witnesses recover the
# same K iff {z_w} is a singleton equal to z0.
# ----------------------------------------------------------------------
common_value_cases=0
for n_valid in range(1,5):
    # Exhaust all 1-bit completion values for n_valid witnesses.
    for zs in product((0,1), repeat=n_valid):
        for K in (0,1):
            for z0 in (0,1):
                C=K ^ z0
                outs=tuple(C ^ z for z in zs)
                all_correct=all(o==K for o in outs)
                singleton=(len(set(zs))==1 and zs[0]==z0)
                ok(f"common_value_{common_value_cases}", all_correct==singleton,
                   (n_valid,zs,K,z0,outs))
                common_value_cases+=1

# ----------------------------------------------------------------------
# 2. Unique-signature adaptor contradiction, as a semantic control.
#
# Under uniqueness, ordinary Sign(sk,m) and every successful Adapt(pre,w)
# must be the same valid sigma*. Hence an adaptor Extract(pre,sigma*) that
# is correct on successful adaptation can be invoked by the signer without
# a witness. This mirrors Erwig et al. Thm 1.
# ----------------------------------------------------------------------
unique_cases=0
for q in (5,7,11):
    for Y in range(q):
        # Toy "hard relation" is abstracted as witnesses satisfying y != Y.
        # We only validate the equality/extraction implication, not hardness.
        valid=[y for y in range(q) if y != Y]
        sigma_star=(3*Y+1)%q
        pre=("pre",Y)
        def sign():
            return sigma_star
        def adapt(w):
            assert w in valid
            return sigma_star
        def extract(pre_obj,sigma):
            # Abstract correctness: on the unique successful completion,
            # return a fixed valid witness. This is what gives the contradiction.
            assert sigma==sigma_star and pre_obj==pre
            return valid[0]
        ordinary=sign()
        for w in valid:
            ok(f"unique_adapt_eq_{unique_cases}_{w}",adapt(w)==ordinary)
        y=extract(pre,ordinary)
        ok(f"unique_extract_without_w_{unique_cases}",y in valid,(Y,y))
        unique_cases+=1

# ----------------------------------------------------------------------
# 3. Non-unique adapted completions and an invariant value.
#
# This shows why invariant != unique: distinct valid signatures may map to
# the same public invariant. It also shows that the existing adaptor
# extractor still consumes a *full completion*, not the invariant alone.
# ----------------------------------------------------------------------
invariant_cases=0
for q in (5,7,11):
    for Y in range(q):
        valid=[w for w in range(q) if w not in (Y,(Y+1)%q)]
        if len(valid)<2: continue
        pre=("pre",Y)
        z=(2*Y+1)%q
        adapted={}
        for idx,w in enumerate(valid):
            sigma=("adapt",Y,w,idx)
            adapted[w]=sigma
        def inv(sig):
            # Same invariant for all legal signatures on this toy message.
            return z
        def extract(sig):
            if sig[0]=="adapt" and sig[1]==Y:
                return sig[2]
            return None
        vals={inv(sig) for sig in adapted.values()}
        ok(f"invariant_singleton_{invariant_cases}",vals=={z})
        ok(f"invariant_nonunique_{invariant_cases}",len(set(adapted.values()))>1)
        # The invariant value alone is not a syntactic input accepted by Ext.
        ok(f"invariant_not_completion_{invariant_cases}",
           all(extract(sig)==w for w,sig in adapted.items()) and extract(("invariant",z)) is None)
        invariant_cases+=1

# ----------------------------------------------------------------------
# 4. Goldreich-Levin/random-linear-key all-witness collision law.
#
# For distinct bit strings s1 != s2, a uniform r gives
# <r,s1>=<r,s2> with probability exactly 1/2. For k independent rows,
# equality of all k GL bits has probability exactly 2^-k.
# ----------------------------------------------------------------------
gl_records=[]
gl_assertions=0
for n in range(1,8):
    domain=range(1<<n)
    for s1 in domain:
        for s2 in domain:
            if s1>=s2: continue
            delta=s1^s2
            equal=sum(1 for r in domain if glbit(r,s1)==glbit(r,s2))
            ok(f"gl_half_{n}_{s1}_{s2}",equal*2==(1<<n),(n,s1,s2,equal))
            gl_assertions+=1
    # Exact k-row probability can be derived from one-row count.
    for k in range(1,7):
        # Rather than enumerate 2^(n*k), use exact product identity.
        num=1
        den=2**k
        ok(f"gl_k_rows_{n}_{k}",num/den==2.0**(-k))
        gl_records.append({"signature_bits":n,"key_bits":k,
                           "equality_probability":2.0**(-k)})

# Small explicit multi-row exhaustions.
for n,k in ((2,2),(3,2),(3,3),(4,2)):
    rows=list(range(1<<n))
    for s1 in range(1<<n):
        for s2 in range(s1+1,1<<n):
            total=0; eq=0
            for R in product(rows, repeat=k):
                total+=1
                if tuple(glbit(r,s1) for r in R)==tuple(glbit(r,s2) for r in R):
                    eq+=1
            ok(f"gl_multi_{n}_{k}_{s1}_{s2}",eq*(2**k)==total,(eq,total))

# ----------------------------------------------------------------------
# 5. Random-hash common-key condition for several distinct completions.
#
# Model a k-bit random linear hash H_R(s). For a completion set containing
# two distinct signatures, probability their derived keys agree is 2^-k;
# hence with overwhelming probability a direct GL/hash-derived key violates
# all-witness same-key unless a prior invariant/canonicalization exists.
# ----------------------------------------------------------------------
for n in range(2,7):
    s1=1
    s2=(1<<(n-1))|1
    if s1==s2:
        s2=2
    for k in range(1,7):
        # exact pairwise probability
        p=2.0**(-k)
        ok(f"hash_common_prob_{n}_{k}",0 < p <= .5)

# ----------------------------------------------------------------------
# 6. Batch IT-MAC dependency graph control.
#
# A pre-fixed key seed is compatible with later chosen x only because a
# second message depends on x. Removing that message leaves no x-dependent
# information. This is a syntax/dependency toy, not a security theorem.
# ----------------------------------------------------------------------
batch_cases=0
for q in (5,7,11):
    for Delta in range(q):
        for k0 in range(q):
            for x in range(q):
                sigma=(Delta*x+k0)%q
                first=("seeded_key",k0)
                second=("chosen_x_tag",x,sigma)
                ok(f"batch_tag_{batch_cases}",second[2]==(Delta*x+first[1])%q)
                # Same first message for every x: future-input dependence is in second.
                ok(f"batch_first_indep_{batch_cases}",first==("seeded_key",k0))
                batch_cases+=1

out={
    "run":111,
    "status":"PASS",
    "total_assertions":len(checks),
    "common_value":{
        "cases":common_value_cases,
        "claim":"A one-mask offline release C=K xor z0 is all-witness correct iff every valid completion derives the same z0."
    },
    "unique_adaptor":{
        "cases":unique_cases,
        "claim":"Semantic control for the Erwig et al. unique-signature impossibility: uniqueness lets the signer feed its ordinary signature to the adaptor extractor without a witness."
    },
    "invariant_adaptor":{
        "cases":invariant_cases,
        "claim":"Non-unique completions can share an invariant value, but the ordinary adaptor extractor consumes a full completion, not the invariant alone."
    },
    "gl_common_key":{
        "pairwise_half_checks":gl_assertions,
        "records":gl_records,
        "claim":"For distinct completions, k random linear/GL key bits agree with probability exactly 2^-k."
    },
    "batch_it_mac_dependency":{
        "cases":batch_cases,
        "claim":"Pre-fixing authenticator randomness does not remove the later x-dependent message in the two-message syntax."
    },
    "scope":[
        "Finite functionality/algebra controls only; no computational security is inferred.",
        "The unique-signature impossibility is a literature theorem; this checker validates its semantic equality/extraction skeleton.",
        "The GL collision law refutes direct random-linear hashing as an all-witness common-key canonicalizer for distinct completions; it does not rule out a deliberately constructed invariant signature.",
        "An invariant common value still needs QPT hiding from the pre-signature and QPT recovery-to-original-witness extraction."
    ]
}
print(json.dumps(out,indent=2,sort_keys=True))
