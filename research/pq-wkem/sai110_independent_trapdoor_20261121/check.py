#!/usr/bin/env python3
"""Exact finite joint-public conditional-independence checker; NOT a WE/FE prototype.
The SOURCE class is deliberately synthetic, and no original BTC/SYS validation occurs.
"""
import hashlib, json
from collections import Counter, defaultdict

def h(tag, n, bits):
    return hashlib.sha256(tag + n.to_bytes(2,'big')).digest()[0] & ((1<<bits)-1)

# Finite model: hidden simulator token tau, public hash image y and D=S xor K.
# A source producer sees the public capsule and chooses a valid synthetic W
# using a distribution dependent on public image; never sees hidden tau.
# The two-source selector is intentionally biased as a deterministic function
# of the public image, to test adaptivity to the observed capsule.
counts=Counter(); base=Counter(); ext=Counter()
for tau in range(32):
    y=h(b'public/image',tau,3)
    k=h(b'private/pad',tau,5)
    for s in range(32):
        d=s^k
        # Source producer may adapt to the *entire public view* (y,d).
        # Both outcomes retain positive probability, but skew varies with (y,d).
        w0_weight=1+((y+3*d)%4)
        for w,weight in [(0,w0_weight),(1,5-w0_weight)]:
            counts[(y,d,w,k,s)]+=weight
            base[(y,d,k,s)]+=weight
            ext[(y,d,w)]+=weight

by_public=defaultdict(Counter)
by_public_w=defaultdict(Counter)
for (y,d,w,k,s),n in counts.items():
    by_public[(y,d)][(k,s)]+=n
    by_public_w[(y,d,w)][(k,s)]+=n

checked=0
for (y,d,w),cnt in by_public_w.items():
    z=sum(cnt.values()); basecnt=by_public[(y,d)]; bz=sum(basecnt.values())
    assert z and bz
    for ks in set(cnt)|set(basecnt):
        assert cnt[ks]*bz==basecnt[ks]*z, (y,d,w,ks)
        checked+=1

# Direct two-original-like-evidence digests differ for two certificate strings;
# this alone does not invalidate a potential *coupled* source-gated compiler.
source_bytes=[b'synthetic-source-certified-fork-branch-B',b'synthetic-source-certified-fork-branch-C']
proof_hashes=[hashlib.sha256(b'future-proof/'+s).hexdigest() for s in source_bytes]
assert proof_hashes[0]!=proof_hashes[1]
# If an H1 image of a hidden token is publicly visible, a deterministic
# output fixed for all token candidates is rare: report actual posterior sizes.
preimages=Counter(h(b'public/image',t,3) for t in range(32))

print(json.dumps({
  'model':'FINITE synthetic independent-source latent-token model; no SHA mining, original certificates, FE or QPT test',
  'hidden_token_states':32,
  'public_image_states':8,
  'secret_states':32,
  'source_witness_types':2,
  'adaptive_source_distribution':'P(W|Y,D), independent of hidden tau conditional on public view',
  'exact_conditional_posterior_equalities':checked,
  'max_abs_posterior_difference':0,
  'public_image_preimage_count':dict(sorted(preimages.items())),
  'different_synthetic_proof_hashes':proof_hashes[0]!=proof_hashes[1],
  'positive_construction':False,
},sort_keys=True,indent=2))
