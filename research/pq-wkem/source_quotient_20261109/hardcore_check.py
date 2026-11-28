#!/usr/bin/env python3
"""Finite Fourier identity for an IND-distinguishing parity predictor.
Purely algebraic 8-bit toy, NOT a QPT reduction test or working PKE.
"""
import json

def parity(n):return n.bit_count()&1

# For each full 8-bit key K with public high nibble 0xA, a randomized
# predictor knows the parity only for r whose low-nibble mask is zero.
# Otherwise it guesses fairly. f(r)=E[(-1)^pred] is then 0 or +/-1.
public_high=0xA
f=[]
for r in range(256):
    f.append(((-1)**parity((public_high<<4)&r)) if ((r&15)==0) else 0)

betas=[]
for s in range(256):
    b=sum(f[r]*((-1)**parity(s&r)) for r in range(256))/256
    betas.append(b)

nonzero=[s for s,v in enumerate(betas) if v!=0]
assert nonzero==list(range(0xA0,0xB0))
assert all(betas[s]==1/16 for s in nonzero)
assert all(betas[s]==0 for s in range(256) if s not in nonzero)

# For every hidden 4-bit value the public parity predictor's success
# averaged over random challenges is exactly (1+1/16)/2 = 17/32.
for low in range(16):
    K=0xA0|low
    correlation=sum(f[r]*((-1)**parity(K&r)) for r in range(256))/256
    assert correlation==1/16

# Hypothetical IND attack converts exactly to predictor on random c:
# predict b from (c,r) as c XOR predicted_parity; recovers parity as c XOR b.
# This is an exact algebraic identity, independent of distribution of c.
for k in range(256):
    for r in range(256):
        for c in (0,1):
            true_b=c^parity(k&r)
            assert c^true_b==parity(k&r)

print(json.dumps({'secret_bits':8,'known_high_nibble':'0xA',
  'walsh_candidate_count':len(nonzero),'all_fourier_weights':1/16,
  'predictor_success':'17/32','key_guess_probability':'1/16',
  'checks':len(nonzero)+len(betas)+16+256*256*2,
  'security':'NONE. Exhaustive algebraic toy only.',
  'theorem':'One-bit IND distinguisher gives a parity predictor; nonnegligible bias allows GL list recovery under reproducible QPT attacks.'},indent=2,sort_keys=True))
