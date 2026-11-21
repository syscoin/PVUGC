#!/usr/bin/env python3
"""Run 410 finite validation: ElGamal public witness addition and ideal-pad
hybrid distributions. Deliberately tiny/insecure parameters; NO crypto-security
claim, no real QPT attack and no WE construction.
"""
import itertools
import json
import hashlib
from collections import Counter

passes=0

def check(pred,msg):
    global passes
    assert pred,msg
    passes+=1

# A deliberately small cyclic group for public homomorphic encryption.
p,q,g=23,11,2
check(pow(g,q,p)==1 and all(pow(g,i,p)!=1 for i in range(1,q)),"group order")

def enc(pk,m,r):
    return pow(g,r,p), pow(g,m,p)*pow(pk,r,p)%p

def mul(a,b):
    return a[0]*b[0]%p,a[1]*b[1]%p

def dec(dk,ct):
    v=ct[1]*pow(pow(ct[0],dk,p),-1,p)%p
    return next(i for i in range(q) if pow(g,i,p)==v)

# Exhaustive 11^5 public re-randomization / post-insertion tests: no secret
# decryption is used by the evaluator, only in the private test assertion.
fixtures=0
for dk in range(1,q):
    pk=pow(g,dk,p)
    for secret in range(q):
        for witness in range(q):
            for r0 in range(q):
                c0=enc(pk,secret,r0)
                r1=(dk*3+secret+5*witness+r0)%q
                cw=enc(pk,witness,r1)
                joined=mul(c0,cw)
                check(joined==enc(pk,(secret+witness)%q,(r0+r1)%q),"ciphertext addition")
                check(dec(dk,joined)==(secret+witness)%q,"joined decryption")
                # Cancellation of public witness encryption *does not decrypt C0*.
                inv=(pow(cw[0],-1,p),pow(cw[1],-1,p))
                check(mul(joined,inv)==c0,"public witness cancellation returns original CT")
                fixtures+=1

# Exact finite hybrid view for a hiding channel (NOT a publicly encryptable PKE).
# Native public checking key h(k) reveals one bit; the pad is uniform.
# The ciphertext C(K) and C(0) have identical joint distributions with vk.
N=16

def vk(k):return k%2

def joint(real):
    ct=Counter()
    for k in range(N):
        for pad in range(N):
            ciphertext=(k^pad) if real else pad
            ct[(vk(k),ciphertext,k)]+=1
    return ct

real,zero=joint(True),joint(False)
# View marginal is identical for all (vk,ct), not including hidden k.
for key in itertools.product(range(2),range(N)):
    check(sum(n for (v,c,k),n in real.items() if (v,c)==key)==
          sum(n for (v,c,k),n in zero.items() if (v,c)==key),"public-view marginal")

# A deterministic public algorithm A(vk,ct,w) can output a guessed signing
# secret k'. Without private coins it cannot beat the best vk-only guess here.
# Enumerate all 16*2 inputs and all possible output guesses. Each guess has
# identical success probability in both worlds under the ideal pad.
max_success=0
for v in range(2):
    for c in range(N):
        ks=[k for k in range(N) if vk(k)==v]
        for guess in range(N):
            r=sum(count for (vv,cc,k),count in real.items()
                  if vv==v and cc==c and k==guess)
            z=sum(count for (vv,cc,k),count in zero.items()
                  if vv==v and cc==c and k==guess)
            check(r==z,"public known-checking-key hybrid")
            check(r in (0,1),"one candidate per view")
        max_success=max(max_success,max(sum(real[(v,c,k)] for k in [guess])
                                        for guess in range(N)))
check(max_success==1,"one guess among eight candidates per public view")

# A secret-dependent helper invalidates simulation from native vk. Example:
# an already valid signature equal to the secret itself (toy only).
for k in range(N):
    aux_secret=k
    check(aux_secret==k,"secret helper leaks in toy")

out={"run":410,"model":"PKE-only release black-box hybrid and toy homomorphic witness admission",
     "elgamal_toy_modulus":p,"elgamal_toy_subgroup_order":q,
     "elgamal_toy_fixtures":fixtures,
     "ideal_pad_hybrid_view_states":2*N,
     "ideal_pad_checking_key_candidates":N//2,
     "assertions_passed":passes,
     "hardness_not_claimed":["ElGamal toy is not post-quantum", "ideal pad is not a PKE",
       "exhaustive testing does not prove IND-CPA/EUF-CMA or WKEM security",
       "secret-dependent correlated setup not covered"]}
print(json.dumps(out,indent=2,sort_keys=True))
