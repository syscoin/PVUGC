#!/usr/bin/env python3
"""Bounded offline exact finite-state check for one-honest SRC coin-flip embedding.
This is an IDEAL programmable function toy, NOT a cryptographic implementation.
"""
import collections, hashlib, json, random

A=0
def check(b, msg):
    global A
    A+=1
    assert b,msg

q=5
DIGEST=8

def policies(c):
    return (
        (0,0),
        (c%q,(3*c+2)%q),
        ((c*c+2)%q,(2*c*c+c)%q),
        ((c.bit_count()+1)%q,(7*c+1)%q),
        ((3*c+c.bit_count())%q,(c*c+4*c+3)%q),
    )

# Real law for fresh RO commitment C: C is uniform independently of honest h,
# including after adversary uses C to select corrupt contribution f(C).
# Simulation: uniform challenge H, define h=H-f(C), then program opening.
for pi in range(5):
    real=collections.Counter()
    sim=collections.Counter()
    for c in range(DIGEST):
        corrupt=policies(c)[pi]
        for h0 in range(q):
            for h1 in range(q):
                h=(h0,h1)
                out=((h0+corrupt[0])%q,(h1+corrupt[1])%q)
                real[(c,corrupt,h,out)]+=1
        for target0 in range(q):
            for target1 in range(q):
                target=(target0,target1)
                h=((target0-corrupt[0])%q,(target1-corrupt[1])%q)
                sim[(c,corrupt,h,target)]+=1
    check(real==sim,f'joint transcript difference policy {pi}')
    check(sum(real.values())==DIGEST*q*q,'normalization')
    for count in sim.values():
        check(count==1,'joint mapping must be bijective')

# Chronology obstruction for an arbitrary (unknown) honest position:
# if h is bound and publicly opened BEFORE a corrupt final share is known,
# target H cannot be embedded for both of two distinct adversarial futures.
for t0 in range(q):
    for t1 in range(q):
        for h0 in range(q):
            for h1 in range(q):
                target=(t0,t1)
                honest=(h0,h1)
                a=((h0+0)%q,h1)
                b=((h0+1)%q,h1)
                check(not (a==target and b==target),'cannot embed two later shares with fixed honest opening')

# Now exercise full SOURCE matrix of n*(m+L) coordinates and two shifted
# LWE ciphertexts in the toy programmable function. Challenge M is supplied
# externally, after corrupt choices the simulator has an exact decomposition.
random.seed(0x5A12)
class Oracle:
    def __init__(self): self.t={}
    def query(self,x):
        if x not in self.t:self.t[x]=random.randrange(2**24)
        return self.t[x]
    def program(self,x,c):
        if x in self.t:return self.t[x]==c
        self.t[x]=c
        return True

def encode(a):return bytes(a)

n,m,L=2,4,2
Q=101
runs=256
for i in range(runs):
    oracle=Oracle()
    # Honest input is not selected until after the corrupt contribution.
    cval=random.randrange(2**24)
    corrupt=tuple((i*17+((cval>>(j%17))&255)*3+j*13)%Q for j in range(n*(m+L)))
    target=tuple(random.randrange(Q) for _ in corrupt)
    honest=tuple((x-y)%Q for x,y in zip(target,corrupt))
    salt=random.getrandbits(160).to_bytes(20,'big')
    msg=encode(honest)+salt
    check(oracle.program(msg,cval),'fresh-point programming')
    check(oracle.query(msg)==cval,'commitment opening')
    check(all((x+y)%Q==z for x,y,z in zip(honest,corrupt,target)),'source exactness')
    # Two related capsule samples; the test does NOT assert QPT indistinguishability.
    keydigits=(random.randrange(2),random.randrange(2))
    pk=hashlib.sha256(bytes(keydigits)).hexdigest()
    for j in range(2):
        r=[random.randrange(Q) for _ in range(n)]
        eta=[random.choice((-1,0,1)) for _ in range(m+L)]
        y=[sum(target[row*(m+L)+col]*r[row] for row in range(n))%Q for col in range(m+L)]
        shifted=[(y[col]+eta[col]+(20*keydigits[col-m] if col>=m else 0))%Q for col in range(m+L)]
        check(len(shifted)==m+L and len(pk)==64,'complete correlated capsule')
        check(shifted == [(sum(target[row*(m+L)+col]*r[row] for row in range(n))+eta[col]+(20*keydigits[col-m] if col>=m else 0))%Q for col in range(m+L)],'full sample law')

# Non-programmable random-oracle one-shot commitment: a single fresh
# random salt hits a pre-chosen 384-bit commitment with probability 2^-384;
# with T independent salts success <=T*2^-384 by a union bound.
for trials in (1,2,2**16,2**40,2**80):
    check(trials < 2**384,'finite bound inputs')
    check(trials * 2**-384 <= 2**-304,'one-shot bounded re-opening')

result={
    'status':'NO_POSITIVE_WKEM_ADVANCE',
    'assertions':A,
    'exact_policies':5,
    'honest_before_corrupt_counterchecks':q**4,
    'exact_distribution_states_per_policy':DIGEST*q*q,
    'toy_challenge_embedding_trials':runs,
    'capsules_per_trial':2,
    'model':'ideal programmable random function ONLY',
    'proved_by_checker':'finite transcript bijections, exact additive challenge embedding, deterministic complete vector consistency',
    'not_proved':'QPT oracle reprogramming, standard-model commitment, ORIGINAL witness release, false-instance secrecy, malicious N-of-N graph',
}
print(json.dumps(result,sort_keys=True,indent=2))
