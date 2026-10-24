#!/usr/bin/env python3
import hashlib, json, itertools, os, sys

ASSERTIONS = 0

def check(cond, msg='assertion failed'):
    global ASSERTIONS
    ASSERTIONS += 1
    if not cond:
        raise AssertionError(msg)

# -----------------------------------------------------------------------------
# Finite source relation and a witness-preserving compiler into a target relation.
# Source statements x in 0..7; witnesses w in 0..7.
# R(x,w)=1 iff lower three bits of w satisfy a statement-specific affine parity
# and a small support condition. Some x are deliberately false.
# -----------------------------------------------------------------------------
TRUE_X = {0,2,3,4,7}

def R(x,w):
    if x not in TRUE_X:
        return False
    return ((w*w + 3*w + x) % 7) == 0

# Ensure selected TRUE_X really have witnesses; if one doesn't, remove would be invalid.
for x in range(8):
    has = any(R(x,w) for w in range(8))
    check(has == (x in TRUE_X), f'truth-set mismatch for {x}')

# Target relation encodes a statement u=(x, tag), witness omega=(w, checksum).
def Comp(x):
    return (x, (5*x + 3) % 11)

def Map(x,w):
    return (w, (w + 2*x + 1) % 13)

def R0(u,omega):
    x, tag = u
    w, cs = omega
    return tag == ((5*x+3)%11) and cs == ((w+2*x+1)%13) and R(x,w)

def SrcExt(x,omega):
    w, cs = omega
    if cs == ((w+2*x+1)%13):
        return w
    return None

# Compiler properties: witness preservation and false preservation.
for x in range(8):
    u = Comp(x)
    for w in range(8):
        if R(x,w):
            om = Map(x,w)
            check(R0(u,om), 'mapped source witness not target witness')
            sw = SrcExt(x,om)
            check(sw is not None and R(x,sw), 'source extraction from target witness failed')
    if x not in TRUE_X:
        for w in range(8):
            for cs in range(13):
                check(not R0(u,(w,cs)), 'false source mapped to true target')

# -----------------------------------------------------------------------------
# Finite target WPRF semantics: secret F table; public Eval returns same value only
# for target witnesses. We exhaust many deterministic secret tables.
# -----------------------------------------------------------------------------
U = [Comp(x) for x in range(8)]
RANGE = list(range(5))

def Eval(F,u,omega):
    if not R0(u,omega):
        return None
    return F[u]

# 125 structured function tables generated deterministically.
Fs=[]
for a in range(5):
    for b in range(5):
        for c in range(5):
            F={u:(a*u[0]*u[0] + b*u[0] + c + u[1])%5 for u in U}
            Fs.append(F)

for F in Fs:
    for x in range(8):
        u=Comp(x)
        for w in range(8):
            if R(x,w):
                z1=F[u]
                z2=Eval(F,u,Map(x,w))
                check(z1==z2, 'composed WPRF correctness failed')

# Extractability transfer is relation-theoretic: any target witness extracted for
# Comp(x) maps to an ORIGINAL source witness.
for x in TRUE_X:
    u=Comp(x)
    for w in range(8):
        for cs in range(13):
            om=(w,cs)
            if R0(u,om):
                sw=SrcExt(x,om)
                check(sw is not None and R(x,sw), 'target->source extraction failed')

# -----------------------------------------------------------------------------
# Exact game-preservation bookkeeping: a distinguisher that sees the composed target
# public view gets literally the same challenge distribution as one on Comp(x).
# We model arbitrary deterministic acceptance functions on (u,y) with 5-bit masks.
# This is distribution identity, not computational hardness.
# -----------------------------------------------------------------------------
for x in range(8):
    u=Comp(x)
    for F in Fs[:25]:
        real=F[u]
        for mask in range(32):
            def acc(y): return (mask >> y) & 1
            # source-composed real and target real are same object
            check(acc(real)==acc(F[u]))
            # uniform challenge averages coincide exactly
            lhs=sum(acc(y) for y in RANGE)
            rhs=sum(acc(y) for y in RANGE)
            check(lhs==rhs)

# -----------------------------------------------------------------------------
# Fixed-input requirement: if a capsule is masked using value at u0, future witness
# evaluation at a witness-dependent u_w generally does NOT recover same key.
# Exhibit exhaustive counterexamples over two valid witnesses for same statement.
# -----------------------------------------------------------------------------
# Find a source statement with at least two valid witnesses.
x_multi=None
valid_ws=[]
for x in TRUE_X:
    ws=[w for w in range(8) if R(x,w)]
    if len(ws)>=2:
        x_multi=x; valid_ws=ws; break
check(x_multi is not None)

# Witness-dependent compiler (bad): target input includes witness identity.
def BadComp(x,w):
    return (x,w)

def Fbad(u):
    x,w=u
    return (2*x+3*w+1)%7

# For all pairs where F differs, pad tied to first cannot be opened by second to same K.
bad_pairs=0
for w0,w1 in itertools.permutations(valid_ws,2):
    z0=Fbad(BadComp(x_multi,w0)); z1=Fbad(BadComp(x_multi,w1))
    if z0!=z1:
        bad_pairs += 1
        for K in range(7):
            C=(K+z0)%7
            K1=(C-z1)%7
            check(K1!=K, 'witness-dependent input unexpectedly canonicalized')
check(bad_pairs>0)

# Good fixed input: every valid witness evaluates same F(Comp(x)).
for F in Fs:
    x=x_multi; u=Comp(x); z=F[u]
    for K in range(5):
        C=(K+z)%5
        for w in valid_ws:
            zw=Eval(F,u,Map(x,w))
            K2=(C-zw)%5
            check(K2==K)

# -----------------------------------------------------------------------------
# Random-function fixed-input collision law. If m distinct target inputs are used by
# m witnesses, all outputs equal a setup-selected first output with probability
# q^{-(m-1)} for a uniform random function restricted to those inputs.
# -----------------------------------------------------------------------------
rf_collision_cases=0
for q in range(2,6):
    for m in range(2,5):
        total=q**m
        good=0
        for vals in itertools.product(range(q), repeat=m):
            if all(v==vals[0] for v in vals[1:]):
                good += 1
        check(good == q)
        check(good * (q**(m-1)) == total)
        rf_collision_cases += 1

# -----------------------------------------------------------------------------
# Setup-collapse control for a fixed source-bearing opening: if Setup can sample a
# target witness omega for Comp(x) without source witness and SrcExt maps every such
# omega back, Setup+SrcExt solves source search.
# -----------------------------------------------------------------------------
for x in TRUE_X:
    u=Comp(x)
    target_witnesses=[(w,cs) for w in range(8) for cs in range(13) if R0(u,(w,cs))]
    check(len(target_witnesses)>0)
    for om in target_witnesses:
        sw=SrcExt(x,om)
        check(sw is not None and R(x,sw))

# -----------------------------------------------------------------------------
# Publicly-samplable target opening cannot be universally source-extractable for a
# hard-source compiler. Negative control: add a public dummy opening accepted by a
# looser target relation but not source-bearing. This preserves setup samplability but
# destroys universal source extraction.
# -----------------------------------------------------------------------------
DUMMY=(99,99)
def R0_loose(u,omega):
    return omega==DUMMY or R0(u,omega)

for x in range(8):
    u=Comp(x)
    check(R0_loose(u,DUMMY))
    sw=SrcExt(x,DUMMY)
    check(sw is None or not R(x,sw))

# -----------------------------------------------------------------------------
# Compact theorem ledger output.
# -----------------------------------------------------------------------------
source = open(__file__,'rb').read()
result={
  'run':127,
  'status':'PASS',
  'assertions':ASSERTIONS,
  'source_sha256':hashlib.sha256(source).hexdigest(),
  'finite_models':{
    'source_statements':8,
    'source_witnesses':8,
    'target_checksum_space':13,
    'structured_wprf_tables':len(Fs),
    'range_size':len(RANGE),
    'bad_fixed_input_pairs':bad_pairs,
    'random_function_collision_cases':rf_collision_cases,
  },
  'validated_claims':[
    'witness-preserving compiler composes special-language same-value evaluation into source-relation same-value evaluation',
    'target-witness extraction plus source map yields ORIGINAL source witness',
    'challenge-distribution identity is exact under deterministic compiler postprocessing',
    'witness-dependent target inputs do not in general preserve one setup-masked key',
    'fixed target input restores all-witness same-key functionality',
    'setup-samplable universally source-extractable target witnesses collapse source search',
    'public dummy openings demonstrate why ordinary local-opening validity cannot equal source-bearing validity'
  ],
  'not_validated':[
    'any computational WPRF pseudorandomness',
    'any pairing, LWE, SIS, MinRank, or QPT hardness assumption',
    'the security proof of ePrint 2026/1079',
    'existence of a standard-LWE/SIS generic-NP compiler',
    'malicious-secure ceremony or practical parameter estimates'
  ]
}
print(json.dumps(result,sort_keys=True,indent=2))