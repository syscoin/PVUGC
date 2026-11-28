#!/usr/bin/env python3
"""Synthetic high-degree hidden-support quotient mask test; not an ORIGINAL bridge certificate."""
import json, random, hashlib, itertools
R=random.Random(3380917)
N=12
# Boolean monomial encoded as bitmask; polynomial over F2, represented by set of monomials.
def mulpoly(f,mono):
    z=set()
    for t in f:
        u=t|mono
        if u in z:z.remove(u)
        else:z.add(u)
    return z

def constraints():
    f=[{0,1}]
    for i in range(1,9):
        # all-one input satisfies x_i = x_(i-1) AND x_((i-1)//2)
        f.append({1<<i, (1<<(i-1)) | (1<<((i-1)//2))})
    # Explicit SHA-256 Ch gate equation with output x9:
    # x9 + x0*x1 + x2 + x0*x2 == 0 (all bits 1 is satisfying).
    f.append({1<<9, (1<<0)|(1<<1), 1<<2, (1<<0)|(1<<2)})
    return f
F=constraints()
assert all((sum(1 for _ in f)&1)==0 for f in F) # every f has two terms at all ones
# Random hidden sparse multiplier supports. Their degree is high, unknown to attacker.
Q=[]
for i,f in enumerate(F):
    terms=[]
    if i==0:terms.append(0)
    seen=set(terms)
    while len(terms)<7:
        degree=R.randint(6,10)
        u=sum(1<<j for j in R.sample(range(N),degree))
        if u in seen or not mulpoly(f,u):continue
        seen.add(u);terms.append(u)
    Q.append(terms)
S=R.getrandbits(256)
# Builder serializes ONLY expanded coefficient dictionary, not Q supports/coefficients.
P={0:S}
for f, terms in zip(F,Q):
    for u in terms:
        b=R.getrandbits(256)
        for m in mulpoly(f,u):
            P[m]=P.get(m,0)^b
P={m:b for m,b in P.items() if b}
assert len(P)<200
# Honest opening at satisfying all-one assignment returns same S.
def evaluate(P,z):
    a=0
    for m,b in P.items():
        if (m&z)==m:a^=b
    return a
assert evaluate(P,(1<<N)-1)==S
# Exhaustively establish correctness for EVERY satisfying input of this fixture.
valid=[z for z in range(1<<N) if all((sum(1 for m in f if (m&z)==m)%2)==0 for f in F)]
invalid=[z for z in range(1<<N) if z not in set(valid)]
assert len(valid)>=2 and invalid
assert all(evaluate(P,z)==S for z in valid)
# Adversary sees P and F, NO Q supports, Q coefficients or valid witness.
# Each printed output monomial m can come from multiplier u with u | t = m,
# for t a term of the local Boolean gate constraint. Enumeration <=2^local_degree.
candidates=set()
for m in set(P)|{0}:
    for f in F:
        for t in f:
            if t&m != t:continue
            sub=t
            while True:
                u=(m&~t)|sub
                if mulpoly(f,u):candidates.add((tuple(sorted(f)),u))
                if sub==0:break
                sub=(sub-1)&t
G=[sum(1<<m for m in mulpoly(set(ft),u)) for ft,u in sorted(candidates)]
# One basis over full Boolean coefficient space, regardless of polynomial degree.
basis={}
def insert(v):
    while v:
        pivot=v.bit_length()-1
        if pivot in basis:v^=basis[pivot]
        else:basis[pivot]=v;return

def reduce(v):
    while v:
        pivot=v.bit_length()-1
        if pivot not in basis:return v
        v^=basis[pivot]
    return 0
for g in G:insert(g)
E0=1
assert reduce(E0)!=0 # every g vanishes at true all-one assignment
# Attempt exact coefficient reconstruction for each secret bit; no public evaluations at a valid witness.
S2=0
fail=[]
for bit in range(256):
    vector=sum(1<<m for m,b in P.items() if (b>>bit)&1)
    if reduce(vector)==0:Sb=0
    elif reduce(vector^E0)==0:Sb=1
    else:fail.append(bit);continue
    S2|=Sb<<bit
# Honest hidden Q support coverage after reverse enumeration is checked only in the diagnostic.
selected=set((tuple(sorted(f)),u) for f,terms in zip(F,Q) for u in terms if mulpoly(f,u))
coverage=len(selected & candidates)
# FALSE instance: x0=1 AND x0=0, independent random coefficient shift
f0={0,1}; fbad={1};
assert mulpoly(f0,0)^mulpoly(fbad,0)=={0}
T=R.getrandbits(256);a=R.getrandbits(256);b=R.getrandbits(256)
false_P0={0:T^a,1:a^b};delta=R.getrandbits(256)
false_P1={0:(T^delta)^(a^delta),1:(a^delta)^(b^delta)}
assert false_P0==false_P1
res={
 'candidate':'sparse high-degree hidden multiplier supports; explicit published polynomial P',
 'n_variables':N,'n_constraints':len(F), 'real_original_source':False,
 'q_support_hidden_from_attacker':True, 'maximum_multiplier_degree':max(u.bit_count() for terms in Q for u in terms),
 'published_nonzero_monomials':len(P), 'inferred_basis_generators':len(G), 'basis_rank':len(basis),
 'honest_same_capability':all(evaluate(P,z)==S for z in valid),
 'valid_witness_count_synthetic':len(valid),
 'selected_nonzero_multiplier_terms':len(selected), 'inferred_term_coverage':coverage,
 'attack_recovered_all_bits':(not fail and S2==S),'attack_unrecovered_bits':len(fail),
 'false_trivial_transcript_shift_exact':false_P0==false_P1,
 'hash_of_public_coefficients':hashlib.sha256(json.dumps(sorted(P.items())).encode()).hexdigest(),
}
print(json.dumps(res,sort_keys=True,indent=2))
