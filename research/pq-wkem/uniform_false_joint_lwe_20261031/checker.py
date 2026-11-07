#!/usr/bin/env python3
"""Exact finite-field checks for a restricted binary-ISIS average-FALSE QPT-LWE hybrid.
No cryptographic hardness, real signature, QPT, or production implementation is tested.
"""
import hashlib, itertools, json, math, random
RNG = random.Random(20261031)
COUNT=0

def ck(cond, msg='assertion'):
    global COUNT
    COUNT+=1
    if not cond: raise AssertionError(msg)

def dot(a,b,q): return sum(x*y for x,y in zip(a,b))%q

def matvec(A,w,q): return [dot(row,w,q) for row in A]

def source(A,t,k,q=257,B=1,g=17):
    d=len(A); n=len(A[0]); s=[RNG.randrange(q) for _ in range(d)]
    e=[RNG.randint(-B,B) for _ in range(n+1)]
    beta=[(sum(A[i][j]*s[i] for i in range(d))+e[j])%q for j in range(n)]
    tau=(sum(t[i]*s[i] for i in range(d))+e[-1]+g*k)%q
    return (beta,tau)

def center(a,q): return (a+q//2)%q-q//2

def release(A,t,w,y,q=257,g=17):
    ck(all(int(z) in (0,1) for z in w), 'binary witness')
    ck(matvec(A,w,q)==t, 'ORIGINAL witness')
    beta,tau=y
    v=center((dot(beta,w,q)-tau)%q,q)
    return 0 if abs(v)<abs(v+g) else 1

# Exact tiny exhaustive uniform A,t FALSE density vs the union bound.
q0,d0,n0=3,2,2
false_count=total=0
for avals in itertools.product(range(q0),repeat=d0*n0):
    A=[list(avals[i*n0:(i+1)*n0]) for i in range(d0)]
    reachable={tuple(matvec(A,w,q0)) for w in itertools.product((0,1),repeat=n0)}
    for t in itertools.product(range(q0),repeat=d0):
        total+=1; false_count+=tuple(t) not in reachable
ck(total==729)
actual_true=1-false_count/total
union_bound=(2**n0)/(q0**d0)
ck(actual_true<=union_bound+1e-15)

# Sparse, overwhelmingly FALSE source instances, honestly generated WITHOUT a witness.
q,d,n=257,3,6
trials=300
false_found=0
for i in range(trials):
    A=[[RNG.randrange(q) for j in range(n)] for row in range(d)]
    t=[RNG.randrange(q) for row in range(d)]
    found=any(matvec(A,w,q)==t for w in itertools.product((0,1),repeat=n))
    false_found+=not found
    ck(isinstance(found,bool))
ck(false_found==trials, 'rare-source TRUE collision in deterministic test stream')
exact_upper=(2**n)/(q**d)
ck(exact_upper<4e-6)

# More than one distinct valid ORIGINAL witness, same 512-bit precommitted mock capability,
# and many related public capsules sharing the same source matrix and native check key.
A=[[RNG.randrange(q) for j in range(n)] for i in range(d)]
for i in range(d): A[i][1]=A[i][0]
w1=(1,0,0,0,0,0); w2=(0,1,0,0,0,0)
t=matvec(A,w1,q)
ck(matvec(A,w2,q)==t and w1!=w2)
K=[RNG.randrange(2) for _ in range(512)]
mock_pk=hashlib.sha256(bytes(K)).hexdigest()
related_capsules=3
releases=0
for cap in range(related_capsules):
    for bit in K:
        y=source(A,t,bit,q=q,B=1,g=17)
        ck(release(A,t,w1,y,q=q,g=17)==bit)
        ck(release(A,t,w2,y,q=q,g=17)==bit)
        releases+=2
ck(releases==3072)

# A chosen, nonrandom FALSE A,t remains broken; the theorem MUST NOT cover it.
# R: binary w in {0,1}, A=[1], t=3. Nonbinary z=3 is a public fake opener.
A_bad=[[1]]; t_bad=[3]; qb=257; gb=7
ck(all(matvec(A_bad,(w,),qb)!=t_bad for w in (0,1)))
nonwitness_recovery=0
for bit in K:
    s=RNG.randrange(qb)
    beta=(s+0)%qb
    tau=(3*s+gb*bit+0)%qb
    residual=center((3*beta-tau)%qb,qb)
    guess=0 if abs(residual)<abs(residual+gb) else 1
    ck(guess==bit)
    nonwitness_recovery+=1
ck(nonwitness_recovery==512)

output={
 'candidate':'uniform-FALSE binary-ISIS joint LWE release',
 'status':'restricted average-FALSE theorem, NOT generic NP witness-KEM',
 'tiny_exhaustive':{'q':q0,'d':d0,'n':n0,'total':total,'false_count':false_count,'true_fraction':actual_true,'union_true_upper':union_bound},
 'random_false_test':{'q':q,'d':d,'n':n,'trials':trials,'false_count':false_found,'true_upper_exact':f'{2**n}/{q**d}','true_upper_decimal':exact_upper},
 'multiple_witness':{'distinct_original_witnesses':2,'native_mock_pk_sha256':mock_pk,'capsules':related_capsules,'bits':len(K),'correct_releases':releases},
 'chosen_false_nonwitness':{'A':[1],'t':3,'nonbinary_opener':3,'recovered_bits':nonwitness_recovery},
 'checks':COUNT,
 'caveats':['finite-field algebra only','mock native checking key; no signature','toy LWE parameters are insecure','no QPT computations','not arbitrary FALSE/hard TRUE','no selective opening of protected ciphertext coins']
}
print(json.dumps(output,sort_keys=True,indent=2))
