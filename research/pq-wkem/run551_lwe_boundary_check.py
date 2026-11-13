#!/usr/bin/env python3
"""Run 551: finite exact falsification of threshold-defined LWE release.
No security inference from these toy parameters.
"""
import hashlib, json, random
Q,N,M,B=257,2,6,1
RNG=random.Random(55120261016)
assert Q>4*M*(B+1)

def randmat(): return [[RNG.randrange(Q) for _ in range(M)] for __ in range(N)]
def vec(A,s): return [sum(A[i][j]*s[i] for i in range(N))%Q for j in range(M)]
def make_b(A,s,e): return [(v+z)%Q for v,z in zip(vec(A,s),e)]
def reps(z): return ((z+Q//2)%Q)-Q//2
def witness(A,b,s): return all(abs(reps((bj-v)%Q))<=B for bj,v in zip(b,vec(A,s)))
def ct(A,b,r,bit):
    u=[sum(A[i][j]*r[j] for j in range(M))%Q for i in range(N)]
    v=(sum(b[j]*r[j] for j in range(M))+bit*(Q//2))%Q
    return (u,v)
def dist(a,b): return min((a-b)%Q,(b-a)%Q)
def dec(s,C):
    u,v=C
    d=(v-sum(si*ui for si,ui in zip(s,u)))%Q
    return int(dist(d,Q//2)<dist(d,0))

def all_r():
    for mask in range(1<<M): yield [(mask>>j)&1 for j in range(M)]

true_checks=false_checks=0
brute_candidates=0
false_fixtures=[]
for trial in range(12):
    A=randmat(); s=[RNG.randrange(Q) for _ in range(N)]
    e=[RNG.choice([-1,0,1]) for _ in range(M)]
    btrue=make_b(A,s,e)
    assert witness(A,btrue,s)
    ebad=[B+1]+[0]*(M-1)
    bfalse=make_b(A,s,ebad)
    assert not witness(A,bfalse,s)
    count=0
    for t0 in range(Q):
      for t1 in range(Q):
        brute_candidates+=1
        if witness(A,bfalse,(t0,t1)): count+=1
    assert count==0,(trial,count)
    for r in all_r():
      for bit in (0,1):
        assert dec(s,ct(A,btrue,r,bit))==bit
        true_checks+=1
        assert dec(s,ct(A,bfalse,r,bit))==bit
        false_checks+=1
    false_fixtures.append({'trial':trial,'false_relation_certified':count==0,'near_secret_error_inf':B+1,'randomness_vectors_tested':1<<M})

# Witness multiplicity is genuine on rank-deficient matrices: distinct s produce the SAME bit.
A=[[5,7,11,13,17,19],[0]*M]
s0=(4,7);s1=(4,17)
e=[1,0,-1,0,1,-1]; b=make_b(A,s0,e)
assert s0!=s1 and witness(A,b,s0) and witness(A,b,s1)
multichecks=0
for r in all_r():
 for bit in (0,1):
  assert dec(s0,ct(A,b,r,bit))==bit
  assert dec(s1,ct(A,b,r,bit))==bit
  multichecks+=2

res={'run':551,'model':'toy finite exact Regev-style threshold release','q':Q,'n':N,'m':M,'B':B,'fixtures':12,'brute_force_candidate_secrets_checked':brute_candidates,'valid_relation_decryption_checks':true_checks,'false_relation_unauthorized_decryption_checks':false_checks,'false_relation_witnesses_found':0,'multiple_valid_secret_witness_checks':multichecks,'test_result':'PASS (FALSIFIED worst-case false-instance hiding)','limitations':'Finite classical correctness and exhaustive false-source tests only; not a QPT-LWE proof'}
print(json.dumps(res,indent=2,sort_keys=True))
