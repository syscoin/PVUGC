#!/usr/bin/env python3
"""R162: bounded neighborhood search for nonlinear hash-of-LWE-like-phase release."""
import hashlib, json, random
Q=(1<<521)-1
INV4=pow(4,-1,Q)
E=E0=1
RUN="R162-HASHED-PHASE-ORIGINAL-SOURCE-20261108"
RNG=random.Random(0x16220261108)
CHECKS=0

def ck(x, reason):
    global CHECKS
    CHECKS+=1
    if not x: raise AssertionError(f"assertion {CHECKS}: {reason}")

def compile_cnf(n, clauses):
    m=len(clauses); N=2*n+7*m
    A=[];b=[]
    for i in range(n):
        row=[0]*N;row[2*i]=1;row[2*i+1]=1;A.append(row);b.append(1)
    for j,cl in enumerate(clauses):
        row=[0]*N
        for p in range(1,8):row[2*n+7*j+p-1]=1
        A.append(row);b.append(1)
        for k,(i,pos) in enumerate(cl):
            row=[0]*N
            for p in range(1,8):
                if (p>>k)&1:row[2*n+7*j+p-1]=1
            row[2*i+(1 if pos else 0)]-=1
            A.append(row);b.append(0)
    return A,b

def dot(a,b):return sum(x*y for x,y in zip(a,b))

def repr_valid(n,clauses,w):
    z=[0]*(2*n+7*len(clauses))
    for i in range(n):z[2*i+int(w[i])]=1
    for j,cl in enumerate(clauses):
        bits=sum((int(int(w[i])==int(pos))<<k) for k,(i,pos) in enumerate(cl))
        if bits==0:return None
        z[2*n+7*j+bits-1]=1
    return z

def y_false(n,m):
    y=[0]*(2*n+7*m)
    for i in range(n):y[2*i]=y[2*i+1]=2
    for j in range(m):
        for p in [1,2,4,7]:y[2*n+7*j+p-1]=1
    return y

def tok(v):return int(v).to_bytes(66,'big')

def tag(t,ctx):return hashlib.sha256(b'R162-check'+ctx+tok(t)).digest()

def pad(t,ctx,L=64):return hashlib.shake_256(b'R162-mask'+ctx+tok(t)).digest(L)

def xor(a,b):return bytes(x^y for x,y in zip(a,b))

def generate(A,b,ctx,cap):
    rows=len(A);columns=len(A[0]);r=[RNG.randrange(Q) for _ in A]
    err=[RNG.randrange(-E,E+1) for _ in range(columns)]
    err0=RNG.randrange(-E0,E0+1)
    C=[(sum(A[i][j]*r[i] for i in range(rows))+err[j])%Q for j in range(columns)]
    t=(dot(b,r)+err0)%Q
    return C,tag(t,ctx),xor(cap,pad(t,ctx,len(cap))),t,err,err0

def open_valid(C,T,D,ctx,z,B):
    a=dot(z,C)%Q
    matched=[]
    for diff in range(-E0-E*B,E0+E*B+1):
        x=(a+diff)%Q
        if tag(x,ctx)==T:matched.append(x)
    ck(len(matched)==1,"legitimate single matching t")
    return xor(D,pad(matched[0],ctx,len(D)))

def attack_false(C,T,D,ctx,y,B):
    a=dot(y,C)%Q
    R=4*(E0+E*B)
    matched=[]
    for diff in range(-R,R+1):
        t=((a+diff)*INV4)%Q
        if tag(t,ctx)==T: matched.append(t)
    ck(len(matched)==1,"false attacker single matching t")
    return xor(D,pad(matched[0],ctx,len(D)))

true_cl=[[(0,True),(1,True),(1,True)]]
Atrue,btrue=compile_cnf(2,true_cl)
valid=[repr_valid(2,true_cl,[i,j]) for i in (0,1) for j in (0,1)]
valid=[v for v in valid if v is not None]
ck(len(valid)==3,"three distinct ORIGINAL witnesses")
for v in valid:
    for row,b in zip(Atrue,btrue):ck(dot(row,v)==b,"true exact witness")
false_cl=[[(0,True)]*3,[(0,False)]*3]
Afalse,bfalse=compile_cnf(1,false_cl)
y=y_false(1,2);B=3
ck(all(repr_valid(1,false_cl,[w]) is None for w in [0,1]),"FALSE 3CNF")
for row,b in zip(Afalse,bfalse):ck(dot(row,y)==4*b,"FALSE fractional scaled A y=4 b")
ck(sum(abs(x) for x in y)==4*B,"FALSE scaled norm bound")
TRIALS=192; legitimate=0; unauthorized=0
for iteration in range(TRIALS):
    cap=RNG.getrandbits(512).to_bytes(64,'big')
    ctx=b'orig:claim/utxo/branch/window/native-vk/v1'+iteration.to_bytes(4,'big')
    C,T,D,t,e,e0=generate(Atrue,btrue,ctx,cap)
    for z in valid:
        ck(open_valid(C,T,D,ctx,z,3)==cap,"every distinct witness same capability")
        legitimate+=1
    C,T,D,t,e,e0=generate(Afalse,bfalse,ctx,cap)
    residue=(4*t-dot(y,C))%Q
    if residue>Q//2:residue-=Q
    actual=4*e0-dot(y,e)
    ck(residue==actual,"false exact residual")
    ck(abs(actual)<=4*(E0+E*B),"false noise bound")
    ck(attack_false(C,T,D,ctx,y,B)==cap,"FALSE unauthorized capability recovery")
    unauthorized+=1
result={"run":RUN,"status":"rejected nonlinear hashed-phase release; no generic WKEM security advance", "assertions":CHECKS,"true_valid_witness_count":len(valid),"true_valid_openings":legitimate,"false_unauthorized_openings":unauthorized,"false_instance":"(x∨x∨x) ∧ (¬x∨¬x∨¬x)","q_bits":Q.bit_length(),"q_is_mersenne_prime_521":True,"false_scaled_search_candidates":2*4*(E0+E*B)+1,"true_search_candidates":2*(E0+E*B)+1,"LWE_assumption_claimed":False,"standard_QPT_LWE_challenge_simulator":False}
print(json.dumps(result,indent=2,sort_keys=True))
