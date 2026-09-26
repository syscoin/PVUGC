#!/usr/bin/env python3
import json, random
from itertools import product

SEED = 0x56A661
rng = random.Random(SEED)


def mm(A,B,q):
    return [[sum(A[i][k]*B[k][j] for k in range(len(B)))%q for j in range(len(B[0]))] for i in range(len(A))]

def ma(A,B,q):
    return [[(A[i][j]+B[i][j])%q for j in range(len(A[0]))] for i in range(len(A))]

def ms(A,B,q):
    return [[(A[i][j]-B[i][j])%q for j in range(len(A[0]))] for i in range(len(A))]

def sm(a,A,q):
    return [[(a*x)%q for x in row] for row in A]

def eye(n):
    return [[1 if i==j else 0 for j in range(n)] for i in range(n)]

def randmat(n,q):
    return [[rng.randrange(q) for _ in range(n)] for _ in range(n)]

def centered(x,q):
    x%=q
    return x-q if x>q//2 else x

def invmat(A,q):
    n=len(A)
    aug=[[(A[i][j]%q) for j in range(n)]+[1 if i==j else 0 for j in range(n)] for i in range(n)]
    for col in range(n):
        piv=next((r for r in range(col,n) if aug[r][col]%q),None)
        if piv is None: raise ValueError('singular')
        aug[col],aug[piv]=aug[piv],aug[col]
        iv=pow(aug[col][col],-1,q)
        aug[col]=[(x*iv)%q for x in aug[col]]
        for r in range(n):
            if r!=col and aug[r][col]%q:
                f=aug[r][col]%q
                aug[r]=[(aug[r][j]-f*aug[col][j])%q for j in range(2*n)]
    return [row[n:] for row in aug]

def rand_gl(n,q):
    while True:
        A=randmat(n,q)
        try:
            invmat(A,q); return A
        except ValueError: pass

def path_prod(trans,w,q):
    P=eye(len(trans[0][0]))
    for i,b in enumerate(w): P=mm(P,trans[i][b],q)
    return P

def suffix_products(trans,w,q):
    L=len(w); n=len(trans[0][0]); out=[None]*L; s=eye(n)
    for i in range(L-1,-1,-1):
        out[i]=s
        s=mm(trans[i][w[i]],s,q)
    return out

def path_eval(C, trans, w, q):
    suf=suffix_products(trans,w,q)
    n=len(C[0][0]); z=[[0]*n for _ in range(n)]
    for i,b in enumerate(w): z=ma(z,mm(C[i][b],suf[i],q),q)
    return z

def nearest_bit(v,delta,q):
    a=abs(centered(v,q)); b=abs(centered(v-delta,q))
    return 0 if a<=b else 1

# 1. General exact telescoping identity, arbitrary matrices, zero noise.
exact_tel=0
for _ in range(600):
    q=101; d=3; L=5
    trans=[(rand_gl(d,q),rand_gl(d,q)) for _ in range(L)]
    w=[rng.randrange(2) for _ in range(L)]
    T=path_prod(trans,w,q)
    R=[randmat(d,q) for _ in range(L)]
    S=randmat(d,q)
    RL=ma(mm(R[0],T,q),S,q)
    Rfull=R+[RL]
    C=[]
    for i in range(L):
        C.append((ms(Rfull[i+1],mm(Rfull[i],trans[i][0],q),q),
                  ms(Rfull[i+1],mm(Rfull[i],trans[i][1],q),q)))
    assert path_eval(C,trans,w,q)==S
    exact_tel+=1

# 2. General full-rank branch-difference attack in noiseless case.
fullrank_attacks=0
attempts=0
while fullrank_attacks<500 and attempts<10000:
    attempts+=1
    q=101; d=3; L=4
    trans=[]
    ok=True
    for i in range(L):
        A0,A1=rand_gl(d,q),rand_gl(d,q)
        try: invmat(ms(A0,A1,q),q)
        except ValueError: ok=False; break
        trans.append((A0,A1))
    if not ok: continue
    w=[rng.randrange(2) for _ in range(L)]
    T=path_prod(trans,w,q)
    R=[randmat(d,q) for _ in range(L)]
    S=randmat(d,q)
    RL=ma(mm(R[0],T,q),S,q); Rfull=R+[RL]
    C=[]
    for i in range(L):
        C.append((ms(Rfull[i+1],mm(Rfull[i],trans[i][0],q),q),
                  ms(Rfull[i+1],mm(Rfull[i],trans[i][1],q),q)))
    def recover_R(i):
        D=ms(C[i][0],C[i][1],q)
        Delta=ms(trans[i][0],trans[i][1],q)
        return sm(-1,mm(D,invmat(Delta,q),q),q)
    R0h=recover_R(0); Rmh=recover_R(L-1)
    RLh=ma(C[L-1][0],mm(Rmh,trans[L-1][0],q),q)
    Sh=ms(RLh,mm(R0h,T,q),q)
    assert Sh==S
    fullrank_attacks+=1

# 3. Signed-permutation/noisy candidate: A0=I, A1=-I, even errors.
q=65537; d=2; L=12; I=eye(d); NI=sm(-1,I,q)
trans=[(I,NI) for _ in range(L)]
delta_key=8192
valid_all=0; attack_ok=0; setups=180; max_honest_noise=0; max_attack_noise=0
for trial in range(setups):
    bit=rng.randrange(2)
    R=[randmat(d,q) for _ in range(L)]
    S=sm(bit*delta_key,I,q)
    RL=ma(R[0],S,q); Rfull=R+[RL]
    C=[]
    for i in range(L):
        pair=[]
        for b in range(2):
            e=[[2*rng.choice([-1,0,1]) for _ in range(d)] for _ in range(d)]
            base=ms(Rfull[i+1],mm(Rfull[i],trans[i][b],q),q)
            pair.append(ma(base,[[x%q for x in row] for row in e],q))
        C.append(tuple(pair))
    for w in product([0,1], repeat=L):
        if sum(w)%2: continue
        F=path_eval(C,trans,w,q)
        dec=nearest_bit(F[0][0],delta_key,q)
        assert dec==bit
        raw=centered(F[0][0]-(bit*delta_key),q)
        max_honest_noise=max(max_honest_noise,abs(raw))
        valid_all+=1
    inv2=pow(2,-1,q)
    def rec_R(i):
        D=ms(C[i][0],C[i][1],q)
        return sm((-inv2)%q,D,q)
    R0h=rec_R(0); Rmh=rec_R(L-1)
    RLh=ma(C[L-1][0],Rmh,q)
    Sh=ms(RLh,R0h,q)
    dec=nearest_bit(Sh[0][0],delta_key,q)
    assert dec==bit
    attack_raw=centered(Sh[0][0]-(bit*delta_key),q)
    max_attack_noise=max(max_attack_noise,abs(attack_raw))
    attack_ok+=1

honest_bound=2*L
attack_bound=6
assert max_honest_noise<=honest_bound
assert max_attack_noise<=attack_bound
assert honest_bound < delta_key//2 and attack_bound < delta_key//2

result={
  'seed':SEED,
  'general_exact_telescoping':exact_tel,
  'general_fullrank_noiseless_attacks':fullrank_attacks,
  'general_fullrank_sampling_attempts':attempts,
  'signed_permutation':{
    'q':q,'d':d,'L':L,'setups':setups,'delta_key':delta_key,
    'all_even_parity_witness_decodes':valid_all,
    'public_attack_recoveries':attack_ok,
    'max_observed_honest_entry_noise':max_honest_noise,
    'max_observed_attack_entry_noise':max_attack_noise,
    'proved_honest_entry_bound':honest_bound,
    'proved_attack_entry_bound':attack_bound,
  }
}
print(json.dumps(result,sort_keys=True,indent=2))
