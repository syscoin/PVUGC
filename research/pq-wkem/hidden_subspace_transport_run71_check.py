#!/usr/bin/env python3
import json, random, math, hashlib
from fractions import Fraction

SEED = 0x71C0FFEE
rng = random.Random(SEED)

# ---------- finite-field linear algebra ----------
def inv_mod(a,p):
    return pow(a%p, p-2, p)

def eye(n):
    return [[1 if i==j else 0 for j in range(n)] for i in range(n)]

def matmul(A,B,p=None):
    m=len(A); k=len(A[0]); assert len(B)==k; n=len(B[0])
    C=[[0]*n for _ in range(m)]
    if p is None:
        for i in range(m):
            for t in range(k):
                a=A[i][t]
                if a:
                    for j in range(n): C[i][j]+=a*B[t][j]
    else:
        for i in range(m):
            for t in range(k):
                a=A[i][t]%p
                if a:
                    for j in range(n): C[i][j]=(C[i][j]+a*B[t][j])%p
    return C

def transpose(A):
    return [list(row) for row in zip(*A)]

def vecmat(v,A,p):
    return matmul([v],A,p)[0]

def matvec(A,v,p):
    return [x[0] for x in matmul(A, [[z] for z in v], p)]

def gauss_solve(A,b,p):
    # Solve A x=b over F_p; returns one solution with free vars = 0 or None.
    m=len(A); n=len(A[0])
    M=[[(A[i][j]%p) for j in range(n)]+[b[i]%p] for i in range(m)]
    piv=[]; r=0
    for c in range(n):
        pr=next((i for i in range(r,m) if M[i][c]%p), None)
        if pr is None: continue
        M[r],M[pr]=M[pr],M[r]
        z=inv_mod(M[r][c],p)
        M[r]=[(x*z)%p for x in M[r]]
        for i in range(m):
            if i!=r and M[i][c]%p:
                f=M[i][c]%p
                M[i]=[(M[i][j]-f*M[r][j])%p for j in range(n+1)]
        piv.append(c); r+=1
        if r==m: break
    for i in range(r,m):
        if all(M[i][j]%p==0 for j in range(n)) and M[i][n]%p:
            return None
    x=[0]*n
    for i,c in enumerate(piv): x[c]=M[i][n]%p
    return x

def solve_row_times_matrix(y,T,p):
    # x T = y => T^T x^T = y^T.
    return gauss_solve(transpose(T), y, p)

def mat_inv(A,p):
    n=len(A); assert len(A[0])==n
    M=[[(A[i][j]%p) for j in range(n)] + eye(n)[i] for i in range(n)]
    r=0
    for c in range(n):
        pr=next((i for i in range(r,n) if M[i][c]%p), None)
        if pr is None: return None
        M[r],M[pr]=M[pr],M[r]
        z=inv_mod(M[r][c],p)
        M[r]=[(x*z)%p for x in M[r]]
        for i in range(n):
            if i!=r and M[i][c]%p:
                f=M[i][c]%p
                M[i]=[(M[i][j]-f*M[r][j])%p for j in range(2*n)]
        r+=1
    return [row[n:] for row in M]

def rand_inv(n,p):
    while True:
        A=[[rng.randrange(p) for _ in range(n)] for __ in range(n)]
        Ai=mat_inv(A,p)
        if Ai is not None: return A,Ai

def first_cols(A,r):
    return [row[:r] for row in A]

def first_rows(A,r):
    return [row[:] for row in A[:r]]

def dot(a,b,p):
    return sum((x*y)%p for x,y in zip(a,b))%p

def row_scale(v,a,p): return [(a*x)%p for x in v]

class Node:
    def __init__(self,d,r,p):
        S,Sinv=rand_inv(d,p)
        self.C=first_cols(Sinv,r)  # d x r
        self.R=first_rows(S,r)     # r x d, R*C=I
        H,Hinv=rand_inv(r,p)
        self.H=H; self.Hinv=Hinv

def token(u,v,p):
    # C_u H_u^{-1} H_v R_v
    return matmul(matmul(matmul(u.C,u.Hinv,p),v.H,p),v.R,p)

def start_row(node,z,p):
    return vecmat(vecmat(z,node.H,p),node.R,p)

def endpoint_col(node,z,K,p):
    tmp=matvec(node.Hinv,z,p)
    tmp=matvec(node.C,tmp,p)
    return [(K*x)%p for x in tmp]

def follow_forward(y,T,p): return vecmat(y,T,p)
def follow_reverse(y,T,p):
    x=solve_row_times_matrix(y,T,p)
    if x is None: raise AssertionError('reverse solve failed')
    return x

# ---------- floating-point orthogonal/noisy control ----------
def f_eye(n): return [[1.0 if i==j else 0.0 for j in range(n)] for i in range(n)]
def f_trans(A): return [list(row) for row in zip(*A)]
def f_matmul(A,B):
    m=len(A); k=len(A[0]); n=len(B[0]); C=[[0.0]*n for _ in range(m)]
    for i in range(m):
        for t in range(k):
            a=A[i][t]
            for j in range(n): C[i][j]+=a*B[t][j]
    return C

def f_vecmat(v,A): return f_matmul([v],A)[0]
def f_matvec(A,v): return [x[0] for x in f_matmul(A,[[z] for z in v])]
def f_dot(a,b): return sum(x*y for x,y in zip(a,b))
def f_add(A,B,scale=1.0): return [[A[i][j]+scale*B[i][j] for j in range(len(A[0]))] for i in range(len(A))]

def random_orthogonal(n):
    Q=f_eye(n)
    # Product of random Givens rotations.
    for _ in range(4*n):
        i,j=rng.sample(range(n),2)
        theta=rng.uniform(-math.pi,math.pi)
        c=math.cos(theta); s=math.sin(theta)
        G=f_eye(n); G[i][i]=c; G[j][j]=c; G[i][j]=-s; G[j][i]=s
        Q=f_matmul(Q,G)
    return Q

def block_cols(Q,r,block):
    # Q columns block*r:(block+1)*r
    lo=block*r; hi=lo+r
    return [[row[j] for j in range(lo,hi)] for row in Q]

def partial_iso(U,V):
    return f_matmul(U,f_trans(V))

def noisy_token(U,V,eps):
    A=partial_iso(U,V)
    O=random_orthogonal(len(A))
    return f_add(A,O,eps)

# ---------- experiments ----------
def finite_field_trials():
    ps=[101,103,107]
    configs=[(4,1),(5,2),(6,3)]
    false_trials=0; false_recover=0; false_no_direct=0; reverse_steps=0; reverse_eq=0
    true_trials=0; true_recover=0
    for p in ps:
      for d,r in configs:
        if r>d: continue
        z=[1]+[0]*(r-1)
        for _ in range(50):
            nodes={name:Node(d,r,p) for name in ['s','A','C','B','t','X','Y']}
            K=rng.randrange(1,p)
            # false directed graph: s->A <- C -> B -> t. No directed s->t path.
            T_sA=token(nodes['s'],nodes['A'],p)
            T_CA=token(nodes['C'],nodes['A'],p)
            T_CB=token(nodes['C'],nodes['B'],p)
            T_Bt=token(nodes['B'],nodes['t'],p)
            y=start_row(nodes['s'],z,p)
            y=follow_forward(y,T_sA,p)
            y2=follow_reverse(y,T_CA,p); reverse_steps+=1
            # validate the public reverse lift has the right action on the next source channel
            ideal_C=start_row(nodes['C'],z,p)
            # It need not equal ideal_C outside the hidden source channel, but next outgoing action must match.
            lhs=follow_forward(y2,T_CB,p)
            rhs=follow_forward(ideal_C,T_CB,p)
            if lhs==rhs: reverse_eq+=1
            y=lhs
            y=follow_forward(y,T_Bt,p)
            b=endpoint_col(nodes['t'],z,K,p)
            got=dot(y,b,p)
            false_trials+=1; false_no_direct+=1
            false_recover += (got==K)

            # true forward path control: s->X->Y->t
            TsX=token(nodes['s'],nodes['X'],p)
            TXY=token(nodes['X'],nodes['Y'],p)
            TYt=token(nodes['Y'],nodes['t'],p)
            y=start_row(nodes['s'],z,p)
            for T in [TsX,TXY,TYt]: y=follow_forward(y,T,p)
            got=dot(y,b,p)
            true_trials+=1; true_recover += (got==K)
    assert false_recover==false_trials
    assert true_recover==true_trials
    assert reverse_eq==reverse_steps
    return {
        'primes':ps,'configs_d_r':configs,
        'false_instances':false_trials,'false_zero_directed_paths':false_no_direct,
        'false_public_reverse_recoveries':false_recover,
        'reverse_steps_checked':reverse_steps,'reverse_next_channel_equalities':reverse_eq,
        'true_forward_controls':true_trials,'true_forward_recoveries':true_recover,
    }

def noisy_trials():
    # orthogonal block partial-isometry special case; false walk length 4, true path length 4
    d=8; r=2; states_per_layer=d//r; z=[1.0]+[0.0]*(r-1)
    eps_list=[0.001,0.005,0.01,0.02,0.05]
    per_eps=[]
    for eps in eps_list:
        n=250; false_ok=true_ok=0; max_false_err=max_true_err=0.0; bound=(1+eps)**4-1
        for _ in range(n):
            Q0=random_orthogonal(d); Q1=random_orthogonal(d); Q2=random_orthogonal(d); Q3=random_orthogonal(d); Q4=random_orthogonal(d)
            # Independent node subspaces via separate orthogonal frames; use block 0 for each named node.
            Us=block_cols(Q0,r,0); UA=block_cols(Q1,r,0); UC=block_cols(Q0,r,1); UB=block_cols(Q1,r,1); Ut=block_cols(Q2,r,0)
            UX=block_cols(Q1,r,2); UY=block_cols(Q2,r,1); UZ=block_cols(Q3,r,0)
            # start row and endpoint col for a fresh random sign key K in {-1,+1}
            K = 1.0 if rng.randrange(2) else -1.0
            ell=f_vecmat(z,f_trans(Us))
            b=[K*x for x in f_matvec(Ut,z)]
            # false walk s->A <-C ->B ->t (4 edges), reverse CA by transpose
            AsA=noisy_token(Us,UA,eps); ACA=noisy_token(UC,UA,eps); ACB=noisy_token(UC,UB,eps); ABt=noisy_token(UB,Ut,eps)
            y=f_vecmat(ell,AsA); y=f_vecmat(y,f_trans(ACA)); y=f_vecmat(y,ACB); y=f_vecmat(y,ABt)
            gv=f_dot(y,b); err=abs(gv-K); max_false_err=max(max_false_err,err); false_ok += ((1.0 if gv>=0 else -1.0)==K)
            # true length-4 path s->X->Y->Z->t
            TsX=noisy_token(Us,UX,eps); TXY=noisy_token(UX,UY,eps); TYZ=noisy_token(UY,UZ,eps); TZt=noisy_token(UZ,Ut,eps)
            y=ell[:]
            for T in [TsX,TXY,TYZ,TZt]: y=f_vecmat(y,T)
            gv=f_dot(y,b); err=abs(gv-K); max_true_err=max(max_true_err,err); true_ok += ((1.0 if gv>=0 else -1.0)==K)
        # theorem gives scalar error <= product operator error bound (unit anchors)
        # Numerical samples should satisfy with tiny floating tolerance because each E=eps*orthogonal.
        assert max_false_err <= bound + 1e-8
        assert max_true_err <= bound + 1e-8
        per_eps.append({
            'epsilon':eps,'trials':n,'deterministic_product_bound':bound,
            'false_alternating_sign_recoveries':false_ok,
            'true_forward_sign_recoveries':true_ok,
            'max_false_abs_error':max_false_err,'max_true_abs_error':max_true_err,
        })
    return {
        'dimension':d,'block_rank':r,'walk_length':4,'decode_rule':'nearest sign in {-1,+1}',
        'per_epsilon':per_eps,
        'sign_correctness_guaranteed_when_bound_lt_one': True,
        'epsilon_threshold_for_L4_bound_lt_one': 2.0**0.25-1,
    }

def exact_public_reverse_lemma_trials():
    # Directly validate: if y=x*T is public, solving x'*T=y yields a row x' whose action
    # on every same-source token agrees with x, even though x' itself may differ from x.
    ps=[101,103]; total=eq=diff_rows=0
    for p in ps:
      for d,r in [(5,2),(7,3)]:
        z=[rng.randrange(p) for _ in range(r)]
        if all(v==0 for v in z): z[0]=1
        for _ in range(100):
            u=Node(d,r,p); v=Node(d,r,p); w=Node(d,r,p)
            Tuv=token(u,v,p); Tuw=token(u,w,p)
            x=start_row(u,z,p); y=follow_forward(x,Tuv,p)
            xp=follow_reverse(y,Tuv,p)
            total+=1
            if xp!=x: diff_rows+=1
            if follow_forward(xp,Tuw,p)==follow_forward(x,Tuw,p): eq+=1
    assert eq==total
    return {'cases':total,'same_source_action_equalities':eq,'reverse_solution_differed_from_hidden_row':diff_rows}

def main():
    out={
        'run':'71','seed':SEED,
        'claim_scope':{
            'proved':'Exact node-potential rank-r linear transports collapse directed consistency to undirected public reachability via forward multiplication and public linear-system reverse lifts. Orthogonal partial-isometry transports with bounded additive operator-norm noise give an alternating false walk the same (1+eps)^L-1 perturbation bound as an honest length-L path.',
            'not_proved':'No impossibility for all noncommutative encodings, no LWE/SIS break, no arbitrary-QPT key-recovery-to-witness theorem, and no claim for noise large enough to destroy the transparent transport channel.'
        },
        'finite_field_node_potential': finite_field_trials(),
        'public_reverse_lemma': exact_public_reverse_lemma_trials(),
        'bounded_noisy_orthogonal_special_case': noisy_trials(),
    }
    print(json.dumps(out,sort_keys=True,indent=2))

if __name__=='__main__': main()
