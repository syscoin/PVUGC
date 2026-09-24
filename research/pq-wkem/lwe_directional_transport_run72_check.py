#!/usr/bin/env python3
import json, random, hashlib
from math import ceil, log2
from itertools import product

SEED = 720072001
rng = random.Random(SEED)

def dot(a,b,q):
    return sum((x*y) for x,y in zip(a,b)) % q

def mat_vec(A,x,q):
    return [dot(row,x,q) for row in A]

def mat_mul(A,B,q):
    # A m x n, B n x d
    m=len(A); n=len(A[0]); d=len(B[0])
    return [[sum(A[i][k]*B[k][j] for k in range(n))%q for j in range(d)] for i in range(m)]

def vec_add(a,b,q):
    return [(x+y)%q for x,y in zip(a,b)]

def vec_sub(a,b,q):
    return [(x-y)%q for x,y in zip(a,b)]

def centered(x,q):
    x%=q
    return x-q if x>q//2 else x

def circular_dist(a,b,q):
    return abs(centered(a-b,q))

def rank_mod(A,q):
    M=[row[:] for row in A]
    if not M:
        return 0
    m=len(M); n=len(M[0]); r=0
    for c in range(n):
        piv=None
        for i in range(r,m):
            if M[i][c]%q:
                piv=i; break
        if piv is None:
            continue
        M[r],M[piv]=M[piv],M[r]
        inv=pow(M[r][c]%q,-1,q)
        M[r]=[(v*inv)%q for v in M[r]]
        for i in range(m):
            if i!=r and M[i][c]%q:
                f=M[i][c]%q
                M[i]=[(M[i][j]-f*M[r][j])%q for j in range(n)]
        r+=1
        if r==m: break
    return r

def rref_solve(A,b,q):
    M=[[(x%q) for x in row]+[bb%q] for row,bb in zip(A,b)]
    if not M:
        return []
    m=len(M); n=len(A[0]); r=0; pivots=[]
    for c in range(n):
        piv=None
        for i in range(r,m):
            if M[i][c]%q:
                piv=i; break
        if piv is None: continue
        M[r],M[piv]=M[piv],M[r]
        inv=pow(M[r][c],-1,q)
        M[r]=[(x*inv)%q for x in M[r]]
        for i in range(m):
            if i!=r and M[i][c]%q:
                f=M[i][c]%q
                M[i]=[(M[i][j]-f*M[r][j])%q for j in range(n+1)]
        pivots.append(c); r+=1
        if r==m: break
    for i in range(r,m):
        if all(M[i][j]%q==0 for j in range(n)) and M[i][n]%q:
            return None
    x=[0]*n
    for i,c in enumerate(pivots):
        x[c]=M[i][n]%q
    return x

def nullspace_basis(A,q):
    if not A:
        return []
    M=[[(x%q) for x in row] for row in A]
    m=len(M); n=len(M[0]); r=0; pivots=[]
    for c in range(n):
        piv=None
        for i in range(r,m):
            if M[i][c]%q:
                piv=i; break
        if piv is None: continue
        M[r],M[piv]=M[piv],M[r]
        inv=pow(M[r][c],-1,q)
        M[r]=[(x*inv)%q for x in M[r]]
        for i in range(m):
            if i!=r and M[i][c]%q:
                f=M[i][c]%q
                M[i]=[(M[i][j]-f*M[r][j])%q for j in range(n)]
        pivots.append(c); r+=1
        if r==m: break
    free=[c for c in range(n) if c not in pivots]
    basis=[]
    for f in free:
        v=[0]*n; v[f]=1
        for i,c in enumerate(pivots):
            v[c]=(-M[i][f])%q
        basis.append(v)
    return basis

def rand_full_row_rank(rows, cols, q):
    while True:
        A=[[rng.randrange(q) for _ in range(cols)] for _ in range(rows)]
        if rank_mod(A,q)==rows:
            return A

def secret_bits(s,q):
    ell=ceil(log2(q))
    bits=[]
    for x in s:
        bits.extend([(x>>k)&1 for k in range(ell)])
    return bits, ell

def bits_to_secret(bits,n,q,ell):
    out=[]
    for j in range(n):
        x=sum((bits[j*ell+k]&1)<<k for k in range(ell))
        # only valid encodings emitted by setup; wrong-decryption values can exceed q-1
        out.append(x % q)
    return out

def decode_bit(residue,q,Delta):
    # nearest circular codeword 0 or Delta
    d0=circular_dist(residue,0,q)
    d1=circular_dist(residue,Delta,q)
    return 0 if d0<=d1 else 1

def make_token(parents, child, q=257, noise_bound=2):
    n=len(parents[0])
    bits,ell=secret_bits(child,q)
    Delta=q//2
    rows=[]
    for bit in bits:
        mats=[]
        total=0
        for s in parents:
            a=[rng.randrange(q) for _ in range(n)]
            mats.append(a)
            total=(total+dot(a,s,q))%q
        e=rng.randint(-noise_bound,noise_bound)
        b=(total+Delta*bit+e)%q
        rows.append({"a":mats,"b":b,"e":e,"bit":bit})
    return {"q":q,"n":n,"ell":ell,"Delta":Delta,"rows":rows}

def decrypt_token(tok, parents):
    q=tok["q"]; Delta=tok["Delta"]; bits=[]
    for row in tok["rows"]:
        res=row["b"]
        for a,s in zip(row["a"],parents):
            res=(res-dot(a,s,q))%q
        bits.append(decode_bit(res,q,Delta))
    return bits_to_secret(bits,tok["n"],q,tok["ell"])

def reverse_residual(tok, child, known_parents, missing_index):
    q=tok["q"]; Delta=tok["Delta"]
    child_bits,_=secret_bits(child,q)
    A=[]; y=[]; errs=[]
    for idx,row in enumerate(tok["rows"]):
        val=(row["b"]-Delta*child_bits[idx])%q
        for j,s in known_parents.items():
            val=(val-dot(row["a"][j],s,q))%q
        A.append(row["a"][missing_index][:])
        y.append(val)
        errs.append(row["e"]%q)
    return A,y,errs

def token_expected_lwe(tok, parent, child, missing_index=0, known_parents=None):
    if known_parents is None: known_parents={}
    A,y,e=reverse_residual(tok, child, known_parents, missing_index)
    q=tok["q"]
    rhs=[(dot(a,parent,q)+ee)%q for a,ee in zip(A,e)]
    return y==rhs


def test_unrounded_collapse(trials=500):
    q=257; n=5; d=3; m=5
    solved=0; identities=0
    for _ in range(trials):
        while True:
            A=[[rng.randrange(q) for _ in range(n)] for __ in range(m)]
            B=[[rng.randrange(q) for _ in range(d)] for __ in range(n)]
            AB=mat_mul(A,B,q)
            if rank_mod(AB,q)==d:
                break
        x=[rng.randrange(q) for _ in range(d)]
        z=[rng.randint(-3,3)%q for _ in range(n)]
        T=vec_add(mat_vec(B,x,q),z,q)
        child=mat_vec(A,z,q)
        y=vec_sub(mat_vec(A,T,q),child,q)
        if y==mat_vec(AB,x,q):
            identities+=1
        xhat=rref_solve(AB,y,q)
        if xhat==x:
            solved+=1
    return {"trials":trials,"exact_linear_identity":identities,"public_parent_recovery":solved}

def test_checkpoint_projection(trials=600):
    # Validate exact identity from Run-72 checkpoint:
    # A T - Enc(Round(Az)) = A B x + delta.
    q=257; n=4; d=3; m=5; Delta=q//2
    ok=0; max_delta=0
    for _ in range(trials):
        A=[[rng.randrange(q) for _ in range(n)] for _ in range(m)]
        B=[[rng.randrange(q) for _ in range(d)] for _ in range(n)]
        x=[rng.randrange(q) for _ in range(d)]
        z=[rng.randint(-3,3)%q for _ in range(n)]
        Bx=mat_vec(B,x,q)
        T=vec_add(Bx,z,q)
        Az=mat_vec(A,z,q)
        child=[decode_bit(v,q,Delta) for v in Az]
        enc=[Delta*b for b in child]
        delta=[(Az[i]-enc[i])%q for i in range(m)]
        max_delta=max(max_delta,max(abs(centered(v,q)) for v in delta))
        lhs=vec_sub(mat_vec(A,T,q),enc,q)
        AB=mat_mul(A,B,q)
        rhs=vec_add(mat_vec(AB,x,q),delta,q)
        if lhs==rhs: ok+=1
    return {"trials":trials,"identity_ok":ok,"max_centered_rounding_residual":max_delta}

def test_directional_single(trials=500):
    q=257; n=4
    fwd=0; rev=0; exact_embed=0
    for _ in range(trials):
        parent=[rng.randrange(q) for _ in range(n)]
        child=[rng.randrange(q) for _ in range(n)]
        tok=make_token([parent],child,q,2)
        if decrypt_token(tok,[parent])==child:
            fwd+=1
        if token_expected_lwe(tok,parent,child,0,{}):
            rev+=1
        # exact reduction embedding: b = y + message
        bits,ell=secret_bits(child,q); Delta=q//2
        A=[]; y=[]; rows=[]
        for bit in bits:
            a=[rng.randrange(q) for _ in range(n)]
            e=rng.randint(-2,2)
            yy=(dot(a,parent,q)+e)%q
            bb=(yy+Delta*bit)%q
            A.append(a); y.append(yy)
            rows.append((a,bb,e,bit))
        recovered=[(bb-Delta*bit)%q for a,bb,e,bit in rows]
        if recovered==y:
            exact_embed+=1
    return {"trials":trials,"forward_exact":fwd,"reverse_is_exact_search_lwe":rev,"challenge_embedding_exact":exact_embed}

def test_and_tokens(trials=500):
    q=257; n=4
    fwd=0; missing_identity=0
    for _ in range(trials):
        p0=[rng.randrange(q) for _ in range(n)]
        p1=[rng.randrange(q) for _ in range(n)]
        child=[rng.randrange(q) for _ in range(n)]
        tok=make_token([p0,p1],child,q,2)
        if decrypt_token(tok,[p0,p1])==child:
            fwd+=1
        if token_expected_lwe(tok,p1,child,1,{0:p0}):
            missing_identity+=1
    return {"trials":trials,"two_parent_forward_exact":fwd,"known_other_parent_reverse_is_lwe":missing_identity}

def test_chain(trials=300, length=6):
    q=257; n=4
    good=0
    for _ in range(trials):
        caps=[[rng.randrange(q) for _ in range(n)] for __ in range(length+1)]
        toks=[make_token([caps[i]],caps[i+1],q,2) for i in range(length)]
        cur=caps[0]
        for tok in toks:
            cur=decrypt_token(tok,[cur])
        if cur==caps[-1]: good+=1
    return {"trials":trials,"length":length,"end_to_end_exact":good}

def test_unsat_public_label_splice(trials=400):
    # False source relation: z AND (NOT z), represented as two local unary truths then AND.
    # Publishing both input labels lets the attacker select z=1 for the first clause
    # and z=0 for the second, then combine clause-true labels.
    q=257; n=4
    formula_witnesses=sum(1 for z in [0,1] if z==1 and (1-z)==1)
    recovered=0
    for _ in range(trials):
        z0=[rng.randrange(q) for _ in range(n)]
        z1=[rng.randrange(q) for _ in range(n)]
        c1=[rng.randrange(q) for _ in range(n)]
        c2=[rng.randrange(q) for _ in range(n)]
        root=[rng.randrange(q) for _ in range(n)]
        t1=make_token([z1],c1,q,2)  # clause z is true only at 1
        t2=make_token([z0],c2,q,2)  # clause !z true only at 0
        tand=make_token([c1,c2],root,q,2)
        # complete-public-view / bad source-gate grants both z labels
        a1=decrypt_token(t1,[z1])
        a2=decrypt_token(t2,[z0])
        out=decrypt_token(tand,[a1,a2])
        if a1==c1 and a2==c2 and out==root:
            recovered+=1
    return {"trials":trials,"source_witnesses":formula_witnesses,"false_formula_public_both_labels_root_recovery":recovered}

def test_affine_source_gate(trials=350):
    # Exact finite-field control of theorem:
    # if an affine-LWE parent term M s is constant over public affine fiber Hs=u,
    # then M annihilates ker H and the constant is publicly computable from H,u,M.
    q=17; d=5; r=3; outdim=3
    constant_cases=0; public_recoveries=0; sweep_controls=0
    for _ in range(trials):
        H=rand_full_row_rank(r,d,q)
        s0=[rng.randrange(q) for _ in range(d)]
        u=mat_vec(H,s0,q)
        ker=nullspace_basis(H,q)
        # make M = R H so it annihilates ker(H)
        R=[[rng.randrange(q) for _ in range(r)] for __ in range(outdim)]
        M=mat_mul(R,H,q)
        vals=[]
        for __ in range(20):
            coeff=[rng.randrange(q) for _ in ker]
            s=s0[:]
            for c,v in zip(coeff,ker):
                s=[(si+c*vi)%q for si,vi in zip(s,v)]
            vals.append(tuple(mat_vec(M,s,q)))
        if len(set(vals))==1:
            constant_cases+=1
        spart=rref_solve(H,u,q)
        if spart is not None and mat_vec(M,spart,q)==list(vals[0]):
            public_recoveries+=1

        # choose a row vector a that does not annihilate some kernel direction;
        # along lambda*v one output scalar sweeps all F_q exactly.
        if ker:
            v=ker[0]
            a=None
            for __ in range(100):
                cand=[rng.randrange(q) for _ in range(d)]
                av=dot(cand,v,q)
                if av:
                    a=cand; break
            if a is not None:
                sweep={dot(a,[(s0[i]+lam*v[i])%q for i in range(d)],q) for lam in range(q)}
                if len(sweep)==q:
                    sweep_controls+=1
    return {"trials":trials,"constant_affine_fiber_cases":constant_cases,
            "public_particular_solution_recovers_constant":public_recoveries,
            "nonannihilating_direction_full_field_sweeps":sweep_controls}

def resource_estimate(n,q,kparents=2):
    ell=ceil(log2(q))
    M=n*ell
    qbits=ceil(log2(q))
    q_elements=M*(kparents*n+1)
    bits=q_elements*qbits
    return {"n":n,"q":q,"q_bits":qbits,"secret_q_elements":n,
            "child_bits":M,"samples_per_edge":M,"parents":kparents,
            "token_q_elements":q_elements,"approx_token_bits_unpacked":bits}

def main():
    results={
        "seed":SEED,
        "scope":"finite algebra/correctness controls only; no security claim from tests",
        "unrounded_public_collapse":test_unrounded_collapse(),
        "checkpoint_projection":test_checkpoint_projection(),
        "single_parent_directional_lwe":test_directional_single(),
        "two_parent_and_transport":test_and_tokens(),
        "directed_chain":test_chain(),
        "public_input_label_false_splice":test_unsat_public_label_splice(),
        "affine_source_gate_barrier":test_affine_source_gate(),
        "resource_examples":[resource_estimate(256,12289,1),resource_estimate(256,12289,2)]
    }
    raw=json.dumps(results,sort_keys=True,indent=2)+"\n"
    print(raw,end="")
if __name__=="__main__":
    main()
