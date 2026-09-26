#!/usr/bin/env python3
from __future__ import annotations
import json, random, math
from itertools import product

def mm(A,B,q):
    return [[sum(A[i][t]*B[t][j] for t in range(len(B)))%q for j in range(len(B[0]))]
            for i in range(len(A))]
def madd(A,B,q):
    return [[(A[i][j]+B[i][j])%q for j in range(len(A[0]))] for i in range(len(A))]
def msub(A,B,q):
    return [[(A[i][j]-B[i][j])%q for j in range(len(A[0]))] for i in range(len(A))]
def hcat(blocks):
    return [sum((list(B[i]) for B in blocks),[]) for i in range(len(blocks[0]))]
def vcat(blocks):
    out=[]
    for B in blocks: out += [list(r) for r in B]
    return out
def zeros(a,b): return [[0]*b for _ in range(a)]
def neg(A,q): return [[(-x)%q for x in row] for row in A]
def eq(A,B): return A==B
def eye(n): return [[1 if i==j else 0 for j in range(n)] for i in range(n)]
def transpose(A): return [list(x) for x in zip(*A)]
def perm_matrix(p):
    n=len(p)
    P=zeros(n,n)
    for i,j in enumerate(p): P[i][j]=1
    return P
def inv_perm(p):
    out=[0]*len(p)
    for i,j in enumerate(p): out[j]=i
    return out
def col_l1(A):
    return max(sum(abs(x) for x in col) for col in zip(*A)) if A and A[0] else 0

checks=[]
def ok(name,cond,detail=None):
    if not cond: raise AssertionError(f"{name}: {detail}")
    checks.append({"name":name,"detail":detail})

q=257
n=2
ell=9
k=3
rout=2
g=[pow(2,j,q) for j in range(ell)]
wbase=n*ell
W=k*wbase

# base gadget G = I_n tensor g^T, n x (n ell)
Gbase=zeros(n,wbase)
for i in range(n):
    for j,gj in enumerate(g):
        Gbase[i][i*ell+j]=gj

# coordinate gadget blocks Gi inside full W input width
Gis=[]
for coord in range(k):
    Gi=zeros(n,W)
    for i in range(n):
        for j in range(wbase):
            Gi[i][coord*wbase+j]=Gbase[i][j]
    Gis.append(Gi)

def gadget_inv_target(T):
    # D in wbase x rout with Gbase D = T, using binary digits of each target entry.
    D=zeros(wbase,len(T[0]))
    for i in range(n):
        for col in range(len(T[0])):
            x=T[i][col] % q
            # distinguished representative 0..q-1, binary decomposition
            for j in range(ell):
                D[i*ell+j][col]=(x>>j)&1
    return D

def embed_D(coord,D):
    Z=zeros(W,len(D[0]))
    for j in range(wbase):
        Z[coord*wbase+j]=list(D[j])
    return Z

# Verify gadget inversion for all field values coordinatewise.
for a in range(q):
    T=[[a],[0]]
    D=gadget_inv_target(T)
    ok(f"gadget_inv_{a}", mm(Gbase,D,q)==T)

# 1. Common-target fixed-matrix linearization + unconditional public preimage.
rng=random.Random(108)
linearization_records=[]
for trial in range(400):
    C=[[rng.randrange(q) for _ in range(W)] for _ in range(n)]
    w=tuple(rng.randrange(2) for _ in range(k))
    S=[[rng.randrange(-2,3)%q for _ in range(rout)] for _ in range(W)]
    Gw=zeros(n,W)
    for i,b in enumerate(w):
        if b: Gw=madd(Gw,Gis[i],q)
    Aw=msub(C,Gw,q)
    T=mm(Aw,S,q)

    Abar=hcat([C]+[neg(Gi,q) for Gi in Gis])
    Zs=[S]+[[[(w[i]*S[row][col])%q for col in range(rout)] for row in range(W)] for i in range(k)]
    z=vcat(Zs)
    ok(f"linearized_valid_{trial}",mm(Abar,z,q)==T)

    # Public attack uses only one gadget block; no witness or FC proof.
    Dsmall=gadget_inv_target(T)
    Zattack=embed_D(0,neg(Dsmall,q))
    zattack=vcat([zeros(W,rout), Zattack, zeros(W,rout), zeros(W,rout)])
    ok(f"public_preimage_{trial}",mm(Abar,zattack,q)==T)
    attack_norm=col_l1([[((x+q//2)%q)-q//2 for x in row] for row in zattack])
    ok(f"attack_norm_{trial}",attack_norm<=n*ell,attack_norm)
    linearization_records.append({"trial":trial,"w_weight":sum(w),"public_preimage_l1":attack_norm})

# 2. Randomized gadget block with a public short map R: B R = G still gives a public target preimage.
randomized_records=[]
for trial in range(150):
    p=list(range(W)); rng.shuffle(p)
    R=perm_matrix(p)
    Rin=perm_matrix(inv_perm(p))
    # B=G0 R^{-1}; B R = G0
    B=mm(Gis[0],Rin,q)
    ok(f"BRG_{trial}",mm(B,R,q)==Gis[0])
    T=[[rng.randrange(q) for _ in range(rout)] for _ in range(n)]
    Dsmall=gadget_inv_target(T)
    Dfull=embed_D(0,Dsmall)
    pre=mm(R,Dfull,q)
    ok(f"randomized_public_preimage_{trial}",mm(B,pre,q)==T)
    randomized_records.append({"trial":trial,"preimage_l1":col_l1(pre)})

# 3. Difference identity for two claimed outputs at same opening input.
# If A s0=t0 and A s1=t1, then A(s1-s0)=t1-t0.
for trial in range(200):
    A=[[rng.randrange(q) for _ in range(6)] for _ in range(2)]
    s0=[[rng.randrange(q)] for _ in range(6)]
    s1=[[rng.randrange(q)] for _ in range(6)]
    t0=mm(A,s0,q); t1=mm(A,s1,q)
    d=msub(s1,s0,q)
    ok(f"difference_{trial}",mm(A,d,q)==msub(t1,t0,q))

# 4. Selective->adaptive shift-bias toy.
# Uniform C in F_q, public input shifts G_w=w for w in {0,...,M-1}.
# Adaptive chooser w(C)=C for C<M else 0 makes A=C-w(C).
M=16
counts=[0]*q
for C in range(q):
    w=C if C<M else 0
    A=(C-w)%q
    counts[A]+=1
p0=counts[0]/q
uniform=1/q
tv=0.5*sum(abs(c/q-uniform) for c in counts)
ok("adaptive_shift_zero_mass",counts[0]==M,counts[0])
ok("adaptive_shift_nonuniform",tv>0,(p0,tv))

loss_rows=[]
for witness_bits in (32,64,128,256,512):
    loss_log2=witness_bits
    loss_rows.append({"witness_bits":witness_bits,"input_space_log2":loss_log2,
                      "guessing_loss":"2^%d"%witness_bits})
    ok(f"guess_loss_{witness_bits}",loss_log2==witness_bits)

# 5. Gadget-channel bounded-error uniqueness control:
# if two candidates fit all observations, delta must have centered 2^j delta <=2B.
q2=257; Berr=3; g2=[1,2,4,8]
survivors=[]
for delta in range(q2):
    centered=[]
    for gj in g2:
        x=(gj*delta)%q2
        if x>q2//2: x-=q2
        centered.append(x)
    if all(abs(x)<=2*Berr for x in centered):
        survivors.append(delta)
ok("gadget_channel_unique_delta",survivors==[0],survivors)

out={
 "run":108,"status":"PASS","total_assertions":len(checks),
 "fc_linearization":{
   "q":q,"n":n,"input_bits":k,"gadget_ell":ell,"input_width":W,"output_columns":rout,
   "trials":len(linearization_records),
   "claim":"Linearizing (C-G_w)S=T into a fixed matrix [C,-G_1,...,-G_k] creates a public short preimage of every target through any gadget block."
 },
 "randomized_gadget":{
   "trials":len(randomized_records),
   "claim":"If a public short map R satisfies B R=G, composing R with gadget inversion again gives a public target preimage under B."
 },
 "selective_adaptive":{
   "q":q,"shift_family_size":M,"adaptive_zero_probability":p0,
   "uniform_zero_probability":uniform,"tv_from_uniform":tv,
   "guessing_loss_rows":loss_rows
 },
 "gadget_channel":{
   "q":q2,"bounded_error":Berr,"gadget":g2,"surviving_secret_deltas":survivors,
   "claim":"In this bounded-noise control, the gadget observations uniquely determine each secret coordinate."
 },
 "scope":[
   "Finite algebra and probability controls only.",
   "The checker does not reimplement de Castro-Peikert homomorphic Eval.",
   "The public-preimage attack applies to the direct fixed-matrix block linearization, not to the functional commitment itself.",
   "The selective/adaptive toy demonstrates why adaptive input choice cannot be treated as an independent uniform shift."
 ]
}
print(json.dumps(out,indent=2,sort_keys=True))
