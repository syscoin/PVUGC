#!/usr/bin/env python3
import json, random, math

SEED = 9100910026
rng = random.Random(SEED)

def compile_3cnf(nvars, clauses):
    npairs=nvars+2*len(clauses); width=1+2*npairs
    def pair(p): return 1+2*p, 2+2*p
    rows=[]
    for p in range(npairs):
        r=[0]*width; a,b=pair(p); r[a]=1; r[b]=1; r[0]=-1; rows.append(r)
    for j,cl in enumerate(clauses):
        r=[0]*width
        for lit in cl:
            a,b=pair(abs(lit)-1); r[a if lit>0 else b]+=1
        s1,_=pair(nvars+2*j); s2,_=pair(nvars+2*j+1)
        r[s1]+=1; r[s2]+=2; r[0]-=4; rows.append(r)
    return rows,npairs

def padded_false(dummies):
    n=1+dummies; clauses=[(1,1,1),(-1,-1,-1)]
    H,npairs=compile_3cnf(n,clauses)
    x=[0]*(1+2*npairs); x[0]=1
    def sp(p,a,b): x[1+2*p]=a; x[2+2*p]=b
    sp(0,0,1)
    for i in range(1,n): sp(i,0,1)
    sp(n,0,1); sp(n+1,2,-1); sp(n+2,1,0); sp(n+3,0,1)
    assert mat_int(H,x)==[0]*len(H)
    return H,x,npairs

def mat_int(A,x): return [sum(a*b for a,b in zip(r,x)) for r in A]
def mm(A,B,q):
    BT=list(zip(*B))
    return [[sum((x%q)*(y%q) for x,y in zip(r,c))%q for c in BT] for r in A]
def mv(A,x,q): return [sum((a%q)*(b%q) for a,b in zip(r,x))%q for r in A]
def tr(A): return [list(c) for c in zip(*A)]
def dot(a,b,q): return sum((x%q)*(y%q) for x,y in zip(a,b))%q
def center(x,q):
    x%=q
    return x-q if x>q//2 else x
def l1(v): return sum(abs(x) for x in v)
def n2(v): return sum(x*x for x in v)

def preimage_table(H,q,extra=4):
    n=len(H); d=len(H[0])
    R=[[rng.choice((-1,0,1)) for _ in range(d)] for __ in range(extra)]
    A2=[[rng.randrange(q) for _ in range(extra)] for __ in range(n)]
    A2R=mm(A2,R,q)
    A1=[[(H[i][j]-A2R[i][j])%q for j in range(d)] for i in range(n)]
    A=[A1[i]+A2[i] for i in range(n)]
    K=[[1 if i==j else 0 for j in range(d)] for i in range(d)]+[r[:] for r in R]
    assert mm(A,K,q)==[[x%q for x in r] for r in H]
    return A,K

def Ka(K,a): return [sum(x*y for x,y in zip(r,a)) for r in K]

def lwe(A,q,B=1):
    n=len(A); AT=tr(A); s=[rng.randrange(q) for _ in range(n)]
    e=[rng.randint(-B,B) for _ in AT]
    c=[(sum(r[i]*s[i] for i in range(n))+e[j])%q for j,r in enumerate(AT)]
    return c,e

q=65537; Be=1
out={"run":91,"seed":SEED,"q":q,"error_bound":Be,
     "preimage_identities":0,"lwe_zeroizer_samples":0,"prefix_zeroizer_samples":0,
     "column_norm_checks":0,"uniform_exact_controls":0,"families":[],"failures":[]}

for dummies in (0,4,16,64):
    H,a,npairs=padded_false(dummies)
    B2=npairs+1
    assert n2(a)==B2+4 and l1(a)==B2+2
    adv=[]; zl1=[]; zn2=[]
    for fixture in range(8):
        A,K=preimage_table(H,q)
        z=Ka(K,a)
        assert any(v%q for v in z) and mv(A,z,q)==[0]*len(A)
        out["preimage_identities"]+=1
        beta=max(math.sqrt(sum(x*x for x in c)) for c in tr(K))
        assert math.sqrt(n2(z)) <= beta*l1(a)+1e-12
        out["column_norm_checks"]+=1
        tau=Be*l1(z); assert tau<(q-1)//2
        adv.append(1-(2*tau+1)/q); zl1.append(l1(z)); zn2.append(n2(z))
        for trial in range(100):
            c,e=lwe(A,q,Be)
            got=center(dot(z,c,q),q); want=sum(x*y for x,y in zip(z,e))
            if got!=want or abs(got)>tau:
                out["failures"].append(["lwe",dummies,fixture,trial])
            out["lwe_zeroizer_samples"]+=1
        n=len(A)
        for pref in range(10):
            S=[[rng.randrange(q) for _ in range(n)] for __ in range(n)]
            SA=mm(S,A,q); assert mv(SA,z,q)==[0]*n
            c,e=lwe(SA,q,Be)
            if center(dot(z,c,q),q)!=sum(x*y for x,y in zip(z,e)):
                out["failures"].append(["prefix",dummies,fixture,pref])
            out["prefix_zeroizer_samples"]+=1
    out["families"].append({
        "dummies":dummies,"honest_threshold_norm2":B2,"false_norm2":n2(a),
        "false_l1":l1(a),"z_l1_min":min(zl1),"z_l1_max":max(zl1),
        "z_norm2_min":min(zn2),"z_norm2_max":max(zn2),
        "distinguisher_advantage_min":min(adv),"distinguisher_advantage_max":max(adv)})

for qs in (5,7,11):
    for z in ([1,0,0],[1,2,0],[2,1,3]):
        counts=[0]*qs
        for x0 in range(qs):
            for x1 in range(qs):
                for x2 in range(qs):
                    counts[dot(z,[x0,x1,x2],qs)]+=1
        assert len(set(counts))==1
        out["uniform_exact_controls"]+=1

out["ok"]=not out["failures"]
print(json.dumps(out,sort_keys=True,indent=2))
