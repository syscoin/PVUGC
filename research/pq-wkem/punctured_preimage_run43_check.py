#!/usr/bin/env python3
import json, random, hashlib, math
from fractions import Fraction
from pathlib import Path

SEED=430043
rng=random.Random(SEED)


def mat_vec(M,x,q=None):
    out=[sum(a*b for a,b in zip(row,x)) for row in M]
    if q is not None: out=[v%q for v in out]
    return out

def mat_mul(A,B,q=None):
    if not A or not B: return []
    BT=list(zip(*B))
    out=[[sum(a*b for a,b in zip(row,col)) for col in BT] for row in A]
    if q is not None: out=[[v%q for v in row] for row in out]
    return out

def concat_cols(A,B):
    return [ra+rb for ra,rb in zip(A,B)]

def puncture_col(M,h):
    col=[row[h] for row in M]
    A=[row[:h]+row[h+1:] for row in M]
    return A,col

def insert_one(y,h):
    return y[:h]+[1]+y[h:]

def dot(a,b): return sum(x*y for x,y in zip(a,b))

def centered(v,q):
    v%=q
    return v-q if v>q//2 else v

# 3CNF compiler copied mathematically from Run 32, independently implemented here.
def compile_3cnf(nvars, clauses):
    # coords: h; variable pairs; 2 slack pairs per clause
    names=['h']
    var_pairs=[]
    for i in range(nvars):
        var_pairs.append((len(names),len(names)+1)); names += [f'z{i}',f'nz{i}']
    slack=[]
    for j in range(len(clauses)):
        p1=(len(names),len(names)+1); names += [f's{j}a',f'ns{j}a']
        p2=(len(names),len(names)+1); names += [f's{j}b',f'ns{j}b']
        slack.append((p1,p2))
    rows=[]
    # pair rows u+ubar-h=0
    for p in var_pairs+[p for pp in slack for p in pp]:
        row=[0]*len(names); row[p[0]]=1; row[p[1]]=1; row[0]=-1; rows.append(row)
    # clause rows literals + s1 + 2s2 -4h =0
    for j,cl in enumerate(clauses):
        row=[0]*len(names); row[0]=-4
        for vi,positive in cl:
            row[var_pairs[vi][0 if positive else 1]] += 1
        row[slack[j][0][0]] += 1
        row[slack[j][1][0]] += 2
        rows.append(row)
    return rows,names,var_pairs,slack

def witness_vec(nvars,clauses,assignment):
    H,names,vp,sl=compile_3cnf(nvars,clauses)
    x=[0]*len(names); x[0]=1
    for i,val in enumerate(assignment): x[vp[i][0 if val else 1]]=1
    for j,cl in enumerate(clauses):
        t=sum(1 for vi,pos in cl if assignment[vi]==pos)
        if t==0: raise ValueError('unsatisfied')
        k=4-t
        s1,s2={1:(1,0),2:(0,1),3:(1,1)}[k]
        x[sl[j][0][0 if s1 else 1]]=1
        x[sl[j][1][0 if s2 else 1]]=1
    assert all(v==0 for v in mat_vec(H,x))
    return H,x,names

def false_contradiction(d):
    # clauses: z,z,z and not z,not z,not z; d unconstrained Boolean variables padded in H by pair rows only.
    H,names,vp,sl=compile_3cnf(1, [[(0,True)]*3,[(0,False)]*3])
    # append d pair coordinates and pair equations
    for k in range(d):
        oldn=len(names); names += [f'p{k}',f'np{k}']
        for row in H: row.extend([0,0])
        row=[0]*len(names); row[0]=-1; row[oldn]=1; row[oldn+1]=1; H.append(row)
    x=[0]*len(names); x[0]=1
    # variable z=0 -> (0,1)
    x[vp[0][1]]=1
    # positive clause: slack first pair (0,1), second (2,-1)
    x[sl[0][0][1]]=1; x[sl[0][1][0]]=2; x[sl[0][1][1]]=-1
    # negative clause: (1,0), (0,1)
    x[sl[1][0][0]]=1; x[sl[1][1][1]]=1
    # padding one-hot
    base=len(names)-2*d
    for k in range(d): x[base+2*k]=1
    assert all(v==0 for v in mat_vec(H,x)), (d,mat_vec(H,x))
    return H,x,names

def make_run42_lift(H,q,nrows=5,aux=4):
    r=len(H); N=len(H[0])
    C=[[rng.randrange(q) for _ in range(r)] for _ in range(nrows)]
    A0=[[rng.randrange(q) for _ in range(aux)] for _ in range(nrows)]
    CH=mat_mul(C, [[v%q for v in row] for row in H], q)
    M=concat_cols(CH,A0)
    D=concat_cols(C,A0)
    return C,A0,M,D

def ternary_sum_distribution(L):
    # exact counts for sum of L iid uniform {-1,0,1}; denominator 3^L
    counts={0:1}
    for _ in range(L):
        nxt={}
        for s,c in counts.items():
            for e in (-1,0,1): nxt[s+e]=nxt.get(s+e,0)+c
        counts=nxt
    return counts

results={"seed":SEED,"puncture_identity_trials":0,"transfer_false_trials":0,"true_decap_trials":0,"false_decap_trials":0,"false_trials_by_d":[],"exact_ternary":[],"norm_family":[]}

# 1) Pure puncturing identity on random M/e, and Run42 semantic-to-preimage identity.
for q in (17,29,101):
    for _ in range(400):
        rows=4; cols=9; h=rng.randrange(cols)
        M=[[rng.randrange(q) for _ in range(cols)] for __ in range(rows)]
        y=[rng.randrange(q) for _ in range(cols-1)]
        A,mh=puncture_col(M,h); u=[(-v)%q for v in mh]
        e=insert_one(y,h)
        lhs=mat_vec(M,e,q)
        rhs=[(a-b)%q for a,b in zip(mat_vec(A,y,q),u)]
        assert lhs==rhs
        results["puncture_identity_trials"]+=1

# 2) Public affine-transfer identity maps every semantic normalized kernel point, including false pseudomode.
#    Synthetic A=I makes R explicit; identity itself is distribution-independent.
for d in (0,1,4,16,64):
    H,xf,names=false_contradiction(d)
    N=len(xf); r=len(H); q=257
    for _ in range(100):
        C=[[rng.randrange(q) for _ in range(r)] for __ in range(N)] # output dimension N, A=I_N
        u=[rng.randrange(q) for __ in range(N)]
        CH=mat_mul(C, [[v%q for v in row] for row in H], q)
        # R = CH + u e_h^T; h=0
        R=[row[:] for row in CH]
        for i in range(N): R[i][0]=(R[i][0]+u[i])%q
        rx=mat_vec(R,[v%q for v in xf],q)
        assert rx==u
        results["transfer_false_trials"]+=1

# 3) Run42 puncturing gives a native preimage, true and false.
# True formula one clause (z or z or z), witness z=1.
Ht,xt,_=witness_vec(1,[[(0,True)]*3],[True])
for d in (0,4,16,64):
    Hf,xf,_=false_contradiction(d)
    B2=d+6
    assert sum(v*v for v in xf)==B2+4
    assert sum(abs(v) for v in xf)==B2+2
    yf=xf[1:]
    assert sum(v*v for v in yf)==B2+3  # punctured: d+9
    assert sum(abs(v) for v in yf)==B2+1 # punctured: d+7
    results["norm_family"].append({"d":d,"B2":B2,"punctured_false_l2sq":sum(v*v for v in yf),"punctured_false_l1":sum(abs(v) for v in yf)})

# true lift/preimage tests on many random lifts/moduli
for q in (32,64,128,257):
    for _ in range(250):
        C,A0,M,D=make_run42_lift(Ht,q,nrows=5,aux=3)
        e=xt+[0]*3
        assert mat_vec(M,[v%q for v in e],q)==[0]*5
        Abar,mh=puncture_col(M,0); u=[(-v)%q for v in mh]; y=e[1:]
        assert mat_vec(Abar,[v%q for v in y],q)==u
        # one synthetic bounded-error dual-Regev decapsulation, q chosen large enough for this tiny true fixture only
        s=[rng.randrange(q) for _ in range(5)]
        eps=[rng.choice((-1,0,1)) for _ in range(len(y))]; eps0=rng.choice((-1,0,1)); K=rng.randrange(2)
        a=[(v+ee)%q for v,ee in zip([sum(Abar[i][j]*s[i] for i in range(5))%q for j in range(len(y))],eps)]
        b=(dot(u,s)+eps0+(q//2)*K)%q if q%2==0 else None
        if b is not None:
            res=centered(b-dot(y,a),q)
            # For K=1 centered residual is near +/-q/2, decode by comparing circular distance.
            d0=abs(centered(res,q)); d1=abs(centered(res-q//2,q))
            got=0 if d0<d1 else 1
            assert got==K
            results["true_decap_trials"]+=1

# false exact preimage + decapsulation at tight deterministic-honest threshold q=4(L+1).
# Here L=B^2=d+6 unit ternary terms for honest residual. False residual law is S_L+2E.
for d in (0,1,4,8,16,32,64):
    Hf,xf,_=false_contradiction(d)
    B2=d+6; L=B2; q=4*(L+1)
    C,A0,M,D=make_run42_lift(Hf,q,nrows=6,aux=4)
    e=xf+[0]*4
    assert mat_vec(M,[v%q for v in e],q)==[0]*6
    Abar,mh=puncture_col(M,0); u=[(-v)%q for v in mh]; y=e[1:]
    assert mat_vec(Abar,[v%q for v in y],q)==u
    # exact ternary distribution law
    counts=ternary_sum_distribution(L)
    den=3**L
    extreme=counts.get(L,0)+counts.get(L-1,0)
    fail=Fraction(2,3)*Fraction(extreme,den)
    formula=Fraction(2*(L+1),3**(L+1))
    assert fail==formula
    success=1-formula
    results["exact_ternary"].append({
        "d":d,"L":L,"q":q,
        "false_failure_num":formula.numerator,"false_failure_den":formula.denominator,
        "false_success_float":float(success)
    })
    # random full capsule trials; exact proof above, trials verify implementation path including s cancellation.
    correct_d=0; total_d=1000
    for _ in range(total_d):
        s=[rng.randrange(q) for __ in range(6)]
        eps=[rng.choice((-1,0,1)) for __ in range(len(y))]; eps0=rng.choice((-1,0,1)); K=rng.randrange(2)
        avec=[sum(Abar[i][j]*s[i] for i in range(6))%q for j in range(len(y))]
        a=[(v+ee)%q for v,ee in zip(avec,eps)]
        b=(dot(u,s)+eps0+(q//2)*K)%q
        # residual relative to 0/q/2 via circular distances
        res=(b-dot(y,a))%q
        d0=abs(centered(res,q)); d1=abs(centered(res-q//2,q))
        got=0 if d0<d1 else 1
        # At q/4=L+1, nearest-half decoding fails exactly when |noise| >= L+1.
        noise=eps0-dot(y,eps)
        expected=K if abs(noise)<L+1 else 1-K
        # tie at exactly threshold nearest distances equal; avoid asserting got on ties
        if abs(noise)!=L+1:
            assert got==expected
        if got==K:
            results["false_decap_trials"]+=1
            correct_d+=1
    results["false_trials_by_d"].append({"d":d,"correct":correct_d,"total":total_d})

# 4) Exact Gaussian diagnostic ratios for punctured norm gap, not a security proof.
def normal_cdf(x): return 0.5*(1+math.erf(x/math.sqrt(2)))
results["gaussian_diagnostic"]=[]
for d in (0,16,64,256,1024,4096):
    VH=d+5 # sigma0=0, sigma=1, punctured honest norm^2
    VF=d+9
    for kappa in (3.0,5.0,8.0):
        ph=2*normal_cdf(kappa)-1
        pf=2*normal_cdf(kappa*math.sqrt(VH/VF))-1
        results["gaussian_diagnostic"].append({"d":d,"kappa":kappa,"honest":ph,"false":pf,"gap":ph-pf})

out=Path('/mnt/data/run43/punctured-preimage-run43.json')
out.write_text(json.dumps(results,indent=2,sort_keys=True)+"\n")
print(out.read_text())
