#!/usr/bin/env python3
import json, random, math, hashlib
from fractions import Fraction
from pathlib import Path
from decimal import Decimal, getcontext

SEED = 440044
rng = random.Random(SEED)
getcontext().prec = 80


def dot(a,b):
    return sum(x*y for x,y in zip(a,b))


def mat_vec(M,x,q=None):
    out=[dot(row,x) for row in M]
    if q is not None:
        out=[v%q for v in out]
    return out


def mat_mul(A,B,q=None):
    if not A or not B: return []
    BT=list(zip(*B))
    out=[[dot(row,col) for col in BT] for row in A]
    if q is not None:
        out=[[v%q for v in row] for row in out]
    return out


def transpose(A):
    return [list(col) for col in zip(*A)] if A else []


def concat_cols(A,B):
    return [ra+rb for ra,rb in zip(A,B)]


def puncture_col(M,h):
    col=[row[h] for row in M]
    A=[row[:h]+row[h+1:] for row in M]
    return A,col


def centered(v,q):
    v%=q
    return v-q if v>q//2 else v


def compile_3cnf(nvars, clauses):
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
    for p in var_pairs+[p for pp in slack for p in pp]:
        row=[0]*len(names); row[p[0]]=1; row[p[1]]=1; row[0]=-1; rows.append(row)
    for j,cl in enumerate(clauses):
        row=[0]*len(names); row[0]=-4
        for vi,positive in cl:
            row[var_pairs[vi][0 if positive else 1]] += 1
        row[slack[j][0][0]] += 1
        row[slack[j][1][0]] += 2
        rows.append(row)
    return rows,names,var_pairs,slack


def append_padding_pairs(H,names,d):
    for k in range(d):
        oldn=len(names); names += [f'p{k}',f'np{k}']
        for row in H: row.extend([0,0])
        row=[0]*len(names); row[0]=-1; row[oldn]=1; row[oldn+1]=1; H.append(row)
    return H,names


def false_line(d,t):
    # Run-34/43 contradiction: (z v z v z) & (!z v !z v !z).
    H,names,vp,sl=compile_3cnf(1,[[(0,True)]*3,[(0,False)]*3])
    H,names=append_padding_pairs(H,names,d)
    x=[0]*len(names); x[0]=1
    x[vp[0][1]]=1                        # z=0
    # Positive-clause affine family a+2b=4:
    # a=2t, b=2-t, with complements 1-a and 1-b.
    a=2*t; b=2-t
    x[sl[0][0][0]]=a; x[sl[0][0][1]]=1-a
    x[sl[0][1][0]]=b; x[sl[0][1][1]]=1-b
    # Negative clause c+2d=1, fixed c=1,d=0.
    x[sl[1][0][0]]=1; x[sl[1][0][1]]=0
    x[sl[1][1][0]]=0; x[sl[1][1][1]]=1
    base=len(names)-2*d
    for k in range(d): x[base+2*k]=1
    assert all(v==0 for v in mat_vec(H,x)), (d,t,mat_vec(H,x))
    return H,x,names


def true_double_clause(d):
    H,names,vp,sl=compile_3cnf(1,[[(0,True)]*3,[(0,True)]*3])
    H,names=append_padding_pairs(H,names,d)
    x=[0]*len(names); x[0]=1; x[vp[0][0]]=1
    # Each all-z clause has three satisfied literals, so slack equation is s1+2s2=1.
    for j in range(2):
        x[sl[j][0][0]]=1
        x[sl[j][1][1]]=1
    base=len(names)-2*d
    for k in range(d): x[base+2*k]=1
    assert all(v==0 for v in mat_vec(H,x))
    return H,x,names


def make_run42_lift(H,q,nrows=6,aux=4):
    r=len(H)
    C=[[rng.randrange(q) for _ in range(r)] for __ in range(nrows)]
    A0=[[rng.randrange(q) for _ in range(aux)] for __ in range(nrows)]
    CH=mat_mul(C,[[v%q for v in row] for row in H],q)
    M=concat_cols(CH,A0)
    return M


def symmetric_ternary(n):
    E=[[0]*n for _ in range(n)]
    upper=[]
    for i in range(n):
        for j in range(i,n):
            e=rng.choice((-1,0,1))
            E[i][j]=e; E[j][i]=e
            upper.append((i,j,e))
    return E,upper


def radial_params(d):
    H=d+5
    T=H+4
    # Honest y has H unit coordinates. Full symmetric E contributes at most H^2,
    # eta contributes H, and T(eps0-eps.y) contributes T(H+1).
    B_H=H*H + H + T*(H+1)
    assert B_H==2*H*H+6*H+4
    q=4*(B_H+2)
    assert q%8==0
    mu=q//8
    threshold=q//4
    return H,T,B_H,q,mu,threshold


def build_capsule(A,u,q,T,K):
    m=len(A); n=len(A[0]); mu=q//8
    s=[rng.randrange(q) for _ in range(m)]
    R=[[rng.randrange(q) for _ in range(n)] for __ in range(m)]
    eps=[rng.choice((-1,0,1)) for _ in range(n)]
    eps0=rng.choice((-1,0,1))
    eta=[rng.choice((-1,0,1)) for _ in range(n)]
    E,upper=symmetric_ternary(n)

    # a=A^T s + eps
    a=[]
    for j in range(n):
        a.append((sum(A[i][j]*s[i] for i in range(m))+eps[j])%q)
    b=(dot(u,s)+eps0+mu*K)%q

    # Q=A^T R + R^T A + E + mu K I
    AtR=[[sum(A[k][i]*R[k][j] for k in range(m)) for j in range(n)] for i in range(n)]
    RtA=[[sum(R[k][i]*A[k][j] for k in range(m)) for j in range(n)] for i in range(n)]
    Q=[[0]*n for _ in range(n)]
    for i in range(n):
        for j in range(n):
            Q[i][j]=(AtR[i][j]+RtA[i][j]+E[i][j]+(mu*K if i==j else 0))%q
    ell=[]
    for j in range(n):
        ell.append((2*sum(R[i][j]*u[i] for i in range(m))+eta[j])%q)
    aux={"eps":eps,"eps0":eps0,"eta":eta,"E":E,"upper":upper}
    return a,b,Q,ell,aux


def quad(y,Q):
    return sum(y[i]*Q[i][j]*y[j] for i in range(len(y)) for j in range(len(y)))


def radial_residual(y,a,b,Q,ell,T,q):
    return (quad(y,Q)-dot(y,ell)-T*(b-dot(y,a)))%q


def predicted_noise(y,aux,T):
    E=aux["E"]
    return quad(y,E)-dot(aux["eta"],y)-T*(aux["eps0"]-dot(aux["eps"],y))


def decode_half(v,q):
    d0=abs(centered(v,q))
    d1=abs(centered(v-q//2,q))
    if d0==d1: return None
    return 0 if d0<d1 else 1


def weighted_ternary_distribution(coeffs):
    counts={0:1}
    for c in coeffs:
        if c==0: continue
        nxt={}
        for s,n in counts.items():
            nxt[s-c]=nxt.get(s-c,0)+n
            nxt[s]=nxt.get(s,0)+n
            nxt[s+c]=nxt.get(s+c,0)+n
        counts=nxt
    return counts


def noise_coeffs_for_y(y,T):
    nz=[v for v in y if v]
    coeff=[]
    # symmetric E: diagonal yi^2, off-diagonal 2 yi yj
    for i,yi in enumerate(nz):
        coeff.append(yi*yi)
        for j in range(i+1,len(nz)):
            coeff.append(2*yi*nz[j])
    coeff += [-yi for yi in nz]      # -eta.y
    coeff += [T*yi for yi in nz]     # T eps.y
    coeff += [-T]                    # -T eps0
    return [abs(c) for c in coeff if c]


results={
    "seed":SEED,
    "false_boolean_assignments_checked":0,
    "false_boolean_witnesses":0,
    "line_identity_checks":0,
    "random_lift_preimage_checks":0,
    "honest_full_capsule_trials":0,
    "honest_full_capsule_failures":0,
    "false_full_capsule_trials":0,
    "false_full_capsule_successes":0,
    "false_full_capsule_by_d":[],
    "exact_false_noise":[],
    "radial_polynomial_escape_checks":0,
}

# 1) The false formula has no Boolean source witness.
for z in (0,1):
    results["false_boolean_assignments_checked"]+=1
    c1=(z or z or z)
    c2=((not z) or (not z) or (not z))
    if c1 and c2: results["false_boolean_witnesses"]+=1
assert results["false_boolean_witnesses"]==0

# 2) Exact public affine line in the false semantic kernel and its radial law.
for d in (0,1,4,16,64):
    H0,x0,names=false_line(d,0)
    H1,x1,_=false_line(d,1)
    assert H0==H1
    v=[b-a for a,b in zip(x0,x1)]
    assert v[0]==0 and all(z==0 for z in mat_vec(H0,v))
    for t in range(-6,7):
        Ht,xt,_=false_line(d,t)
        assert Ht==H0
        expected=[x0[i]+t*v[i] for i in range(len(x0))]
        assert xt==expected
        y=xt[1:]
        radial=sum(z*z for z in y)
        assert radial==d+9+10*t*(t-1)
        results["line_identity_checks"]+=1
    # Special radii: t=0,1 are the notch; t=2 escapes by +20.
    y0=x0[1:]; y1=x1[1:]; y2=false_line(d,2)[1][1:]
    assert sum(z*z for z in y0)==d+9
    assert sum(z*z for z in y1)==d+9
    assert sum(z*z for z in y2)==d+29
    assert sum(abs(z) for z in y2)==d+11

# 3) Any finite-degree radial polynomial notch is escaped somewhere on the line.
# Deterministic controls use polynomials whose roots are selected false-line radii.
def poly_eval_from_roots(s,roots):
    out=1
    for r in roots: out*=s-r
    return out
for d in (0,3,11):
    honest_radius=d+5
    for deg in range(1,9):
        roots=[d+9+10*t*(t-1) for t in range(deg)]
        # If the chosen roots accidentally included honest radius this would not be a valid honest gate.
        assert poly_eval_from_roots(honest_radius,roots)!=0
        # Composition degree <=2*deg, so <=2*deg integer t can be roots unless identically zero.
        found=None
        for t in range(0,2*deg+2):
            s=d+9+10*t*(t-1)
            if poly_eval_from_roots(s,roots)!=0:
                found=t; break
        assert found is not None
        results["radial_polynomial_escape_checks"]+=1

# 4) Random Run-42 lifts preserve every point on the false line as a punctured exact preimage.
for d in (0,4,16):
    _,_,BH,q,mu,thr=radial_params(d)
    Hf,x0,_=false_line(d,0)
    x2=false_line(d,2)[1]
    for _ in range(100):
        M=make_run42_lift(Hf,q,nrows=6,aux=4)
        Abar,mh=puncture_col(M,0); u=[(-z)%q for z in mh]
        for x in (x0,x2):
            e=x+[0]*4
            assert mat_vec(M,[z%q for z in e],q)==[0]*6
            y=e[1:]
            assert mat_vec(Abar,[z%q for z in y],q)==u
            results["random_lift_preimage_checks"]+=1

# 5) Full public quadratic capsule: honest deterministic correctness and false t=2 decoding.
for d in (0,4,8,16):
    Hcount,T,BH,q,mu,threshold=radial_params(d)
    Ht,xt,_=true_double_clause(d)
    Hf,xf0,_=false_line(d,0)
    xf2=false_line(d,2)[1]
    # Honest and false compilers have the same ambient size; use independent statement-specific lifts.
    honest_ok=0; false_ok=0; trials=200
    for _ in range(trials):
        # honest
        M=make_run42_lift(Ht,q,nrows=6,aux=4)
        Abar,mh=puncture_col(M,0); u=[(-z)%q for z in mh]
        e=xt+[0]*4; y=e[1:]
        assert mat_vec(Abar,[z%q for z in y],q)==u
        assert sum(z*z for z in y)==Hcount
        K=rng.randrange(2)
        a,b,Q,ell,aux=build_capsule(Abar,u,q,T,K)
        res=radial_residual(y,a,b,Q,ell,T,q)
        noise=predicted_noise(y,aux,T)
        ideal=(mu*K*(sum(z*z for z in y)-T))%q
        assert (res-ideal-noise)%q==0
        assert abs(noise)<=BH < threshold
        got=decode_half(res,q)
        assert got==K
        honest_ok+=1; results["honest_full_capsule_trials"]+=1

        # false on a fresh lift of the false statement
        Mf=make_run42_lift(Hf,q,nrows=6,aux=4)
        Af,mhf=puncture_col(Mf,0); uf=[(-z)%q for z in mhf]
        ef=xf2+[0]*4; yf=ef[1:]
        assert mat_vec(Af,[z%q for z in yf],q)==uf
        assert sum(z*z for z in yf)==T+20
        assert (mu*(sum(z*z for z in yf)-T))%q==q//2
        Kf=rng.randrange(2)
        af,bf,Qf,ellf,auxf=build_capsule(Af,uf,q,T,Kf)
        resf=radial_residual(yf,af,bf,Qf,ellf,T,q)
        noisef=predicted_noise(yf,auxf,T)
        idealf=(mu*Kf*(sum(z*z for z in yf)-T))%q
        assert (resf-idealf-noisef)%q==0
        gotf=decode_half(resf,q)
        results["false_full_capsule_trials"]+=1
        if gotf==Kf:
            false_ok+=1; results["false_full_capsule_successes"]+=1
    results["false_full_capsule_by_d"].append({"d":d,"correct":false_ok,"total":trials})

# 6) Exact complete false-decoder noise law and analytic Hoeffding bound.
for d in (0,1,4,8,16,32):
    Hcount,T,BH,q,mu,threshold=radial_params(d)
    y2=false_line(d,2)[1][1:]
    coeffs=noise_coeffs_for_y(y2,T)
    counts=weighted_ternary_distribution(coeffs)
    den=3**len(coeffs)
    success_count=sum(n for s,n in counts.items() if abs(s)<threshold)
    failure=Fraction(den-success_count,den)
    sigma_coeff_sq=sum(c*c for c in coeffs)
    expected_sigma=Hcount**3+35*Hcount**2+312*Hcount+1240
    assert sigma_coeff_sq==expected_sigma
    false_B=sum(coeffs)
    assert false_B==2*Hcount**2+24*Hcount+70
    # Hoeffding for independent centered variables in [-c_i,c_i].
    hoeffding=min(1.0,2.0*math.exp(-(threshold**2)/(2.0*sigma_coeff_sq)))
    # exact failure must respect the proved generic tail bound (floating slack only)
    assert float(failure) <= hoeffding + 1e-15
    fail_dec=Decimal(failure.numerator)/Decimal(failure.denominator)
    succ_dec=Decimal(1)-fail_dec
    results["exact_false_noise"].append({
        "d":d,
        "H":Hcount,
        "T":T,
        "B_H":BH,
        "q":q,
        "threshold":threshold,
        "mu":mu,
        "false_l1":sum(abs(z) for z in y2),
        "false_l2sq":sum(z*z for z in y2),
        "num_independent_ternary_terms":len(coeffs),
        "sum_coeff_squares":sigma_coeff_sq,
        "false_failure_num":failure.numerator,
        "false_failure_den":failure.denominator,
        "false_failure_decimal":format(fail_dec,'.35E'),
        "false_success_decimal":format(succ_dec,'.35E'),
        "hoeffding_failure_upper_bound":hoeffding,
    })

# 7) Larger-size analytic controls only; no exact distribution enumeration claimed here.
results["hoeffding_asymptotic_controls"]=[]
for d in (64,128,256,512,1024):
    Hcount,T,BH,q,mu,threshold=radial_params(d)
    sigma=Hcount**3+35*Hcount**2+312*Hcount+1240
    bound=min(1.0,2.0*math.exp(-(threshold**2)/(2.0*sigma)))
    results["hoeffding_asymptotic_controls"].append({"d":d,"H":Hcount,"failure_upper_bound":bound})

out=Path('/mnt/data/run44/radial-preimage-gate-run44.json')
out.write_text(json.dumps(results,indent=2,sort_keys=True)+"\n")
print(out.read_text())
