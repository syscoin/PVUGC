#!/usr/bin/env python3
import itertools, math, random, json, hashlib
from collections import defaultdict

# Coordinates: h first, then for each logical pair p, (p, pbar).
# Pair list consists of n variable pairs followed by two slack pairs per clause.

def compile_3cnf(nvars, clauses):
    npairs = nvars + 2*len(clauses)
    m = 1 + 2*npairs
    def pair_indices(p):
        return 1+2*p, 1+2*p+1
    rows=[]
    # variable normalization rows
    for i in range(nvars):
        r=[0]*m; a,b=pair_indices(i)
        r[a]=1; r[b]=1; r[0]=-1
        rows.append(r)
    # slack normalization rows
    for j in range(len(clauses)):
        for k in range(2):
            p=nvars+2*j+k
            r=[0]*m; a,b=pair_indices(p)
            r[a]=1; r[b]=1; r[0]=-1
            rows.append(r)
    # clauses
    for j,cl in enumerate(clauses):
        assert len(cl)==3
        r=[0]*m
        for lit in cl:
            var=abs(lit)-1
            a,b=pair_indices(var)
            r[a if lit>0 else b]+=1
        s1,_=pair_indices(nvars+2*j)
        s2,_=pair_indices(nvars+2*j+1)
        r[s1]+=1; r[s2]+=2; r[0]-=4
        rows.append(r)
    return rows, npairs

def matvec(rows,x):
    return [sum(a*b for a,b in zip(r,x)) for r in rows]

def norm2(x): return sum(v*v for v in x)
def l1(x): return sum(abs(v) for v in x)

def witness_vector(nvars, clauses, assignment):
    rows,npairs=compile_3cnf(nvars,clauses)
    x=[0]*(1+2*npairs); x[0]=1
    def set_pair(p,bit):
        x[1+2*p]=bit; x[1+2*p+1]=1-bit
    for i,b in enumerate(assignment): set_pair(i,int(bool(b)))
    for j,cl in enumerate(clauses):
        t=0
        for lit in cl:
            b=assignment[abs(lit)-1]
            t += b if lit>0 else (1-b)
        if t==0: raise ValueError('not satisfying')
        val=4-t # 1,2,3
        s1=val&1; s2=1 if val>=2 else 0
        set_pair(nvars+2*j,s1)
        set_pair(nvars+2*j+1,s2)
    assert all(v==0 for v in matvec(rows,x))
    assert norm2(x)==npairs+1
    return x

def extract_assignment_if_short(nvars,clauses,x):
    rows,npairs=compile_3cnf(nvars,clauses)
    if x[0]!=1: return None
    if any(matvec(rows,x)): return None
    if norm2(x)>npairs+1: return None
    ass=[]
    for i in range(nvars):
        a=x[1+2*i]; b=x[1+2*i+1]
        if (a,b) not in ((1,0),(0,1)): return None
        ass.append(a)
    # verify clauses
    for cl in clauses:
        if not any((ass[abs(l)-1] if l>0 else 1-ass[abs(l)-1]) for l in cl):
            return None
    return ass

def contradiction_formula(t):
    # t copies of x and not-x 3-literal clauses
    return 1, [(1,1,1)]*t + [(-1,-1,-1)]*t

def fractional_false_vector(t):
    n,clauses=contradiction_formula(t)
    rows,npairs=compile_3cnf(n,clauses)
    x=[0]*(1+2*npairs); x[0]=1
    def setpair(p,a,b): x[1+2*p]=a; x[1+2*p+1]=b
    setpair(0,0,1)
    # positive clause: truth 0; solve s1+2s2=4 with (0,1),(2,-1)
    for j in range(t):
        setpair(n+2*j,0,1); setpair(n+2*j+1,2,-1)
    # negative clause: truth 3; solve s1+2s2=1 with (1,0),(0,1)
    for j in range(t,2*t):
        setpair(n+2*j,1,0); setpair(n+2*j+1,0,1)
    assert all(v==0 for v in matvec(rows,x))
    return x, npairs


def padded_contradiction(dummies):
    n=1+dummies
    clauses=[(1,1,1),(-1,-1,-1)]
    return n,clauses

def padded_false_vector(dummies):
    n,clauses=padded_contradiction(dummies)
    rows,npairs=compile_3cnf(n,clauses)
    x=[0]*(1+2*npairs); x[0]=1
    def setpair(p,a,b): x[1+2*p]=a; x[1+2*p+1]=b
    setpair(0,0,1)
    for i in range(1,n): setpair(i,0,1)
    # positive unsatisfied clause repaired by exactly one nonbinary slack pair
    setpair(n+0,0,1); setpair(n+1,2,-1)
    # negative clause already has truth count 3
    setpair(n+2,1,0); setpair(n+3,0,1)
    assert all(v==0 for v in matvec(rows,x))
    assert norm2(x)==(npairs+1)+4
    assert l1(x)==(npairs+1)+2
    return x,npairs

def sat_formula(t):
    # same n=1 and clause count 2t, all satisfied by x=1
    return 1, [(1,1,1)]*(2*t)

def mod_dot(x,c,Q): return sum((a%Q)*(b%Q) for a,b in zip(x,c))%Q

def center(v,Q):
    v%=Q
    return v-Q if v>Q//2 else v

def transpose_times(rows,y,Q):
    if not rows: return []
    m=len(rows[0]); out=[0]*m
    for i,r in enumerate(rows):
        yi=y[i]%Q
        for j,a in enumerate(r): out[j]=(out[j]+a*yi)%Q
    return out

def encapsulate(rows,mu,Q,E,rng):
    y=[rng.randrange(Q) for _ in rows]
    base=transpose_times(rows,y,Q)
    e=[rng.randint(-E,E) for _ in base]
    c=[(base[j]+e[j]+((Q//2)*mu if j==0 else 0))%Q for j in range(len(base))]
    return c,e

def decode_with_x(c,x,Q):
    z=center(mod_dot(x,c,Q),Q)
    # nearest of 0 and +/-Q/2 in centered coordinates
    # compare circular distance to 0 vs Q/2
    d0=abs(z)
    d1=min(abs(z-Q//2),abs(z+Q//2))
    return 0 if d0<d1 else 1

def exact_ternary_fourier(x,Q):
    val=1.0
    for a in x:
        a%=Q
        val *= (1+2*math.cos(2*math.pi*a/Q))/3.0
    return abs(val)

def brute_min_norm_h1(nvars,clauses,limit=3):
    rows,npairs=compile_3cnf(nvars,clauses)
    m=1+2*npairs
    # use pair equations to reduce: choose first entry of each pair in [-limit,limit], complement=1-a
    best=None; bestx=None
    for vals in itertools.product(range(-limit,limit+1), repeat=npairs):
        x=[1]
        for a in vals: x.extend([a,1-a])
        if all(v==0 for v in matvec(rows,x)):
            n2=norm2(x)
            if best is None or n2<best:
                best=n2;bestx=x
    return best,bestx

def run():
    out={}
    # honest compiler exhaustive assignments on several formulas
    compiler_checks=0
    rng=random.Random(0xC0FFEE32)
    for n in range(1,5):
        # random clauses, then plant random assignment by rejection
        for case in range(25):
            ass=[rng.randrange(2) for _ in range(n)]
            clauses=[]
            for _ in range(8):
                while True:
                    cl=[]
                    for __ in range(3):
                        i=rng.randrange(n)+1; sign=1 if rng.randrange(2) else -1
                        cl.append(sign*i)
                    if any((ass[abs(l)-1] if l>0 else 1-ass[abs(l)-1]) for l in cl): break
                clauses.append(tuple(cl))
            x=witness_vector(n,clauses,ass)
            got=extract_assignment_if_short(n,clauses,x)
            assert got==ass
            compiler_checks += 1
    out['honest_compiler_cases']=compiler_checks

    # extraction theorem exhaustive small coordinate choices for tiny formulas, whenever within B
    ex_checks=0
    tiny=[(1,[(1,1,1)]),(1,[(-1,-1,-1)]),(2,[(1,2,-1)])]
    for n,cls in tiny:
        rows,npairs=compile_3cnf(n,cls); B2=npairs+1
        # enumerate pair first coordinates only in {-1,0,1,2}; complements=1-a
        for vals in itertools.product(range(-1,3), repeat=npairs):
            x=[1]
            for a in vals: x.extend([a,1-a])
            if norm2(x)<=B2 and all(v==0 for v in matvec(rows,x)):
                got=extract_assignment_if_short(n,cls,x)
                assert got is not None
                ex_checks += 1
    out['exhaustive_short_extract_vectors']=ex_checks

    # false family identities and gap
    false_stats=[]
    for t in [1,2,4,8,16,32,64]:
        xf,npairs=fractional_false_vector(t)
        assert extract_assignment_if_short(*contradiction_formula(t),xf) is None
        B2=npairs+1
        false_stats.append({'t':t,'pairs':npairs,'good_B2':B2,'false_norm2':norm2(xf),'ratio2':norm2(xf)/B2,'false_l1':l1(xf)})
    out['false_family']=false_stats
    # Padding control: the false normalized kernel gap is only additive +4 in squared norm.
    padded=[]
    for d in [0,4,16,64,256,1024]:
        xf,npairs=padded_false_vector(d)
        B2=npairs+1
        Q=8*B2
        padded.append({'dummies':d,'pairs':npairs,'good_B2':B2,'false_norm2':norm2(xf),'ratio2':norm2(xf)/B2,'false_l1':l1(xf),'l1_ratio':l1(xf)/B2,'Q':Q,'false_fourier_abs':exact_ternary_fourier(xf,Q)})
    out['padded_false_gap']=padded

    # exhaustive minimum for t=1,2 within limited coordinate range
    mins=[]
    for t in [1]:
        n,cls=contradiction_formula(t)
        # t=2 has npairs=9; range -1..2 => 4^9=262k feasible
        best,bx=brute_min_norm_h1(n,cls,limit=2)
        rows,npairs=compile_3cnf(n,cls)
        mins.append({'t':t,'min_h1_norm2_in_range':best,'good_B2':npairs+1,'witness_exists_below_B': best is not None and best<=npairs+1})
    out['false_minimum_controls']=mins

    # modular no-wrap bound checks for witness threshold
    mod_checks=[]
    for t in [1,4,16,32]:
        n,cls=sat_formula(t); rows,npairs=compile_3cnf(n,cls)
        B=math.sqrt(npairs+1)
        qmin=math.floor(2*math.sqrt(24)*B)+1
        ass=[1]
        x=witness_vector(n,cls,ass)
        assert all(v==0 for v in matvec(rows,x))
        mod_checks.append({'t':t,'B':B,'q_no_wrap_sufficient':qmin})
    out['modulus_bounds']=mod_checks

    # KEM honest/false decoding with bounded ternary noise and generous q=8*(N+1), rounded even.
    kem=[]
    for t in [1,4,16,32]:
        n,cls=sat_formula(t); rows,npairs=compile_3cnf(n,cls); xh=witness_vector(n,cls,[1])
        Q=8*(npairs+1)
        if Q%2: Q+=1
        honest=0
        for trial in range(200):
            mu=rng.randrange(2); c,e=encapsulate(rows,mu,Q,1,rng)
            honest += decode_with_x(c,xh,Q)==mu
        nf,cf=contradiction_formula(t); rf,npf=compile_3cnf(nf,cf); xf,_=fractional_false_vector(t)
        false=0
        for trial in range(200):
            mu=rng.randrange(2); c,e=encapsulate(rf,mu,Q,1,rng)
            false += decode_with_x(c,xf,Q)==mu
        kem.append({'t':t,'Q':Q,'honest':honest,'false_attack':false,'trials':200,'false_fourier_abs':exact_ternary_fourier(xf,Q)})
    out['kem_trials']=kem

    # Exact convolution distribution for false decoder noise for selected t, and exact success under circular nearest decoding.
    exact=[]
    for t in [1,2,4,8,16,32]:
        xf,npairs=fractional_false_vector(t); Q=8*(npairs+1)
        dist={0:1}
        for a in xf:
            nd=defaultdict(int)
            for z,cnt in dist.items():
                for e in (-1,0,1): nd[z+a*e]+=cnt
            dist=dict(nd)
        total=3**len(xf)
        # bit0 success iff centered sum closer to 0 than Q/2; support << Q so abs(sum)<Q/4 sufficient
        succ=sum(cnt for z,cnt in dist.items() if abs(z)<Q/4)
        exact.append({'t':t,'Q':Q,'support_min':min(dist),'support_max':max(dist),'success_num':succ,'success_den':total,'failure_prob':1-succ/total})
    out['exact_false_attack_noise']=exact

    return out

if __name__=='__main__':
    res=run()
    print(json.dumps(res,indent=2,sort_keys=True))
