#!/usr/bin/env python3
from __future__ import annotations
import itertools, json, math, random

checks=[]
def ok(name, cond, detail=None):
    if not cond:
        raise AssertionError(f"{name}: {detail}")
    checks.append((name,detail))

def sat_clause(clause, assignment):
    # clause: [(var_index, positive_bool), ...] with 0-based vars
    for i,pos in clause:
        bit=assignment[i]
        if bit if pos else (1-bit):
            return True
    return False

def formula_sat(formula, a):
    return all(sat_clause(c,a) for c in formula)

def local_sat_assignments(clause):
    out=[]
    for bits in itertools.product((0,1), repeat=3):
        good=False
        for p,(i,pos) in enumerate(clause):
            lit=bits[p] if pos else 1-bits[p]
            good |= bool(lit)
        if good:
            out.append(bits)
    return out

def build_compiler(n, formula):
    # columns grouped: n variable one-hot pairs, then one group per clause of locally satisfying triples.
    groups=[]; names=[]
    col=0
    var_cols=[]
    for i in range(n):
        g=[col,col+1]; col+=2
        groups.append(g); var_cols.append(g); names += [f"v{i}=0",f"v{i}=1"]
    clause_cols=[]
    local_lists=[]
    for j,c in enumerate(formula):
        loc=local_sat_assignments(c); local_lists.append(loc)
        g=list(range(col,col+len(loc))); col += len(loc)
        groups.append(g); clause_cols.append(g)
        names += [f"c{j}:{''.join(map(str,b))}" for b in loc]
    rows=[]; target=[]; rownames=[]
    # group sum =1
    for gi,g in enumerate(groups):
        row=[0]*col
        for k in g: row[k]=1
        rows.append(row); target.append(1); rownames.append(f"group{gi}_sum")
    # each local position's actual variable bit equals global variable bit
    for j,c in enumerate(formula):
        for p,(i,pos) in enumerate(c):
            row=[0]*col
            for k,bits in zip(clause_cols[j], local_lists[j]):
                if bits[p]==1: row[k]+=1
            row[var_cols[i][1]] -= 1
            rows.append(row); target.append(0); rownames.append(f"c{j}p{p}_cons_v{i}")
    return rows,target,groups,var_cols,clause_cols,local_lists,names,rownames

def matvec(M,z): return [sum(a*b for a,b in zip(r,z)) for r in M]
def l1(z): return sum(abs(x) for x in z)

def encode_witness(n, formula, comp, a):
    M,t,groups,var_cols,clause_cols,local_lists,*_=comp
    z=[0]*len(M[0])
    for i in range(n): z[var_cols[i][a[i]]]=1
    for j,c in enumerate(formula):
        bits=tuple(a[i] for i,_ in c)
        idx=local_lists[j].index(bits)
        z[clause_cols[j][idx]]=1
    return z

def extract_short(n, formula, comp, z):
    M,t,groups,var_cols,clause_cols,local_lists,*_=comp
    # one-hot forced by integer group sums + l1 bound; check syntactically here
    for g in groups:
        if sum(z[k] for k in g)!=1 or sum(abs(z[k]) for k in g)!=1:
            return None
    a=[]
    for i,g in enumerate(var_cols):
        if z[g[0]]==1 and z[g[1]]==0: a.append(0)
        elif z[g[0]]==0 and z[g[1]]==1: a.append(1)
        else: return None
    for j,c in enumerate(formula):
        chosen=[h for h,k in enumerate(clause_cols[j]) if z[k]==1]
        if len(chosen)!=1: return None
        bits=local_lists[j][chosen[0]]
        for p,(i,pos) in enumerate(c):
            if bits[p]!=a[i]: return None
        if not sat_clause(c,a): return None
    return tuple(a)

def gen_l1_vectors(d,B):
    z=[0]*d
    def rec(i,rem):
        if i==d:
            yield tuple(z); return
        for v in range(-rem, rem+1):
            z[i]=v
            yield from rec(i+1, rem-abs(v))
        z[i]=0
    yield from rec(0,B)

# ---- one-hot affine compiler tests ----
formula_sets=[]
# all sign patterns on one 3-variable clause
for signs in itertools.product((False,True), repeat=3):
    formula_sets.append((3,[[(0,signs[0]),(1,signs[1]),(2,signs[2])]],"one_clause"))
# repeated-variable satisfiable and unsatisfiable fixtures
formula_sets += [
 (2,[[(0,True),(1,True),(1,True)]],"repeat_sat"),
 (1,[[(0,True),(0,True),(0,True)],[(0,False),(0,False),(0,False)]],"repeat_unsat")
]
short_solution_count=0
ball_vectors=0
for fi,(n,formula,label) in enumerate(formula_sets):
    comp=build_compiler(n,formula); M,t,groups,*_=comp
    B=n+len(formula); q=2*(B+1)+1
    # every satisfying Boolean assignment encodes to norm exactly B and solves Mz=t
    sats=[]
    for a in itertools.product((0,1), repeat=n):
        if formula_sat(formula,a):
            sats.append(a); z=encode_witness(n,formula,comp,a)
            ok(f"enc_norm_{fi}_{a}", l1(z)==B)
            ok(f"enc_eq_{fi}_{a}", matvec(M,z)==t)
            ok(f"enc_extract_{fi}_{a}", extract_short(n,formula,comp,z)==a)
    # Exhaust all centered integer vectors in l1-ball and all modular short preimages.
    for idx,z in enumerate(gen_l1_vectors(len(M[0]),B)):
        ball_vectors += 1
        mz=matvec(M,z)
        modok=all((x-y)%q==0 for x,y in zip(mz,t))
        if modok:
            short_solution_count += 1
            # q>2(B+1) should force equality over integers.
            ok(f"nowrap_{fi}_{idx}", mz==t,(label,z,mz,t,q))
            a=extract_short(n,formula,comp,z)
            ok(f"extract_{fi}_{idx}", a is not None,(label,z))
            ok(f"sat_{fi}_{idx}", formula_sat(formula,a),(label,a))
    if not sats:
        ok(f"unsat_no_short_{fi}", not any(
            all((x-y)%q==0 for x,y in zip(matvec(M,z),t))
            for z in gen_l1_vectors(len(M[0]),B)
        ))

# Generic proof controls: each group integer sum=1 implies l1>=1, equality iff a basis vector +1.
for width in range(2,9):
    for v in gen_l1_vectors(width,3):
        if sum(v)==1:
            ok(f"group_l1_{width}_{v}", l1(v)>=1)
            if l1(v)==1:
                ok(f"group_onehot_{width}_{v}", sum(1 for x in v if x==1)==1 and all(x in (0,1) for x in v))

# ---- W-W-W correlated matrix same-secret difference attack ----
def centered(x,q):
    x%=q
    return x-q if x>q//2 else x

def gadget(q):
    ell=math.ceil(math.log2(q))
    return [pow(2,j,q) for j in range(ell)]

def gadget_encode_secret(s,q):
    g=gadget(q); out=[]
    for h in s:
        out += [(gg*h)%q for gg in g]
    return out

def decode_gadget_block(obs,q,E):
    g=gadget(q); n=len(obs)//len(g); out=[]
    for i in range(n):
        ys=obs[i*len(g):(i+1)*len(g)]
        candidates=[]
        for h in range(q):
            if all(abs(centered(y-gg*h,q))<=E for y,gg in zip(ys,g)):
                candidates.append(h)
        if len(candidates)!=1:
            return None,candidates
        out.append(candidates[0])
    return out,None

rng=random.Random(117)
gadget_trials=0
for q in (31,61,127,257):
    Ebase=max(1,(q-1)//13) # ensures 2*Ebase < q/6 for these q
    ok(f"noise_radius_{q}",2*Ebase < q/6,(q,Ebase))
    g=gadget(q); ell=len(g); n=3; k=4; blocklen=n*ell
    for trial in range(60):
        s=[rng.randrange(q) for _ in range(n)]
        u=[rng.randrange(2) for _ in range(k)]
        v=u[:]
        # ensure distinct, arbitrary multi-bit delta
        flips=[r for r in range(k) if rng.randrange(2)]
        if not flips: flips=[trial%k]
        for r in flips: v[r]^=1
        base=[rng.randrange(q) for _ in range(k*blocklen)]
        gu=gadget_encode_secret(s,q)
        def tail_sample(label):
            nois=[rng.randint(-Ebase,Ebase) for _ in range(k*blocklen)]
            out=[]
            for r,bit in enumerate(label):
                for j in range(blocklen):
                    val=base[r*blocklen+j]
                    if bit: val-=gu[j]
                    out.append((val+nois[r*blocklen+j])%q)
            return out
        bu=tail_sample(u); bv=tail_sample(v)
        # difference bu-bv on any changed label block is +/- G^T s plus error difference.
        r=flips[0]; sign=(v[r]-u[r]) # bu-bv = (v-u) G^T s + eta
        obs=[(sign*(bu[r*blocklen+j]-bv[r*blocklen+j]))%q for j in range(blocklen)]
        # multiplying by sign makes +G^Ts; noise bound 2Ebase
        dec,_=decode_gadget_block(obs,q,2*Ebase)
        ok(f"gadget_recover_{q}_{trial}", dec==s,(u,v,flips,s,dec,Ebase))
        gadget_trials+=1

# Negative control: independent secrets destroy exact gadget cancellation identity.
independent_control=0
q=127; g=gadget(q); n=2; k=2; bl=n*len(g)
for trial in range(50):
    s1=[rng.randrange(q) for _ in range(n)]; s2=[rng.randrange(q) for _ in range(n)]
    if s1==s2: s2[0]=(s2[0]+1)%q
    # noiseless tails under labels 00 and 10 with same base but independent secrets
    base=[rng.randrange(q) for _ in range(k*bl)]
    e1=gadget_encode_secret(s1,q); e2=gadget_encode_secret(s2,q)
    u=[0,0]; v=[1,0]
    bu=base[:] # label 00
    bv=base[:]
    for j in range(bl): bv[j]=(bv[j]-e2[j])%q
    diff=[(bu[j]-bv[j])%q for j in range(bl)]
    # diff encodes s2, not s1; confirms attack specifically targets shared/common secret relation.
    dec,_=decode_gadget_block(diff,q,0)
    ok(f"indep_control_{trial}",dec==s2 and dec!=s1)
    independent_control+=1

out={
  "run":117,
  "status":"PASS",
  "total_assertions":len(checks),
  "onehot_affine_compiler":{
    "formula_fixtures":len(formula_sets),
    "l1_ball_vectors_checked":ball_vectors,
    "short_modular_solutions_checked":short_solution_count,
    "claim":"For the tested 3CNF one-hot compiler, every centered modular preimage with l1 <= B=n+m and q>2(B+1) unwraps to an integer solution and extracts a satisfying Boolean assignment. The accompanying note gives the general proof."
  },
  "correlated_matrix_attack":{
    "trials":gadget_trials,
    "claim":"For A_i tail B-u_i tensor G and two distinct labels sharing the same secret s, differencing any changed label block yields +/-G^T s plus difference noise. Under per-sample infinity error E with 2E<q/6, powers-of-two gadget decoding recovers s uniquely."
  },
  "independent_secret_control":{
    "trials":independent_control,
    "claim":"With independent secrets the same cancellation produces the secret tied to the changed matrix block rather than a global shared secret; this is a semantic control, not a security proof."
  },
  "scope":[
    "The one-hot compiler is a supplied-short-preimage-to-original-3SAT-witness theorem; it does not make the structured matrix LWE-random.",
    "The correlated-matrix attack targets a naive same-secret use of Waters-Wee-Wu matrices and does not contradict their individual-marginal somewhere-hardness theorem.",
    "No QPT security is inferred from finite checks. The paper's stated SIS/LWE theorem is not silently upgraded from efficient/PPT adversaries to QPT here."
  ]
}
print(json.dumps(out,indent=2,sort_keys=True))
