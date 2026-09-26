import itertools, random, json
from collections import Counter

def rref(A,q):
    A=[[x%q for x in row] for row in A]
    if not A: return A,[]
    m,n=len(A),len(A[0]); r=0; piv=[]
    for c in range(n):
        p=next((i for i in range(r,m) if A[i][c]),None)
        if p is None: continue
        A[r],A[p]=A[p],A[r]
        s=pow(A[r][c],-1,q); A[r]=[(s*x)%q for x in A[r]]
        for i in range(m):
            if i!=r and A[i][c]:
                f=A[i][c]
                A[i]=[(A[i][j]-f*A[r][j])%q for j in range(n)]
        piv.append(c); r+=1
        if r==m: break
    return A,piv

def rank(A,q): return len(rref(A,q)[1])
def in_span(rows,t,q): return rank(rows,q)==rank(rows+[t],q)

def has_path(layers,edges):
    reach={layers[0][0]}
    for ed in edges:
        reach={v for u,v in ed if u in reach}
    return layers[-1][0] in reach

def flow_matrix(layers,edges,q):
    L=len(layers)-1
    s=layers[0][0]; t=layers[-1][0]
    vertices=[v for layer in layers for v in layer]
    pads=[v for v in vertices if v not in (s,t)]
    pidx={v:L+i for i,v in enumerate(pads)}
    rows=[]; edge_order=[]
    for i in range(L):
        for u,v in edges[i]:
            row=[0]*(L+len(pads)); row[i]=1
            if u in pidx: row[pidx[u]]=(row[pidx[u]]+1)%q
            if v in pidx: row[pidx[v]]=(row[pidx[v]]-1)%q
            rows.append(row); edge_order.append((u,v))
    target=[1]*L+[0]*len(pads)
    return rows,target,edge_order,pads

def false_dag_control():
    layers=[[0],[1,2],[3,4],[5]]
    edges=[[(0,1)],[(1,3),(2,3),(2,4)],[(4,5)]]
    assert not has_path(layers,edges)
    coeff_int=[1,1,-1,1,1]
    details={}
    for q in (2,3,5,101):
        rows,t,order,pads=flow_matrix(layers,edges,q)
        coeff=[c%q for c in coeff_int]
        combined=[sum(coeff[i]*rows[i][j] for i in range(len(rows)))%q
                  for j in range(len(t))]
        assert combined==t
        assert in_span(rows,t,q)
        details[str(q)]={"edge_order":order,"coefficients":coeff,"target_in_span":True}
    q=3; rows,t,order,pads=flow_matrix(layers,edges,q); L=3
    coeff=[c%q for c in coeff_int]
    samples=0
    for k0,k1 in itertools.product(range(q),repeat=2):
        for K in range(q):
            ks=[k0,k1,(K-k0-k1)%q]
            for pv in itertools.product(range(q),repeat=len(pads)):
                x=ks+list(pv)
                out=[sum(a*b for a,b in zip(row,x))%q for row in rows]
                rec=sum(c*y for c,y in zip(coeff,out))%q
                assert rec==K
                samples+=1
    return {"no_path":True,"fields":details,"exhaustive_F3_transcripts":samples}

pairs=[(0,0),(0,1),(1,0),(1,1)]
def cycle_rows(rels,q):
    n=len(rels); rows=[]
    for i,rel in enumerate(rels):
        for idx in rel:
            a,b=pairs[idx]
            row=[0]*(3*n); row[i]=1
            row[n+2*i+a]=(row[n+2*i+a]+1)%q
            j=(i+1)%n
            row[n+2*j+b]=(row[n+2*j+b]-1)%q
            rows.append(row)
    return rows,[1]*n+[0]*(2*n)

def sat_cycle(rels):
    n=len(rels)
    allowed=[{pairs[j] for j in rel} for rel in rels]
    for x in itertools.product((0,1),repeat=n):
        if all((x[i],x[(i+1)%n]) in allowed[i] for i in range(n)):
            return True
    return False

def odd_cycle_trials():
    q=101; inv2=pow(2,-1,q); rng=random.Random(16002); out={}
    for n in (3,5,7,9):
        rels=[{1,2} for _ in range(n)]
        assert not sat_cycle(rels)
        rows,t=cycle_rows(rels,q); assert in_span(rows,t,q)
        for _ in range(100):
            ks=[rng.randrange(q) for _ in range(n)]
            pads=[[rng.randrange(q),rng.randrange(q)] for _ in range(n)]
            vals=[]
            for i in range(n):
                j=(i+1)%n
                vals.append((ks[i]+pads[i][0]-pads[j][1])%q)
                vals.append((ks[i]+pads[i][1]-pads[j][0])%q)
            rec=inv2*sum(vals)%q
            assert rec==sum(ks)%q
        out[str(n)]={"fresh_trials":100,"false":True,"target_in_span":True}
    return out

def triangle_census():
    q=101
    c={"total":0,"sat":0,"unsat":0,"target_in_span":0,
       "unsat_leaky":0,"unsat_nonleaky":0}
    for masks in itertools.product(range(16),repeat=3):
        rels=[{j for j in range(4) if (m>>j)&1} for m in masks]
        sat=sat_cycle(rels)
        rows,t=cycle_rows(rels,q); leak=in_span(rows,t,q)
        c["total"]+=1;c["sat"]+=int(sat);c["unsat"]+=int(not sat)
        c["target_in_span"]+=int(leak)
        if not sat and leak:c["unsat_leaky"]+=1
        if not sat and not leak:c["unsat_nonleaky"]+=1
        if sat: assert leak
    expected={"total":4096,"sat":2397,"unsat":1699,"target_in_span":2557,
              "unsat_leaky":160,"unsat_nonleaky":1539}
    assert c==expected,(c,expected)
    return c

def mac_kernel_trials():
    rng=random.Random(16003);q=7;checked=0
    for _ in range(500):
        nx=4;dims=[3,2,3]
        Ls=[[[rng.randrange(q) for _ in range(nx)] for _ in range(d)] for d in dims]
        Phi=[row for L in Ls for row in L]
        PT=[list(col) for col in zip(*Phi)]
        R,piv=rref(PT,q);n=len(Phi);free=[j for j in range(n) if j not in piv]
        if not free: continue
        g=[0]*n
        for f in free:g[f]=rng.randrange(q)
        for i,c in enumerate(piv):
            g[c]=(-sum(R[i][f]*g[f] for f in free))%q
        assert all(sum(Phi[r][j]*g[r] for r in range(n))%q==0 for j in range(nx))
        x=[rng.randrange(q) for _ in range(nx)]
        off=0;tot=0
        for L,d in zip(Ls,dims):
            z=[sum(row[j]*x[j] for j in range(nx))%q for row in L]
            gj=g[off:off+d];off+=d
            tot=(tot+sum(a*b for a,b in zip(gj,z)))%q
        assert tot==0
        checked+=1
    return checked

out={
  "status":"PASS",
  "linear_mac_kernel_trials":mac_kernel_trials(),
  "false_layered_dag":false_dag_control(),
  "odd_cycle_false_recovery":odd_cycle_trials(),
  "triangle_csp_census":triangle_census(),
}
print(json.dumps(out,indent=2,sort_keys=True))
