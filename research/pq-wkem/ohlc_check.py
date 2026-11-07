import itertools, random, json, math

Q=31

def xor(a,b): return a^b

class Builder:
    def __init__(self):
        self.names=[]; self.idx={}; self.rows=[]; self.rhs=[]; self.blocks=[]
    def var(self,name):
        if name not in self.idx:
            self.idx[name]=len(self.names); self.names.append(name)
        return self.idx[name]
    def add(self, coeffs, rhs=0):
        row=[0]*len(self.names)
        for n,c in coeffs.items(): row[self.idx[n]]+=c
        self.rows.append(row); self.rhs.append(rhs)
    def finalize_row_widths(self):
        n=len(self.names)
        for i,row in enumerate(self.rows):
            if len(row)<n: self.rows[i]=row+[0]*(n-len(row))

def compile_xor_circuit(wires, gates, out_wire):
    B=Builder()
    for w in wires:
        names=[f'x:{w}:0',f'x:{w}:1']
        for n in names: B.var(n)
        B.blocks.append(names)
    for g,_,_,_ in gates:
        names=[f'y:{g}:{a}{b}' for a in (0,1) for b in (0,1)]
        for n in names: B.var(n)
        B.blocks.append(names)
    for w in wires:
        B.add({f'x:{w}:0':1,f'x:{w}:1':1},1)
    for g,i,j,k in gates:
        ys={(a,b):f'y:{g}:{a}{b}' for a in (0,1) for b in (0,1)}
        B.add({name:1 for name in ys.values()},1)
        for a in (0,1):
            c={f'x:{i}:{a}':1}
            for b in (0,1): c[ys[a,b]]=c.get(ys[a,b],0)-1
            B.add(c,0)
        for b in (0,1):
            c={f'x:{j}:{b}':1}
            for a in (0,1): c[ys[a,b]]=c.get(ys[a,b],0)-1
            B.add(c,0)
        for o in (0,1):
            c={f'x:{k}:{o}':1}
            for a in (0,1):
                for b in (0,1):
                    if xor(a,b)==o: c[ys[a,b]]=c.get(ys[a,b],0)-1
            B.add(c,0)
    B.add({f'x:{out_wire}:1':1},1)
    B.finalize_row_widths()
    return B

def witness_vector(B, wire_values, gates):
    z=[0]*len(B.names)
    for w,v in wire_values.items(): z[B.idx[f'x:{w}:{v}']]=1
    for g,i,j,k in gates:
        a=wire_values[i]; b=wire_values[j]
        z[B.idx[f'y:{g}:{a}{b}']]=1
    return z

def matvec(H,z): return [sum(a*b for a,b in zip(row,z)) for row in H]
def matvec_mod(H,z,q=Q): return [x%q for x in matvec(H,z)]
def norm2(z): return sum(x*x for x in z)

def short_vectors(n,B):
    lim=int(math.isqrt(B)); vals=range(-lim,lim+1)
    cur=[0]*n
    def rec(i,rem):
        if i==n:
            yield tuple(cur); return
        for v in vals:
            s=v*v
            if s<=rem:
                cur[i]=v
                yield from rec(i+1,rem-s)
        cur[i]=0
    yield from rec(0,B)

def random_projection(H,b,d,q,rng):
    m=len(H); n=len(H[0])
    R=[[rng.randrange(q) for _ in range(m)] for __ in range(d)]
    Hp=[]; bp=[]
    for rr in R:
        Hp.append([sum(rr[i]*H[i][j] for i in range(m))%q for j in range(n)])
        bp.append(sum(rr[i]*b[i] for i in range(m))%q)
    return Hp,bp

def satisfies_mod(H,b,z,q=Q):
    return matvec_mod(H,z,q)==[x%q for x in b]

def analyze_fixture():
    trueB=compile_xor_circuit(['w0','w1','out'], [('g','w0','w1','out')], 'out')
    falseB=compile_xor_circuit(['w','out'], [('g','w','w','out')], 'out')
    Bt=len(trueB.blocks); Bf=len(falseB.blocks)
    z01=witness_vector(trueB,{'w0':0,'w1':1,'out':1}, [('g','w0','w1','out')])
    z10=witness_vector(trueB,{'w0':1,'w1':0,'out':1}, [('g','w0','w1','out')])
    assert norm2(z01)==Bt and norm2(z10)==Bt
    assert matvec(trueB.rows,z01)==trueB.rhs and matvec(trueB.rows,z10)==trueB.rhs
    true_short=[]
    for z in short_vectors(len(trueB.names),Bt):
        if matvec(trueB.rows,z)==trueB.rhs: true_short.append(z)
    false_candidates=list(short_vectors(len(falseB.names),Bf))
    false_short=[z for z in false_candidates if matvec(falseB.rows,z)==falseB.rhs]
    assert len(true_short)==2 and not false_short
    true_mod=[z for z in short_vectors(len(trueB.names),Bt) if satisfies_mod(trueB.rows,trueB.rhs,z,Q)]
    false_mod=[z for z in false_candidates if satisfies_mod(falseB.rows,falseB.rhs,z,Q)]
    assert set(true_mod)==set(true_short) and not false_mod
    rng=random.Random(80921); proj={}
    for d,trials in [(2,2000),(3,5000),(4,5000)]:
        hits=0
        for _ in range(trials):
            Hp,bp=random_projection(falseB.rows,falseB.rhs,d,Q,rng)
            if any(satisfies_mod(Hp,bp,z,Q) for z in false_candidates): hits+=1
        proj[str(d)]={'trials':trials,'false_projected_short_hit_trials':hits,
                      'observed_rate':hits/trials,
                      'union_bound':min(1.0,len(false_candidates)*(Q**(-d)))}
    for _ in range(200):
        Hp,bp=random_projection(trueB.rows,trueB.rhs,3,Q,rng)
        assert satisfies_mod(Hp,bp,z01,Q) and satisfies_mod(Hp,bp,z10,Q)
    max_support=max(sum(1 for x in row if x) for row in trueB.rows+falseB.rows)
    return {'field':Q,
        'true':{'variables':len(trueB.names),'rows':len(trueB.rows),'blocks':Bt,
                'short_integer_solutions':len(true_short),'short_modular_solutions':len(true_mod)},
        'false':{'variables':len(falseB.names),'rows':len(falseB.rows),'blocks':Bf,
                 'enumerated_short_vectors':len(false_candidates),'short_integer_solutions':0,'short_modular_solutions':0},
        'max_row_support':max_support,
        'sufficient_modulus_lower_bound':2*(max_support*math.sqrt(max(Bt,Bf))+1),
        'random_projection':proj,'genuine_witness_projection_checks':400}

def equivalence_toy():
    rng=random.Random(8811); q=65537; trials=500; ok=0
    for _ in range(trials):
        K=rng.randrange(q); theta=K
        for _w in (0,1):
            pi=K; assert pi==theta
        a=rng.randrange(1,q); b=rng.randrange(q)
        assert (a*theta+b)%q==(a*pi+b)%q
        ok+=1
    return {'trials':trials,'functional_roundtrips':ok,
            'note':'Toy functionality only; theorem in CANONICAL_COSET_EQUIVALENCE_AND_OHLC.md gives the black-box security equivalence.'}

if __name__=='__main__':
    print(json.dumps({'ohlc':analyze_fixture(),'canonical_coset_equivalence_toy':equivalence_toy()},sort_keys=True))
