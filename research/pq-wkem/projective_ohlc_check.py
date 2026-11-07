import itertools, random, json, math, cmath

def xor(a,b): return a^b
def OR(a,b): return a|b
OPS={'XOR':xor,'OR':OR}

class Builder:
    def __init__(self):
        self.names=[]; self.idx={}; self.rows=[]; self.rhs=[]; self.blocks=[]
    def var(self,name):
        if name not in self.idx:
            self.idx[name]=len(self.names); self.names.append(name)
        return self.idx[name]
    def add(self,coeffs,rhs=0):
        row=[0]*len(self.names)
        for n,c in coeffs.items(): row[self.idx[n]]+=c
        self.rows.append(row); self.rhs.append(rhs)
    def finalize(self):
        n=len(self.names)
        for i,row in enumerate(self.rows):
            if len(row)<n:self.rows[i]=row+[0]*(n-len(row))

def compile_circuit(wires,gates,out_wire):
    B=Builder()
    for w in wires:
        ns=[f'x:{w}:0',f'x:{w}:1']
        for n in ns:B.var(n)
        B.blocks.append(ns)
    for g,op,i,j,k in gates:
        ns=[f'y:{g}:{a}{b}' for a in (0,1) for b in (0,1)]
        for n in ns:B.var(n)
        B.blocks.append(ns)
    for w in wires:B.add({f'x:{w}:0':1,f'x:{w}:1':1},1)
    for g,op,i,j,k in gates:
        ys={(a,b):f'y:{g}:{a}{b}' for a in (0,1) for b in (0,1)}
        B.add({n:1 for n in ys.values()},1)
        for a in (0,1):
            c={f'x:{i}:{a}':1}
            for bb in (0,1):c[ys[a,bb]]=c.get(ys[a,bb],0)-1
            B.add(c)
        for bb in (0,1):
            c={f'x:{j}:{bb}':1}
            for a in (0,1):c[ys[a,bb]]=c.get(ys[a,bb],0)-1
            B.add(c)
        f=OPS[op]
        for o in (0,1):
            c={f'x:{k}:{o}':1}
            for a in (0,1):
                for bb in (0,1):
                    if f(a,bb)==o:c[ys[a,bb]]=c.get(ys[a,bb],0)-1
            B.add(c)
    B.add({f'x:{out_wire}:1':1},1)
    B.finalize()
    return B

def witness_vector(B,wire_values,gates):
    z=[0]*len(B.names)
    for w,v in wire_values.items():z[B.idx[f'x:{w}:{v}']]=1
    for g,op,i,j,k in gates:
        a=wire_values[i]; b=wire_values[j]
        z[B.idx[f'y:{g}:{a}{b}']]=1
    return z

def mv(H,z,mod=None):
    ans=[sum(a*b for a,b in zip(row,z)) for row in H]
    return [x%mod for x in ans] if mod else ans

def t_mv(A,s,q):
    return [sum(A[i][j]*s[i] for i in range(len(A)))%q for j in range(len(A[0]))]

def project(H,b,d,q,rng):
    m=len(H); n=len(H[0])
    R=[[rng.randrange(q) for _ in range(m)] for __ in range(d)]
    A=[[sum(R[i][k]*H[k][j] for k in range(m))%q for j in range(n)] for i in range(d)]
    bp=[sum(R[i][k]*b[k] for k in range(m))%q for i in range(d)]
    return R,A,bp

def circdist(a,b,q):
    x=(a-b)%q
    return min(x,q-x)

def false_projective_fixture():
    wires=['w0','w1','w2','w3']
    gates=[('g0','OR','w1','w1','w2'),('g1','XOR','w1','w2','w3')]
    B=compile_circuit(wires,gates,'w3')
    assert all((b ^ (b|b))==0 for b in (0,1))
    t=3
    a=[0]*len(B.names)
    p={'w0':1,'w1':1,'w2':2,'w3':3}
    for w in wires:
        a[B.idx[f'x:{w}:0']]=t-p[w]
        a[B.idx[f'x:{w}:1']]=p[w]
    for g,vals in [('g0',(1,1,1,0)),('g1',(0,2,1,0))]:
        for (x,y),v in zip(itertools.product((0,1),(0,1)),vals):
            a[B.idx[f'y:{g}:{x}{y}']]=v
    assert mv(B.rows,a)==[t*x for x in B.rhs]
    assert len(B.blocks)==6 and sum(x*x for x in a)==32 and sum(abs(x) for x in a)==18
    rng=random.Random(90120)
    for _ in range(200):
        _,A,bp=project(B.rows,B.rhs,5,65536,rng)
        assert mv(A,a,65536)==[(t*x)%65536 for x in bp]
    return B,a,t

def direct_capsule_attack(B,a,t):
    rng=random.Random(90123)
    q=65536; delta=q//2; d=5; E=1; trials=2000; ok=0; maxnoise=0
    for _ in range(trials):
        _,A,bp=project(B.rows,B.rhs,d,q,rng)
        s=[rng.randrange(q) for __ in range(d)]
        e=[rng.randint(-E,E) for __ in B.names]; e0=rng.randint(-E,E)
        k=rng.randrange(2)
        c=[(x+ee)%q for x,ee in zip(t_mv(A,s,q),e)]
        dd=(sum(bp[i]*s[i] for i in range(d))+e0+delta*k)%q
        r=(t*dd-sum(x*y for x,y in zip(a,c)))%q
        centers=[0,(t*delta)%q]
        guess=min((0,1),key=lambda kk:circdist(r,centers[kk],q))
        ok += guess==k
        raw=t*e0-sum(x*y for x,y in zip(a,e))
        maxnoise=max(maxnoise,abs(raw))
        assert r==(centers[k]+raw)%q
    assert ok==trials
    bound=E*(abs(t)+sum(abs(x) for x in a))
    assert maxnoise<=bound==21
    return {'q':q,'delta':delta,'error_bound':E,'trials':trials,
            'key_recoveries':ok,'maximum_observed_raw_noise':maxnoise,
            'proved_absolute_noise_bound':bound,
            'center_distance':q//2}

def true_control():
    wires=['w0','w1','out']
    gates=[('g','XOR','w0','w1','out')]
    B=compile_circuit(wires,gates,'out')
    z=witness_vector(B,{'w0':0,'w1':1,'out':1},gates)
    assert mv(B.rows,z)==B.rhs and sum(z)==len(B.blocks)==4
    rng=random.Random(90124); q=65536; delta=q//2; E=1; d=5; trials=1000; ok=0
    for _ in range(trials):
        _,A,bp=project(B.rows,B.rhs,d,q,rng)
        s=[rng.randrange(q) for __ in range(d)]
        e=[rng.randint(-E,E) for __ in B.names]; e0=rng.randint(-E,E)
        k=rng.randrange(2)
        c=[(x+ee)%q for x,ee in zip(t_mv(A,s,q),e)]
        dd=(sum(bp[i]*s[i] for i in range(d))+e0+delta*k)%q
        r=(dd-sum(x*y for x,y in zip(z,c)))%q
        guess=min((0,1),key=lambda kk:circdist(r,delta*kk,q))
        ok+=guess==k
    assert ok==trials
    return {'blocks':len(B.blocks),'trials':trials,'key_recoveries':ok}

def fourier_single_capsule():
    q=8; delta=4
    A=[[1,2]]; b=[3]
    errors=[-1,0,1]
    omega=cmath.exp(2j*math.pi/q)
    def empirical(z0,z1,t,k):
        acc=0j; total=0
        for s in range(q):
            for e0 in errors:
                for e1 in errors:
                    for ed in errors:
                        c0=(s+e0)%q; c1=(2*s+e1)%q
                        dd=(3*s+ed+delta*k)%q
                        acc += omega**((z0*c0+z1*c1+t*dd)%q); total+=1
        return acc/total
    def nh(z0,z1,t):
        vals=[]
        for coeff in (z0,z1,t):
            vals.append(sum(omega**((coeff*e)%q) for e in errors)/len(errors))
        return vals[0]*vals[1]*vals[2]
    checks=0; maxerr=0.0
    for z0,z1,t,k in itertools.product(range(q),range(q),range(q),(0,1)):
        got=empirical(z0,z1,t,k)
        dual=((z0+2*z1+3*t)%q)==0
        want=(nh(z0,z1,t)*(omega**((t*delta*k)%q))) if dual else 0j
        maxerr=max(maxerr,abs(got-want)); checks+=1
    assert maxerr<1e-10
    return {'group_modulus':q,'character_checks':checks,'max_complex_error':maxerr}

def xor_share_phase():
    q=8; delta=4; omega=cmath.exp(2j*math.pi/q); L=3
    checked=0
    for ts in itertools.product(range(q),repeat=L):
        vals={}
        for K in (0,1):
            ss=[]
            for bits in itertools.product((0,1),repeat=L):
                if (sum(bits)%2)==K:
                    ss.append(omega**(sum(ts[i]*delta*bits[i] for i in range(L))%q))
            vals[K]=sum(ss)/len(ss)
        pars=[t%2 for t in ts]
        if len(set(pars))>1:
            assert abs(vals[0])<1e-10 and abs(vals[1])<1e-10
        elif pars[0]==0:
            assert abs(vals[0]-1)<1e-10 and abs(vals[1]-1)<1e-10
        else:
            assert abs(vals[0]-1)<1e-10 and abs(vals[1]+1)<1e-10
        checked+=1
    return {'modulus':q,'shares':L,'frequency_tuples_checked':checked}

def projective_block_lower_bound():
    def mk(t,k):
        a=abs(t)
        u,r=divmod(a,k)
        return r*(u+1)**2+(k-r)*u**2
    vals={}
    for t in range(1,10):
        vals[str(t)]={'wire_block_min_norm2':mk(t,2),'gate_block_min_norm2':mk(t,4)}
    return vals

if __name__=='__main__':
    B,a,t=false_projective_fixture()
    out={'false_fixture':{
             'blocks':len(B.blocks),'variables':len(B.names),'rows':len(B.rows),
             'scale':t,'scaled_vector_norm2':sum(x*x for x in a),
             'scaled_vector_l1':sum(abs(x) for x in a),
             'ideal_scaled_onehot_norm2':t*t*len(B.blocks)},
         'direct_false_key_attack':direct_capsule_attack(B,a,t),
         'true_control':true_control(),
         'fourier_single_capsule':fourier_single_capsule(),
         'xor_share_phase':xor_share_phase(),
         'block_lower_bounds':projective_block_lower_bound()}
    print(json.dumps(out,sort_keys=True))
