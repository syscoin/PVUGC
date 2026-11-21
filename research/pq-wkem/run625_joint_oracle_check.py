#!/usr/bin/env python3
"""Run625: multi-capsule coherent query hybrid + correlated key counterexample.
Deterministic standard-library exact finite statevector checks. Not a PQ WKEM.
"""
import cmath, math, random, hashlib, json

N=5 # qubits 0 capsule-index i, 1 witness selector z, 2-3 response bits, 4 advice
SIZE=1<<N
Q_MASK=(1<<0)|(1<<1)
TARGET=1
VALID=lambda i,z:(z==1) if i==TARGET else (z==0)
KEYS=(1,0)

def oracle(vec, include_target):
    out=[0j]*SIZE
    for index, amplitude in enumerate(vec):
        i=index&1
        z=(index>>1)&1
        valid=VALID(i,z) and (i!=TARGET or include_target)
        new=index ^ ((2|KEYS[i])<<2 if valid else 0)
        out[new]+=amplitude
    return out

def gate_single(vec, bit, kind):
    out=vec[:]
    for j in range(SIZE):
        if j&(1<<bit): continue
        k=j|(1<<bit)
        a,b=vec[j],vec[k]
        if kind=='H': out[j]=(a+b)/math.sqrt(2);out[k]=(a-b)/math.sqrt(2)
        if kind=='X': out[j]=b;out[k]=a
        if kind=='S': out[j]=a;out[k]=1j*b
        if kind=='Z': out[j]=a;out[k]=-b
    return out

def gate_two(vec,control,target):
    out=[0j]*SIZE
    for j,a in enumerate(vec):
        jj=j^ (1<<target) if ((j>>control)&1) else j
        out[jj]+=a
    return out

def gates(vec,recipe):
    for name,a,b in recipe:
        if name=='CNOT': vec=gate_two(vec,a,b)
        else: vec=gate_single(vec,a,name)
    return vec

def pmass(vec):return sum(abs(x)**2 for x in vec)
def success(vec):
    # exact target reply marker 1 and target key K_B=0 in response bits 2:3
    return sum(abs(v)**2 for j,v in enumerate(vec) if ((j>>2)&3)==(2|KEYS[TARGET]))

def extract_mass(vec):
    return sum(abs(v)**2 for j,v in enumerate(vec) if (j&1)==TARGET and ((j>>1)&1)==1)

def trial(seed,q):
    rng=random.Random(seed)
    choices=('H','X','S','Z','CNOT')
    def recipe(length):
        result=[]
        for _ in range(length):
            name=rng.choice(choices);a=rng.randrange(N)
            b=(a+1+rng.randrange(N-1))%N if name=='CNOT' else 0
            result.append((name,a,b))
        return result
    prep=recipe(4+seed%4)
    rounds=[recipe(2+(seed+j)%5) for j in range(q)]
    finish=recipe(4+seed%5)
    start=[0j]*SIZE;start[rng.randrange(SIZE)]=1+0j
    # Initial prep may entangle advice qubit. Both experiments share same state.
    init=gates(start,prep)
    real=init[:];empty=init[:];mus=[]
    for j in range(q):
        real=gates(real,rounds[j]);empty=gates(empty,rounds[j])
        mu=extract_mass(empty);mus.append(mu)
        real=oracle(real,True);empty=oracle(empty,False)
    real=gates(real,finish);empty=gates(empty,finish)
    assert abs(pmass(real)-1)<2e-12
    assert abs(pmass(empty)-1)<2e-12
    eps,p0=success(real),success(empty)
    delta=abs(eps-p0)
    mean=sum(mus)/q
    assert delta<=2*sum(math.sqrt(v) for v in mus)+1e-10
    assert mean+1e-10>=delta*delta/(4*q*q)
    return delta,mean,eps,p0

if __name__=='__main__':
    checked=0
    nonzero=0; min_slack=1.0; max_gap=0
    for q in (1,2,3,4):
        for seed in range(320):
            delta,mean,eps,p0=trial(seed,q)
            checked+=2
            if delta>1e-9: nonzero+=1
            min_slack=min(min_slack,mean-delta*delta/(4*q*q))
            max_gap=max(max_gap,delta)
    # A false and B valid too? Case A true and B false is the linked-key negative control.
    # For the latter the B release oracle never opens, yet A opens K_A.
    n=400
    for z in range(n):
        seed=hashlib.sha256(b'Run625 honest K_A'+z.to_bytes(2,'big')).digest()
        delta=hashlib.sha256(b'Run625 public delta'+z.to_bytes(2,'big')).digest()
        key_b=bytes(a^b for a,b in zip(seed,delta))
        # hypothetical public native verifier (toy hash, NOT native signatures)
        pk_b=hashlib.sha256(b'RUN625_TOY_NATIVE_PK'+key_b).digest()
        known_a=seed # obtained using one valid A ORIGINAL witness
        extracted_b=bytes(a^b for a,b in zip(known_a,delta))
        assert hashlib.sha256(b'RUN625_TOY_NATIVE_PK'+extracted_b).digest()==pk_b
        assert extracted_b==key_b
        # Even without any access to oracle for B (false statement), success is 1.
        checked+=2
    result={"run":625,"model":"two-index coherent XOR-release oracle, 5 qubits incl advice","q_range":[1,2,3,4],"coherent_fixtures":1280,"coherent_nonzero_gaps":nonzero,"max_gap":round(max_gap,12),"minimum_extraction_bound_slack":round(min_slack,12),"counted_assertions":checked,"cross_capsule_related_key_false_B_leaks":400,"classical_hash":"SHA256 toy public checker only","hardware":"none","real_WKEM":"unproved"}
    print(json.dumps(result,indent=2,sort_keys=True))
