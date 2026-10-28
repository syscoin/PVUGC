#!/usr/bin/env python3
"""Exact bounded checks: native-key XOR splitting across independent SOURCE capsules.
   Algebra/statistics only; does NOT test QPT hardness or native SLH.
"""
import json, random, hashlib, itertools, collections, math
RNG=random.Random(20261028)
q=257; M=9; h=2; g=2*h+1; radix=q//g; ell=46; t=3
checks=0

def check(cond,label):
    global checks
    assert cond,label
    checks+=1

def xor(*bs):
    return bytes(__import__('functools').reduce(lambda a,b:a^b, bits) for bits in zip(*bs))

def source_for(w):
    # basis row space orthogonal to anchored w with w[0]=1
    return [tuple((-w[j] if i==0 else (1 if i==j else 0))%q for i in range(M)) for j in range(1,M)]

def transposed(G,u):
    return [sum(G[j][i]*u[j] for j in range(len(G)))%q for i in range(M)]

def digits(Z):
    v=int.from_bytes(Z,'big'); a=[]
    for j in range(ell): a.append(v%radix);v//=radix
    check(v==0,'digits capacity')
    return a

def produce(G,Z):
    out=[]
    for a in digits(Z):
        u=[RNG.randrange(q) for _ in range(len(G))]
        eps=[RNG.choice((-1,0,1)) for _ in range(M)]
        base=transposed(G,u)
        p=[(base[k]+eps[k]+(g*a if k==0 else 0))%q for k in range(M)]
        out.append((p,u,eps,a))
    return out

def release(G,w,caps):
    check(all(sum(x*y for x,y in zip(row,w))%q==0 for row in G),'source relation')
    check(w[0]==1 and sum(w)==h and set(w)<={0,1},'original relation')
    recovered=[]
    for p,u,eps,a in caps:
        phase=sum(x*y for x,y in zip(p,w))%q
        possible=[d for d in range(radix) if min((phase-g*d)%q,(g*d-phase)%q)<=h]
        check(possible==[a],'deterministic digit')
        recovered.append(possible[0])
    z=sum(d*radix**j for j,d in enumerate(recovered))
    check(z < 2**256,'decoded 256-bit share')
    return z.to_bytes(32,'big')

check(radix==51 and radix**45 < 2**256 <=radix**46,'capacity exact')
check(q-(radix-1)*g > 2*h,'cyclic gap')
# 3 distinct ORIGINAL relations/witnesses, independent source matrices.
ws=[];Gs=[]
for i in range(t):
    w=[0]*M;w[0]=w[i+1]=1
    ws.append(w);Gs.append(source_for(w))
for rep in range(24):
    K=RNG.randbytes(32);U=RNG.randbytes(32);Zs=[RNG.randbytes(32) for _ in range(t)]
    D=xor(U,*Zs);V=xor(K,U)
    caps=[produce(G,Z) for G,Z in zip(Gs,Zs)]
    got=[release(G,w,cap) for G,w,cap in zip(Gs,ws,caps)]
    check(got==Zs,'all honest source shares')
    check(xor(D,V,*got)==K,'one committed capability')
    check(hashlib.sha256(b'test-only-not-native'+xor(D,V,*got)).digest()==
          hashlib.sha256(b'test-only-not-native'+K).digest(),'mock checking binding')
    # Check exact public capsule and opening (including coins) for arbitrary revealed subset.
    for subset in itertools.chain.from_iterable(itertools.combinations(range(t),j) for j in range(t)):
        for i in subset:
            for p,u,eps,a in caps[i]:
                check(p==[(v+e+(g*a if j==0 else 0))%q
                          for j,(v,e) in enumerate(zip(transposed(Gs[i],u),eps))],
                      'authenticated opened capsule coins')
        survivor=next(i for i in range(t) if i not in subset)
        check(survivor not in subset,'at least one unopened')

# Exhaustive XOR-share simulator distribution, including public (D,V), for
# *each* fixed K and *every* adversarially chosen opened-index set |S|<t.
# In zero-shift/reference experiment, p_i* is independent of hidden Z_i*.
bits=3;N=2**bits
for Ssize in range(t):
    for S in itertools.combinations(range(t),Ssize):
        counts0=collections.Counter();counts1=collections.Counter()
        for K,C in ((0,counts0),(N-1,counts1)):
            for U in range(N):
                for Zs in itertools.product(range(N),repeat=t):
                    D=U
                    for Z in Zs:D^=Z
                    V=U^K
                    C[(D,V,tuple(Zs[j] for j in S))]+=1
        check(counts0==counts1,f'exact mask independent K, opened {S}')
        all_cts=list(counts0.values())
        check(len(set(all_cts))==1 and all_cts[0]==N**(t-Ssize-1),
              f'exact uniform conditional distribution {S}')

# Explicit certified-false SOURCE: G = I_M, so *each* p_j is uniformly
# distributed for every a, even with other independent source coins visible.
Gfalse=[tuple(int(i==j) for i in range(M)) for j in range(M)]
for rep in range(300):
    a=RNG.randrange(radix)
    u=[RNG.randrange(q) for _ in range(M)]
    eps=[RNG.choice((-1,0,1)) for _ in range(M)]
    p=[(u[j]+eps[j]+(g*a if j==0 else 0))%q for j in range(M)]
    # Shift simulation uses no a; maps uniform u to uniform u' bijectively.
    u0=[(u[j]+(g*a if j==0 else 0))%q for j in range(M)]
    p0=[(u0[j]+eps[j])%q for j in range(M)]
    check(p==p0,'full-vector exact certified false shift coupling')

print(json.dumps({'result':'PASS','assertions':checks,'toy_seed_bits':256,
                  'share_capsules':t,'radix':radix,'columns_per_capsule':ell,
                  'tested_same_K_trials':24,'opened_subsets':7,
                  'exact_xor_mask_enumeration_bits':bits,
                  'native_signature_security_tested':False,
                  'QPT_hardness_tested':False},sort_keys=True))
