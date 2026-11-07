#!/usr/bin/env python3
"""Offline bounded algebraic checks for MINK-EVC-20261102.
This is NOT a security proof or hardness estimate.
"""
import itertools, json, math, random, hashlib

SEED=0x4D494E4B455643
rng=random.Random(SEED)
checks=0

def check(test, note=''):
    global checks
    assert test, note
    checks+=1

def dot(A,r,q):
    return [sum(x*y for x,y in zip(row,r))%q for row in A]

def add(a,b,q):return [(x+y)%q for x,y in zip(a,b)]

def matvec(U,M,q):return [sum(U[i][j]*M[j] for j in range(len(M)))%q for i in range(len(U))]

# Simulator mode U=A R, with A uniform, R binary, and r opening from wide cube.
q,n,m,k,B0=101,3,13,4,20
for case in range(160):
    A=[[rng.randrange(q) for j in range(m)] for i in range(n)]
    R=[[rng.randrange(2) for j in range(k)] for i in range(m)]
    U=[[sum(A[i][t]*R[t][j] for t in range(m))%q for j in range(k)] for i in range(n)]
    r0=[rng.randint(-B0,B0) for i in range(m)]
    C=dot(A,r0,q)
    for M in itertools.product((0,1), repeat=k):
        rM=[r0[i]-sum(R[i][j]*M[j] for j in range(k)) for i in range(m)]
        check(max(abs(x) for x in rM)<=B0+k,'bound')
        check(add(dot(A,rM,q),matvec(U,M,q),q)==C,'equivocation')
        check(len(rM)==m,'length')

# A two-opening collision is a direct, nonzero short SIS vector in [A|U].
for case in range(200):
    A=[[rng.randrange(q) for j in range(m)] for i in range(n)]
    R=[[rng.randrange(2) for j in range(k)] for i in range(m)]
    U=[[sum(A[i][t]*R[t][j] for t in range(m))%q for j in range(k)] for i in range(n)]
    base_r=[rng.randint(-B0,B0) for j in range(m)]
    M=(0,0,0,0)
    M2=(0,1,0,1)
    r2=[base_r[i]-R[i][1]-R[i][3] for i in range(m)]
    check(add(dot(A,base_r,q),matvec(U,M,q),q)==add(dot(A,r2,q),matvec(U,M2,q),q),'dual openings')
    v=[base_r[i]-r2[i] for i in range(m)]+[a-b for a,b in zip(M,M2)]
    check(any(v),'nonzero')
    check(all(abs(x)<=2*(B0+k) for x in v),'short')
    AU=[A[i]+U[i] for i in range(n)]
    check(dot(AU,v,q)==[0]*n,'SIS kernel')


# Fixed SHA-384 digest reduces commitment message dimension from arbitrary long
# setup transcript/CRS share to k=384 public binary coordinates.
import hashlib

def manifest_bits(x):
    x=bytes(x)
    wire=b"MINK-EVC-v1\x00"+len(x).to_bytes(8,"big")+x
    h=hashlib.sha384(wire).digest()
    return tuple((byte>>j)&1 for byte in h for j in range(8))

hash_fixtures=64
kh=384
for case in range(hash_fixtures):
    A=[[rng.randrange(q) for _ in range(m)] for _ in range(n)]
    R=[[rng.randrange(2) for _ in range(kh)] for _ in range(m)]
    U=[[sum(A[i][t]*R[t][j] for t in range(m))%q for j in range(kh)] for i in range(n)]
    r0=[rng.randrange(-B0,B0+1) for _ in range(m)]
    C=dot(A,r0,q)
    for msg in (b"",b"crs"+case.to_bytes(2,"big"),bytes([case])*8192):
        h=manifest_bits(msg)
        rr=[r0[i]-sum(R[i][j]*h[j] for j in range(kh)) for i in range(m)]
        check(len(h)==kh,'SHA384 bitlength')
        check(max(abs(x) for x in rr)<=B0+kh,'SHA384 bound')
        check(add(dot(A,rr,q),matvec(U,h,q),q)==C,'SHA384 commitment equivocation')
        check(manifest_bits(msg)==h,'manifest deterministic')
    check(manifest_bits(b"a")!=manifest_bits(b"a\x00"),'length framing differs')

# Exact TV for one coordinate: uniform interval versus translate.
Q=21
for shift in range(0,21):
    x=set(range(Q))
    y=set(range(shift,shift+Q))
    tv=1-len(x&y)/Q
    check(abs(tv-shift/Q)<1e-12,'exact shift TV')

# Exact distribution of AR versus a uniform public U for small full families.
# Uniform A in F_3^{1 x 7}; independent uniform binary R in {0,1}^7.
q0,m0=3,7
s=0.0
for A in itertools.product(range(q0),repeat=m0):
    counts=[0]*q0
    for R in itertools.product(range(2),repeat=m0):
        counts[sum(a*r for a,r in zip(A,R))%q0]+=1
    tv=0.5*sum(abs(count/(2**m0)-1/q0) for count in counts)
    s+=tv
    check(0<=tv<=1,'TV range')
exact_tv=s/(q0**m0)
leftover=0.5*math.sqrt(q0/(2**m0))
check(exact_tv<=leftover+1e-12,'leftover bound')

# Asymptotic illustration, not validated hardness/security.
# q=2^255-19, n=128, k=384, m=32940, B0=2^159, Q=2^160+1.
N,K,MM=128,384,32940
q_big=(1<<255)-19
B0_big=1<<159
Q_big=2*B0_big+1
stat_mode_log2=math.log2(K/2)+(N*math.log2(q_big)-MM)/2
shift_log2=math.log2(MM*K)-math.log2(Q_big)
check(Q_big<q_big,'cube shorter than modulus')
check(stat_mode_log2 < -128,'mode statistical gap')
check(shift_log2 < -128,'opening statistical gap')

out={
  'run':'MINK-EVC-20261102',
  'seed':SEED,'checks':checks,
  'toy':{'q':q,'n':n,'m':m,'k':k,'B0':B0,'cases':160,'message_checks_per_case':16},
  'hash_compressed':{'message_bytes_tested':[0,5,8192], 'cases':hash_fixtures,'hash_bits':kh},
  'exact_tv_small':{'field':3,'m':m0,'total_A':q0**m0,'exact':exact_tv,'leftover_upper':leftover},
  'asymptotic_unassessed':{'q':'2^255-19','n':N,'m':MM,'k':K,'B0':'2^159','log2_statistical_mode_bound':stat_mode_log2,'log2_opening_shift_bound_per_commitment':shift_log2,'A_bytes_approx':N*MM*255/8},
  'scope':'algebraic equalities and finite distribution tests only; no SIS/LWE hardness estimate; no generic NP or source-release construction'
}
print(json.dumps(out,sort_keys=True,indent=2))
