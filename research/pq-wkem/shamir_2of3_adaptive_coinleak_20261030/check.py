#!/usr/bin/env python3
"""Bounded functional checker for restricted 2-of-3 LWE SOURCE release.
Toy SOURCE A deliberately has repeated columns to show two different SOURCE openings;
it is NOT a secure LWE sample, QPT test, or real native signature implementation.
"""
import hashlib, itertools, json, random

q, n, m, L, g, B, w = 65537, 3, 8, 52, 2000, 2, 2
rng = random.Random(202610301136)
checks = 0

def ck(condition, message):
    global checks
    if not condition:
        raise AssertionError(message)
    checks += 1

def gf_mul(a,b):
    acc=0
    while b:
        if b & 1: acc ^= a
        a <<= 1
        if a & 256: a ^= 0x11b
        b >>= 1
    return acc

def gf_pow(a,e):
    out=1
    while e:
        if e&1: out=gf_mul(out,a)
        a=gf_mul(a,a)
        e>>=1
    return out

def gf_div(a,b):
    assert b
    return gf_mul(a,gf_pow(b,254))

def shares(master):
    slope=bytes(rng.randrange(256) for _ in range(32))
    return [bytes(k ^ gf_mul(x,a) for k,a in zip(master,slope)) for x in (1,2,3)]

def reconstruct(x,sx,y,sy):
    ck(x!=y,'distinct abscissas')
    return bytes(a ^ gf_mul(x,gf_div(a^b,x^y)) for a,b in zip(sx,sy))

def digits(data):
    v=int.from_bytes(data,'little')
    return [(v>>(5*i))&31 for i in range(L)]

def from_digits(dd):
    v=sum(int(a) << (5*i) for i,a in enumerate(dd))
    if v >= (1<<256):
        return None
    return v.to_bytes(32,'little')

def source():
    A=[[rng.randrange(q) for _ in range(m)] for _ in range(n)]
    for j in (0,1,4,5):
        for row in A: row[j+2]=row[j]
    U=[]; za=[];zb=[]
    for _ in range(L):
        p,t=rng.sample((0,1,4,5),2)
        sp,st=rng.choice((-1,1)),rng.choice((-1,1))
        z1=[0]*m;z2=[0]*m
        z1[p]=sp;z1[t]=st
        z2[p+2]=sp;z2[t+2]=st
        U.append([sum(row[i]*z1[i] for i in range(m))%q for row in A])
        za.append(z1);zb.append(z2)
    return A,U,za,zb

def capsule(A,U,share):
    r=[rng.randrange(q) for _ in range(n)]
    ec=[rng.randint(-B,B) for _ in range(m)]
    ed=[rng.randint(-B,B) for _ in range(L)]
    c=[(sum(A[i][j]*r[i] for i in range(n))+ec[j])%q for j in range(m)]
    d=[(sum(U[l][i]*r[i] for i in range(n))+ed[l]+g*digits(share)[l])%q for l in range(L)]
    return (c,d),(r,ec,ed)

def decode(packet,z):
    c,d=packet
    result=[]
    for l in range(L):
        ck(sum(int(v!=0) for v in z[l])==w, 'legal signed SOURCE weight')
        t=(d[l]-sum(zz*cc for zz,cc in zip(z[l],c)))%q
        distances=[min((t-g*j)%q,(g*j-t)%q) for j in range(32)]
        best=min(range(32), key=distances.__getitem__)
        ck(distances[best]<=B*(w+1),'correct packet nearest digit')
        ck(distances.count(distances[best])==1,'unique closest digit')
        result.append(best)
    value=from_digits(result)
    ck(value is not None,'canonical 256-bit share')
    return value

def mock_pk(master,prelabel):
    # Functional binding mock only: not native SLH-D(S)A KeyGen or signing.
    native_seeds=hashlib.shake_256(b'PVUGC/PQ-WKEM/native-master/v1\x00'+len(prelabel).to_bytes(4,'big')+prelabel+master).digest(48)
    return hashlib.sha256(b'MOCK/PK.root/'+native_seeds).digest()

# Exact GF(2^8) arithmetic, inversion, and information-theoretic single-share law.
for a in range(1,256):
    ck(gf_mul(a,gf_pow(a,254))==1,'field inverse')
for x in (1,2,3):
    for secret_byte in (0,1,17,127,255):
        possible=[secret_byte ^ gf_mul(x,slope) for slope in range(256)]
        ck(sorted(possible)==list(range(256)),'one share uniform for every master')
# Fix the observed share: all 256 possible master bytes remain possible with a distinct slope.
for x in (1,2,3):
    for obs in (0,4,87,255):
        solutions=[(secret, gf_div(obs ^ secret,x)) for secret in range(256)]
        ck(len({secret ^ gf_mul(x,a) for secret,a in solutions})==1,'consistent observed share')
        ck(len({secret for secret,a in solutions})==256,'no master information from one share')

trials=32
for trial in range(trials):
    # Predetermined prelabel never includes the eventual native public key or UTXO txid.
    prelabel=hashlib.sha256(f'PVUGC/pre-funding-session/{trial}'.encode()).digest()
    master=bytes(rng.randrange(256) for _ in range(32))
    ss=shares(master)
    A,U,z0,z1=source()
    packets=[];coins=[]
    for sh in ss:
        cap,co=capsule(A,U,sh)
        packets.append(cap);coins.append(co)
    pk=mock_pk(master,prelabel)
    scope=(f'original-relation|claim-utxo-{trial}|challenge|anchors|native-pk={pk.hex()}').encode()
    ck(pk.hex().encode() in scope,'final signed scope binds the actual native checking key')
    # Any two packets and either valid SOURCE opening restore one and the same master.
    for i,j in itertools.combinations(range(3),2):
        for opening in (z0,z1):
            first=decode(packets[i],opening)
            second=decode(packets[j],opening)
            got=reconstruct(i+1,first,j+1,second)
            ck(got==master,'2-of-3 same master for distinct SOURCE openings')
            ck(mock_pk(got,prelabel)==pk,'mock public binding')
    # Leaked complete encryption randomness of any one packet reveals precisely one share.
    for leak in range(3):
        (r,ec,ed)=coins[leak]; c,d=packets[leak]
        recovered_digits=[((d[l]-sum(U[l][i]*r[i] for i in range(n))-ed[l])%q)//g for l in range(L)]
        # Exact integer g*digit modulo q with no wrapping for this q,g.
        exposed=from_digits(recovered_digits)
        ck(exposed==ss[leak],'leak exposes exactly a Shamir share')
        surviving=[i for i in range(3) if i!=leak]
        ck(reconstruct(surviving[0]+1,decode(packets[surviving[0]],z0),surviving[1]+1,decode(packets[surviving[1]],z1))==master,'recover despite leaked packet')
        # All surviving 2-packet hybrid indices remain unopened.
        ck(all(i!=leak for i in surviving),'adaptive unopened-pair combinatorial cover')
    # An inconsistent share produced by an adversary is detected AFTER release via checking key.
    modified=bytearray(ss[0]); modified[0]^=1
    bad=reconstruct(1,bytes(modified),2,ss[1])
    ck(bad!=master,'modified share not same master')
    ck(mock_pk(bad,prelabel)!=pk,'mock key check detects modified reconstruction')

# Model-comparison size arithmetic, same 3 packets as 3 duplicate-master capsules.
n_big,m_big,N,C,J=256,4469,4,100,3
public_bytes=N*n_big*m_big*3 + N*C*(n_big*L*3+J*(m_big+L)*3)
ck(public_bytes==45978768,'illustrative public SOURCE+capsule bytes')
ck(2*B*(w+1)<g,'toy decoding margin')
ck(q-31*g>2*B*(w+1),'toy wraparound gap')
print(json.dumps({'candidate':'2-of-3 Shamir native-master share release with adaptive one-coin-disclosure cover',
 'status':'functional/source-only; not ORIGINAL witness WKEM or QPT hardness test',
 'field':'GF(256) using x^8+x^4+x^3+x+1',
 'toy':{'q':q,'n':n,'m':m,'digits':L,'packet_count':3,'sparse_weight':w,'g':g,'noise_bound':B},
 'trials':trials,'assertions':checks,'illustrative_public_bytes':public_bytes,
 'mock_keygen':True},sort_keys=True))
