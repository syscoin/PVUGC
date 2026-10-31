#!/usr/bin/env python3
"""Deterministic finite-algebra / exact-integer SOURCE two-pass checks.
NOT a QPT security test, production sampler, or native signature implementation.
"""
import json, random, math, hashlib, itertools
from collections import Counter

Q = 65537; N = 8; M = 22; W = 6; G = 2047; E = 2
SYMBOLS = 103; PASS_COUNT = 2; TARGET_COLS = (SYMBOLS+PASS_COUNT-1)//PASS_COUNT
COUNTS=Counter()
def check(ok, name='assertion'):
    assert ok, name
    COUNTS[name]+=1

def gf_mul(a,b):
    out=0
    for _ in range(8):
        if b&1: out ^= a
        hi=a&0x80
        a=(a<<1)&255
        if hi: a^=0x1b
        b >>= 1
    return out

def gf_inv(a):
    assert a
    out=1; exponent=254; x=a
    while exponent:
        if exponent&1: out=gf_mul(out,x)
        x=gf_mul(x,x); exponent>>=1
    return out

def share(K,V,i):
    return bytes(a ^ gf_mul(i,b) for a,b in zip(K,V))

def recover_key(Si,Sj,i,j):
    inv=gf_inv(i^j)
    return bytes(a ^ gf_mul(i, gf_mul(a^b, inv)) for a,b in zip(Si,Sj))

def digits(b):
    x=int.from_bytes(b,'little')
    return [(x>>(5*j)) & 31 for j in range(SYMBOLS)]

def undigits(d):
    x=sum(a<<(5*j) for j,a in enumerate(d))
    check(x < (1<<512),'canonical_master')
    return x.to_bytes(64,'little')

def sample_z(rng, force_collision=False):
    if force_collision:
        slots=[0]+rng.sample(range(2,M),W-1)
    else:
        slots=rng.sample(range(M),W)
    return tuple(sorted((j,rng.choice([-1,1])) for j in slots))

def vector(A,z):
    u=[0]*N
    for j,sgn in z:
        for i in range(N): u[i] = (u[i] + sgn*A[j][i])%Q
    return tuple(u)

def dot(x,y): return sum(a*b for a,b in zip(x,y))%Q

def legal(A,u,z):
    return len(z)==W and len({i for i,s in z})==W and all(0<=i<M and s in (-1,1) for i,s in z) and vector(A,z)==u

def sample_packet(rng,A,S,collision=False):
    zz=[sample_z(rng, force_collision=collision) for _ in range(TARGET_COLS)]
    UU=[vector(A,z) for z in zz]
    aa=digits(S)
    cc=[]; dd=[]
    for j in range(PASS_COUNT):
        r=[rng.randrange(Q) for _ in range(N)]
        c=[(dot(A[col],r)+rng.randint(-E,E))%Q for col in range(M)]
        d=[]
        for l in range(TARGET_COLS):
            pos=j*TARGET_COLS+l
            if pos < SYMBOLS:
                d.append((dot(UU[l],r)+rng.randint(-E,E)+G*aa[pos])%Q)
        cc.append(c); dd.append(d)
    return {'U':UU,'Z':zz,'c':cc,'d':dd}

def centered(x):
    return x%Q if x%Q <= Q//2 else x%Q-Q

def open_packet(A,packet,zs):
    for l,z in enumerate(zs): check(legal(A,packet['U'][l],z),'legal_source_open')
    aa=[]
    for j in range(PASS_COUNT):
        for l,d in enumerate(packet['d'][j]):
            z=zs[l]
            val=(d-sum(s*packet['c'][j][i] for i,s in z))%Q
            close=[a for a in range(32) if abs(centered(val-G*a))<=E*(W+1)]
            check(len(close)==1,'unique_digit_decode')
            aa.append(close[0])
    check(len(aa)==SYMBOLS,'symbol_count')
    return undigits(aa)

def storage(n,m,nsymbols,passes,scopes=400,packets=3,byte_width=3):
    L=(nsymbols+passes-1)//passes
    global_A=n*m*byte_width
    per_packet=(n*L+passes*m+nsymbols)*byte_width
    return global_A+scopes*packets*per_packet

def main():
    rng=random.Random(20261031)
    check(G-2*E*(W+1)>0,'toy_margin_left')
    check(Q-31*G-2*E*(W+1)>0,'toy_margin_right')
    check(TARGET_COLS==52,'target_cols')
    for a in range(1,256):
        check(gf_mul(a,gf_inv(a))==1,'gf_inverse')
    for j in (1,2,3):
        for k in range(256):
            # Exhaustive one-byte uniformity: each fixed K gives all shares exactly once over V.
            vals={k ^ gf_mul(j,v) for v in range(256)}
            check(len(vals)==256,'one_share_uniform')

    A=[tuple(rng.randrange(Q) for _ in range(N)) for _ in range(M)]
    for trial in range(16):
        K=bytes(rng.randrange(256) for _ in range(64))
        V=bytes(rng.randrange(256) for _ in range(64))
        pk=hashlib.sha256(b'MOCK-PK-NOT-NATIVE'+K).hexdigest()
        pp={i:sample_packet(rng,A,share(K,V,i)) for i in (1,2,3)}
        opened={i:open_packet(A,pp[i],pp[i]['Z']) for i in (1,2,3)}
        for i in (1,2,3):
            check(opened[i]==share(K,V,i),'packet_share')
        for i,j in itertools.combinations((1,2,3),2):
            kk=recover_key(opened[i],opened[j],i,j)
            check(kk==K,'same_master')
            check(hashlib.sha256(b'MOCK-PK-NOT-NATIVE'+kk).hexdigest()==pk,'mock_pk_check')
        check(pp[1]['U']!=pp[2]['U'] and pp[1]['U']!=pp[3]['U'] and pp[2]['U']!=pp[3]['U'],'separate_packet_target')
        for i in (1,2,3):
            check(pp[i]['c'][0]!=pp[i]['c'][1],'independent_pass_samples')
    # Collision-controlled *nonuniform* fixture demonstrates every alternative legal SOURCE opening decodes same share.
    Ac=list(A); Ac[1]=Ac[0]
    K=bytes(rng.randrange(256) for _ in range(64))
    V=bytes(rng.randrange(256) for _ in range(64))
    packet=sample_packet(rng,Ac,share(K,V,1),collision=True)
    alt=[]
    for z in packet['Z']:
        one=dict(z)
        check(0 in one and 1 not in one,'collision_fixture')
        s=one.pop(0); one[1]=s
        z2=tuple(sorted(one.items()))
        check(legal(Ac,packet['U'][len(alt)],z2),'alternate_legal')
        alt.append(z2)
    check(open_packet(Ac,packet,alt)==share(K,V,1),'alternate_same_share')
    check(open_packet(Ac,packet,packet['Z'])==share(K,V,1),'original_same_share')

    q=16777213;n=256;m=4469;w=2004;g=524287; B=128
    check(g-2*B*(w+1)==11007,'full_margin_left')
    check(q-31*g-2*B*(w+1)==11036,'full_margin_right')
    J=400*3*2*52
    sample_size=2**w*math.comb(m,w)
    exact_stat=(J*J*(q**n-1)*(2**256) <=4*sample_size)
    check(exact_stat,'full_400scope_statistical_bound')
    check(not (J*J*(q**n-1)*(2**256) <=4*(2**(w-1)*math.comb(m,w-1))), 'weight_2003_not_enough')
    check(all(q%p for p in range(2,math.isqrt(q)+1)), 'full_modulus_prime')
    check(400*3*2*52==124800,'full_stat_union_count')
    sizes={str(k):storage(n,m,103,k) for k in range(1,9)}
    check(sizes['1']==114816192,'baseline_bytes')
    check(sizes['2']==83902992,'two_pass_bytes')
    check(min(sizes,key=sizes.get)=='2','optimal_passes_1_to_8')
    check(sizes['3']==84324192,'three_pass_bytes')
    pct=100*(sizes['1']-sizes['2'])/sizes['1']
    check(26<pct<28,'saving_range')
    result={
      'candidate':'independent-two-pass-reused-packet-source-qpt-lwe',
      'status':'SOURCE-only release; not ORIGINAL-WKEM',
      'params':{'q':q,'n':n,'m':m,'w':w,'g':g,'B':B,'master_bits':512,'digits':103,'target_columns_per_packet':52},
      'bytes_by_pass_count':sizes,'two_pass_reduction_pct':round(pct,9),
      'two_pass_vs_prg_wrapper_extra_bytes':sizes['2']-67707792,
      'margins':[11007,11036],
      'exact_400scope_statistical_inequality':exact_stat,
      'statistical_union_log2_upper':round(math.log2(J)-1+0.5*(math.log2(q**n-1)-math.log2(sample_size)),6),
      'toy_trials':16,'toy_accepted_source_openings':16*3+2,
      'assertions_total':sum(COUNTS.values()),'assertions_by_category':dict(sorted(COUNTS.items())),
      'caveat':'toy RNG, toy GF256 release, mock native PK; no QPT test, no ORIGINAL compiler, no security calibration'
    }
    print(json.dumps(result,indent=2,sort_keys=True))

if __name__=='__main__': main()
