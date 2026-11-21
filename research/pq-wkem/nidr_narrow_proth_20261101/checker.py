#!/usr/bin/env python3
"""Offline, deterministic parameter/identity checker for NIDR narrow Proth fields.
Standard library only. Proth witness gives a primality *certificate*, not just BPSW.
"""
import json
import hashlib
import math
import random
from itertools import product

SEED=202611010940
rng=random.Random(SEED)
checks=0

def ck(condition,label):
    global checks
    checks+=1
    if not condition: raise AssertionError(label)

def proth_search(threshold):
    # Search bounded small odd k; p chosen so q barely exceeds the size threshold.
    p=max(4,threshold.bit_length()-5)
    for k in range(1,4096,2):
        q=k*(1<<p)+1
        if q<=threshold: continue
        if k>=(1<<p): continue
        for a in (2,3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,59,61,67,71):
            if pow(a,(q-1)//2,q)==q-1:
                return q,p,k,a
    raise ValueError("No Proth prime witness within local resource bound")

def spec(n,caps=2,keybits=512,lanes=3,security=128,edges=None):
    M=1+n+(n if edges is None else edges)
    H=(5*n+1)//2
    T=caps*keybits*lanes
    B=(1<<security)*T*H//2
    q,p,k,a=proth_search(4*B*M+2)
    ck(k%2==1 and k<(1<<p),"Proth shape")
    ck(q==k*(1<<p)+1 and pow(a,(q-1)//2,q)==q-1,"complete primality certificate")
    ck(q>4*B*M+2,"deterministic all-witness correctness")
    ck(T*H*(1<<security)<=2*B+1,"target statistical budget")
    ck(q%2==1 and q>2*B+1,"no ambiguity in bounded error domain")
    return {"n":n,"M":M,"H_max":H,"T":T,"B":B,"q":q,"proth_p":p,"proth_k":k,"proth_witness":a,
            "q_bits":q.bit_length(),"bytes_per_residue":(q.bit_length()+7)//8,
            "ciphertext_bytes":T*M*((q.bit_length()+7)//8),"old_32byte_size":T*M*32,
            "tv_bound_power_of_two":"at most 2^-"+str(security)}

def cycle_source(n,labels):
    # Sparse representation of source rows g_i=z_i+z_j-2z_i z_j-b_i;
    # feature layout 0=constant; 1..n=vertices; n+1..2n=edge monomials.
    rows=[]
    for i,b in enumerate(labels):
        j=(i+1)%n
        rows.append({0:-b,1+i:1,1+j:1,1+n+i:-2})
    return rows

def enc(rows,M,q,B,m,s,e):
    g=(q-1)//2
    c=e.copy()
    c[0]+=g*m
    for i,row in enumerate(rows):
        for j,a in row.items(): c[j]+=a*s[i]
    return [z%q for z in c]

def center(z,q):
    z%=q
    return z if z<=q//2 else z-q

def dec(c,v,q):
    t=sum(x*y for x,y in zip(c,v))%q
    g=(q-1)//2
    d0=min(t,q-t)
    d1=min((t-g)%q,(g-t)%q)
    return int(d1<d0)

def cycle_truth(labels):
    return sum(labels)%2==0

def witness(labels,t0):
    w=[t0]
    for b in labels[:-1]: w.append(w[-1]^b)
    return w

def eval_vector(w):
    n=len(w)
    return [1]+w+[w[i]*w[(i+1)%n] for i in range(n)]

def test_size(spec_,iterations):
    n=spec_["n"];q=spec_["q"];B=spec_["B"];M=spec_["M"]
    # TRUE cycle: XOR parity 0, two distinct valid ORIGINAL witnesses
    labels=[rng.randrange(2) for _ in range(n-1)]
    labels.append(sum(labels)%2)
    rows=cycle_source(n,labels)
    w0=witness(labels,0);w1=witness(labels,1)
    ck(w0!=w1 and cycle_truth(labels),"distinct witnesses consistent")
    v0=eval_vector(w0);v1=eval_vector(w1)
    for row in rows:
        ck(sum(v0[j]*a for j,a in row.items())==0,"original witness 0 maps to zero source")
        ck(sum(v1[j]*a for j,a in row.items())==0,"original witness 1 maps to zero source")
    for _ in range(iterations):
        m=rng.randrange(2)
        s=[rng.randrange(q) for _ in range(n)]
        e=[rng.randint(-B,B) for _ in range(M)]
        c=enc(rows,M,q,B,m,s,e)
        ck(dec(c,v0,q)==m,"witness 0 same key")
        ck(dec(c,v1,q)==m,"witness 1 same key")
        ck(all(0<=z<q for z in c),"field residues")
        # Portable byte packing is exact and sized at b=ceil(log2(q)/8)
        bb=spec_["bytes_per_residue"]
        packed=b"".join(z.to_bytes(bb,"big") for z in c)
        recovered=[int.from_bytes(packed[j*bb:(j+1)*bb],"big") for j in range(M)]
        ck(recovered==c,"bit-exact compact serialization")
    # FALSE cycle: independent shift and exact arbitrary bit opening
    labels[-1]^=1
    ck(not cycle_truth(labels),"odd false cycle")
    rows=cycle_source(n,labels)
    delta=[(q+1)//2]*n
    bsum=sum(labels)
    h=[-((bsum+1)//2)]+[1]*n+[-1]*n
    actual=[center(( (q-1)//2 if j==0 else 0 ) +sum(rows[i].get(j,0)*delta[i] for i in range(n)),q) for j in range(M)]
    ck(actual==h,"exact public false shift")
    ck(sum(abs(x) for x in h)==(bsum+1)//2+2*n,"instance shift norm")
    ck(sum(abs(x) for x in h)<=spec_["H_max"],"instance uniformly bounded by public Hmax")
    for _ in range(iterations):
        s=[rng.randrange(q) for _ in range(n)]
        e=[rng.randint(-B,B) for _ in range(M)]
        m=rng.randrange(2)
        c0=enc(rows,M,q,B,0,s,e)
        sm=[(x+m*d)%q for x,d in zip(s,delta)]
        em=[z-m*hj for z,hj in zip(e,h)]
        ck(c0==enc(rows,M,q,B,m,sm,em),"joint coin+plaintext opening exact")
        ck(all(abs(z)<=B+spec_["H_max"] for z in em),"opening deviation bounded")
    return {"n":n,"valid_and_false_instances":2,"true_tries":iterations,"false_openings":iterations,"actual_H":sum(abs(x) for x in h)}

def small_exact_tv():
    # Probability TV between independent uniform integer errors e and e-h.
    for B in [1,2,3,4]:
        U=list(range(-B,B+1))
        for h in [(-1,0),(1,-1),(0,2),(2,2)]:
            N=len(U)**2
            inter=sum(1 for e in product(U,repeat=2) if all(-B<=e[j]-h[j]<=B for j in range(2)))
            exact_num=N-inter
            via_prod=1.0-math.prod(max(0,1-abs(v)/(2*B+1)) for v in h)
            ck(abs(exact_num/N-via_prod)<1e-14,"exact 2D overlap TV")
            ck(exact_num/N<=sum(abs(z) for z in h)/(2*B+1)+1e-14,"TV union bound")

params=[spec(31),spec(101),spec(1001)]
cycles=[test_size(params[0],64),test_size(params[1],16),test_size(params[2],2)]
small_exact_tv()
# Compare to 32-byte preexisting carrier, preserving all 3 lanes, all bits, all capsules.
for s in params:
    ck(s["ciphertext_bytes"]<s["old_32byte_size"],"strict physical savings")
    ck(s["ciphertext_bytes"]==s["T"]*s["M"]*s["bytes_per_residue"],"exact ciphertext dimension")
summary={"run":"PNIDR-2026-11-01-T10","status":"restricted NIDR modulus compression; generic NP unresolved",
         "seed":SEED,"checks":checks,"parameters":params,"tests":cycles,
         "limitations":["all false signed XOR graphs only","QPT postprocessing of classical openings, not quantum opening oracle","native EUF and authenticated manifests independent assumptions","no generic false/hard-true ORIGINAL extraction"]}
print(json.dumps(summary,indent=2,sort_keys=True))
