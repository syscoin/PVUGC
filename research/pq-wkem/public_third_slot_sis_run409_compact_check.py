#!/usr/bin/env python3
import itertools, json, random
r=random.Random(409); checks=0
for bit in (0,1):
    frequencies={}
    for bits in itertools.product((0,1),repeat=8):
        cols=[bits[i:i+2] for i in range(0,8,2)]
        chosen=(cols[bit],cols[2],cols[3])
        frequencies[chosen]=frequencies.get(chosen,0)+1
    assert len(frequencies)==64; checks+=1
    assert set(frequencies.values())=={4}; checks+=1
for q in (17,101,257):
    for _ in range(500):
        A=[[r.randrange(q) for j in range(8)] for i in range(3)]
        bit=r.randrange(2); C=[[r.randrange(q) for j in range(8)] for i in range(4)]
        for dst,src in zip((bit,2,3),A): C[dst]=src[:]
        B=[C[i] for i in (bit,2,3)]
        assert B==A; checks+=1
        # Finite-field Gaussian elimination; at these toy parameters SIS is EASY.
        X=[v[:] for v in B]; piv=[]; row=0
        for col in range(8):
            pos=next((i for i in range(row,3) if X[i][col]%q),None)
            if pos is None: continue
            X[row],X[pos]=X[pos],X[row]
            inv=pow(X[row][col],-1,q)
            X[row]=[(v*inv)%q for v in X[row]]
            for i in range(3):
                if i!=row:
                    fac=X[i][col]
                    X[i]=[(X[i][j]-fac*X[row][j])%q for j in range(8)]
            piv.append(col); row+=1
            if row==3: break
        free=next(i for i in range(8) if i not in piv)
        t=[0]*8;t[free]=1
        for i,c in enumerate(piv):t[c]=(-X[i][free])%q
        t=[x if x<=q//2 else x-q for x in t]
        assert any(t); checks+=1
        assert all(sum(a*b for a,b in zip(v,t))%q==0 for v in A); checks+=1
        assert sum(v*v for v in t)<q*q; checks+=1
        assert sum(v*v for v in [q]+[0]*7)>=q*q; checks+=1
print(json.dumps({'run':409,'assertions':checks,'toy_cases':1500,'scope':'finite modular reduction only; no SIS hardness'},sort_keys=True))
