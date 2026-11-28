#!/usr/bin/env python3
"""Finite tests for multi-party offset-correction CRS candidate.
No QPT security claim. Uses deterministic fixtures and real modular arithmetic.
"""
import json, random
from itertools import combinations
R=random.Random(20261101)
q=65537; g=(q-1)//2; n=3; m=24; eta=2; parties=3
edges=list(combinations(range(4),2))
assert len(edges)==6
checks=0

def dot(x,y):return sum(a*b for a,b in zip(x,y))%q
def gen_A():return [[R.randrange(q) for _ in range(n)] for _ in range(m)]
def key_contribution(A,s):
    errors=[R.randrange(-eta,eta+1) for _ in range(m)]
    return [(dot(row,s)+e)%q for row,e in zip(A,errors)]
def make_setup():
    AA=[gen_A() for _ in range(parties)]
    SS=[[R.randrange(q) for _ in range(n)] for _ in range(parties)]
    # Party 1 is honest uniform-only CRS; others deliberately retain LWE secrets.
    BB=[key_contribution(AA[i],SS[i]) if i!=1 else [R.randrange(q) for _ in range(m)] for i in range(parties)]
    A=[[sum(AA[i][j][k] for i in range(parties))%q for k in range(n)] for j in range(m)]
    b=[sum(BB[i][j] for i in range(parties))%q for j in range(m)]
    return AA, BB, SS, A, b

def enc(bit,setup):
    AA,BB,SS,A,b=setup
    r=[R.randrange(2) for _ in range(m)]
    u=[sum(A[j][k]*r[j] for j in range(m))%q for k in range(n)]
    v=(dot(b,r)+g*bit)%q
    # Every party's correction projection permits that party to isolate its own ciphertext.
    u_parts=[[sum(AA[i][j][k]*r[j] for j in range(m))%q for k in range(n)] for i in range(parties)]
    v_parts=[(dot(BB[i],r)+g*bit)%q for i in range(parties)]
    return dict(r=r,u=u,v=v,u_parts=u_parts,v_parts=v_parts,bit=bit)

def center(x):
    x%=q
    return x if x<=q//2 else x-q

def decrypt_party(c,setup,i):
    s=setup[2][i]
    t=(c['v_parts'][i]-dot(s,c['u_parts'][i]))%q
    # nearest of 0,g, assuming bounded honest-generated LWE noise
    return 0 if abs(center(t))<=abs(center(t-g)) else 1

stats=dict(fixtures=0, false_rounds=0, decrypted_challenge_bits=0, decrypted_hidden_color_bits=0, checks=0)
for _ in range(96):
    setup=make_setup(); stats['fixtures']+=1
    for _ in range(8):
        # Honest verifier encrypts edge with actual source coins and publishes *all* correction tags.
        edge=R.randrange(6)
        bits=[(edge>>j)&1 for j in range(3)]
        cts=[enc(b,setup) for b in bits]
        extracted=[decrypt_party(c,setup,0) for c in cts]
        assert extracted==bits; checks+=1; stats['decrypted_challenge_bits']+=3
        recovered=sum(bit<<j for j,bit in enumerate(extracted))
        assert recovered==edge;checks+=1
        a,b=edges[recovered]
        # Prover now chooses a new 'coloring' targeted *only* to this edge,
        # despite the full K4 being 4-chromatic (false 3COL instance).
        coloring=[0,0,0,0];coloring[b]=1
        assert coloring[a]!=coloring[b];checks+=1
        # Commit all vertices after the ciphertext challenge but before the edge reveal.
        cols=[[enc((coloring[v]>>j)&1,setup) for j in range(2)] for v in range(4)]
        for v in range(4):
            got=[decrypt_party(c,setup,0) for c in cols[v]]
            assert got==[(coloring[v]>>j)&1 for j in range(2)];checks+=1
            stats['decrypted_hidden_color_bits']+=2
        # The actual edge and randomness reveal match the original ciphertexts.
        for c in cts:
            assert c['r'] and c['bit'] in (0,1)
            assert c['v']==(dot(setup[4],c['r'])+g*c['bit'])%q
            assert all(c['v_parts'][i]==(dot(setup[1][i],c['r'])+g*c['bit'])%q for i in range(parties));checks+=1
        assert coloring[a]!=coloring[b];checks+=1
        stats['false_rounds']+=1
stats['checks']=checks
stats['false_graph']='K4 has no 3-coloring; every edge can be independently satisfied'
stats['outcome']='false proof accepts 100% of encrypted-edge rounds using retained corrupt-party LWE secret'
print(json.dumps(stats,sort_keys=True,indent=2))
