#!/usr/bin/env python3
"""Run 672: exact finite public-cover search test; NOT an encryption implementation."""
import hashlib, json, math
from fractions import Fraction
from pathlib import Path
N=1<<5
CHECKS=0

def require(test, label):
    global CHECKS
    CHECKS+=1
    if not test: raise AssertionError(label)

def cover(c,r,a):
    b=b'RUN672-published-cover'+bytes((r,a))
    return int.from_bytes(hashlib.shake_256(b).digest((c+7)//8),'big')&((1<<c)-1)

def frame(c,r,s):
    return (65539*s+(7*r+11)**3)%(1<<c)

def unframe(c,r,s):
    return (pow(65539,-1,1<<c)*(s-(7*r+11)**3))%(1<<c)

cases=[]
for c in (24,192,384):
    marked=0
    for r in range(16):
        expected={((w+3*r)%N) for w in (0,5,11)} if r%4 else set()
        image={cover(c,r,a) for a in range(N)}
        require(len(image)==N,'injective cover')
        allowed={cover(c,r,a) for a in expected}
        for a in range(N):
            s=cover(c,r,a)
            mixed=frame(c,r,s)
            require(unframe(c,r,mixed)==s,'reversible mixing')
            accept=unframe(c,r,mixed) in allowed
            require(accept==(a in expected),'correct covered acceptance')
            marked+=accept
    require(marked==36,'exact accepted seed-tape pairs')
    p=Fraction(marked,16*N)
    require(p==Fraction(9,128),'public-cover probability')
    cases.append({'physical_state_bits':c,'public_seed_bits':5,
                  'accepted_pairs':marked,'total_pairs':512,'probability':str(p)})

# Exact Grover iterations on the PUBLIC seed-and-tape search space.
marked={(r<<5)|((w+3*r)%N) for r in range(16) if r%4 for w in (0,5,11)}
require(len(marked)==36,'number of quantum marks')
amp=[1/math.sqrt(512)]*512
angle=math.asin(math.sqrt(Fraction(36,512)))
probs=[]
for j in range(5):
    q=sum(amp[i]**2 for i in marked)
    require(abs(q-math.sin((2*j+1)*angle)**2)<1e-11,'Grover probability')
    probs.append(round(q,12))
    for i in marked:amp[i]=-amp[i]
    avg=sum(amp)/512
    amp=[2*avg-a for a in amp]
    require(abs(sum(a*a for a in amp)-1)<1e-11,'norm preservation')

print(json.dumps({'run':672,'scope':'counting tests only; NOT WE/PQ security',
                  'source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                  'checks':CHECKS,'cases':cases,'grover_success':probs},sort_keys=True,indent=2))
