#!/usr/bin/env python3
"""Small falsification of noncommutative public masked-group gate. Not source/WE proof."""
import hashlib, json, random
N=9
r=random.Random(20261119)
def ident():return tuple(range(N))
def mul(p,q):return tuple(p[q[i]] for i in range(N))
def inv(p):return tuple(p.index(i) for i in range(N))
def product(a):
    z=ident()
    for x in a:z=mul(z,x)
    return z
def randp():
    x=list(range(N));r.shuffle(x);return tuple(x)
def hashperm(p):return hashlib.sha256(bytes(p)).digest()
def xor(a,b):return bytes(x^y for x,y in zip(a,b))
a,b=randp(),randp()
target=product((a,b,inv(a),inv(b)))
assert target!=ident()
def blinded_gate(branches):
    frames=[randp() for _ in range(4)];frames.append(frames[0]);
    pubs=[tuple(product((inv(frames[j]),g,frames[j+1])) for g in pair) for j,pair in enumerate(branches)]
    return pubs
# 4 choices (each position has same input variable x), locally identity baseline 0/1/0/1.
branches_false=[(ident(),a),(b,ident()),(ident(),inv(a)),(inv(b),ident())]
P=blinded_gate(branches_false)
for x in (0,1):
    z=product([P[j][bit] for j,bit in enumerate([x,x,x,x])])
    assert z==ident(), (x,z)
# Use per-occurrence baseline 0,1,0,1: impossible as a globally consistent bitstring x.
baselines=(0,1,0,1)
base=ident();V=[]
for j in range(4):
    row=P[j];bit=baselines[j]
    # V_j(b)=B_(j-1) M_(j,b) M_(j,bit)^(-1) B_(j-1)^(-1)
    v=product((base,row[1-bit],inv(row[bit]),inv(base)))
    V.append(v)
    base=mul(base,row[bit])
assert base==ident()
# Inconsistent per-occurrence choices directly realize the target word.
invalid_occurrence_path = product((P[0][1],P[1][0],P[2][1],P[3][0]))
# Local 'a' and 'b' generators at positions 1 and 2 alone reveal the blind conjugate of [a,b].
conj_target=product((V[0],V[1],inv(V[0]),inv(V[1])))
assert invalid_occurrence_path == conj_target
# Directly check the hidden (nonpublic) target conjugate by choosing any frames? not needed.
secret=hashlib.sha256(b"TEST ONLY: frozen cancellation signature bytes").digest()
ct=xor(secret,hashperm(conj_target))
extracted=xor(ct,hashperm(conj_target))
assert extracted==secret
# True x AND y: use same group program but independently selectable x,y.
branches_true=[(ident(),a),(ident(),b),(ident(),inv(a)),(ident(),inv(b))]
T=blinded_gate(branches_true)
for x in (0,1):
    for y in (0,1):
        product_val=product((T[0][x],T[1][y],T[2][x],T[3][y]))
        # same independent mask because each gate's own frame0=frame4
        if x*y:
            assert product_val!=ident()
        else: assert product_val==ident()
print(json.dumps({"scope":"small public permutation-gate regression only", "n":N,"all_false_consistent_inputs_reject":True,"inconsistent_public_baseline_recovers_secret":extracted==secret,"ordinary_true_gate_correct":True,"full_public_source_FE_constructed":False},sort_keys=True))
