#!/usr/bin/env python3
"""Run 369: finite signature-pin leak, not a PQ/WKEM security test."""
import hashlib,json
n=8
H=lambda x:hashlib.sha256(x).digest()
X=lambda a,b:bytes(x^y for x,y in zip(a,b))
checks=0
def ck(b):
 global checks
 checks+=1
 assert b
for s in range(8):
 ck(set(a for a in range(8))==set(range(8)))
 ck(set(a^s for a in range(8))==set(range(8)))
 for a in range(8): ck((a^(a^s))==s)
K=[(H(b'leaf0'+bytes([i])),H(b'leaf1'+bytes([i]))) for i in range(n)]
V=[(H(a),H(b)) for a,b in K]
m=[i%2 for i in range(n)]
sig=[K[i][m[i]] for i in range(n)]
A=[H(b'mask'+bytes([i])) for i in range(n)]
B=[X(A[i],sig[i]) for i in range(n)]
recovered=[X(a,b) for a,b in zip(A,B)]
verify=lambda bits,s:all(H(s[i])==V[i][bits[i]] for i in range(n))
ck(recovered==sig)
ck(verify(m,recovered))
ck(not verify([1-b for b in m],recovered))
p=H(b'setup-password')
y=H(p)
R=lambda flag,w:flag==1 and w[1] in (0,1) and H(w[0])==y
release=lambda flag,w:K if R(flag,w) else None
ck((p,0)!=(p,1))
ck(release(1,(p,0))==K and release(1,(p,1))==K)
ck(release(0,(p,0)) is None and verify(m,recovered))
print(json.dumps({'run':369,'status':'PASS','assertions':checks,'message_bits':n,'joint_signature_leak':True,'false_source_gate_release':False,'different_message_valid':False,'scope':'finite algebra only; no QPT OWF or actual SLH proof'},sort_keys=True))
