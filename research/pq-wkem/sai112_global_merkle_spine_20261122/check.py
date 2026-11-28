#!/usr/bin/env python3
"""Synthetic SHA256 Merkle consistency and public occurrence bypass screen.
Not original-source verification, release cryptography, or quantum testing.
"""
import hashlib, json
S=b'original-bridge-claim-bound-test'

def H(x): return hashlib.sha256(x).digest()
def leaf(j,bit,nonce): return H(b'V1LEAF\0'+S+j.to_bytes(4,'big')+bytes([bit])+nonce)
def node(a,b): return H(b'V1NODE\0'+a+b)
def root(w,nonce): return node(leaf(0,w[0],nonce),leaf(1,w[1],nonce))
def opening(w,nonce,j): return {'index':j,'bit':w[j],'nonce':nonce,'sibling':leaf(1-j,w[1-j],nonce)}
def verify(R,op):
    j,b,n,s=op['index'],op['bit'],op['nonce'],op['sibling']
    if j not in (0,1) or b not in (0,1) or len(n)!=16 or len(s)!=32: return False
    L=leaf(j,b,n)
    return node(L,s)==R if j==0 else node(s,L)==R

def mul(p,q): return tuple(p[q[i]] for i in range(5))
def inverse(p): return tuple(p.index(i) for i in range(5))
def cycle(*xs):
    a=list(range(5))
    for i,x in enumerate(xs): a[x]=xs[(i+1)%len(xs)]
    return tuple(a)
I=tuple(range(5)); a=cycle(0,1,2); b=cycle(0,1,3)
def comm(A,B): return mul(mul(mul(A,B),inverse(A)),inverse(B))

nonce=H(b'toy nonce')[:16]
r0=root((0,0),nonce); r1=root((1,0),nonce)
o0=opening((0,0),nonce,0);o1=opening((1,0),nonce,0)
assert verify(r0,o0) and verify(r1,o1)
assert not verify(r0,o1) and not verify(r1,o0)
assert r0!=r1
# The globally impossible equation (x=0 and x=1) has no satisfying x.
assert all(not (x==0 and x==1) for x in (0,1))
assert comm(a,I)==I and comm(I,b)==I
# Public path selection over *occurrences* bypasses the global-binding prescription.
attack=comm(a,b)
assert attack!=I
# Even if an honest evaluator insists that the two occurrences share the same
# root, these publicly available transition matrices can be multiplied directly.
print(json.dumps({
 'global_false':True,'one_root_opens_two_conflicting_values':False,
 'different_valid_roots':r0.hex()!=r1.hex(),
 'public_occurrence_bypass_nontrivial':attack!=I,
 'commutator':list(attack),
 'scope':'SHA256 Merkle consistency and public BP exposure only; no Build/Open, original evidence, source-work or FE proof'
},sort_keys=True))
