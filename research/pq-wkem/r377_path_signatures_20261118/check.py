#!/usr/bin/env python3
"""BIP340 additive-path tweak negative control. Public TEST keys only; no BTC/SYS tx or source witness."""
import hashlib, json
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.exceptions import InvalidSignature
P=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G=(55066263022277343669578718895168534326250603453777594175500187360389116729240,
   32670510020758816978083085130507043184471273380659243275938904335757337482424)

def inv(a):return pow(a,-1,P)
def plus(a,b):
 if a is None:return b
 if b is None:return a
 if a[0]==b[0] and (a[1]+b[1])%P==0:return None
 if a==b:
  l=(3*a[0]*a[0]*inv(2*a[1]))%P
 else:l=((b[1]-a[1])*inv(b[0]-a[0]))%P
 x=(l*l-a[0]-b[0])%P; return(x, (l*(a[0]-x)-a[1])%P)
def mul(k,point=G):
 r=None; q=point
 while k:
  if k&1:r=plus(r,q)
  q=plus(q,q);k>>=1
 return r

def H(b):return hashlib.sha256(b).digest()
def tag(name,m):
 t=H(name.encode()); return H(t+t+m)
def b32(i):return i.to_bytes(32,'big')

# BIP340 specification key parity conventions, deterministic test nonce.
sk=1+int.from_bytes(H(b'R377 public test sign key'), 'big')%(N-1)
Q=mul(sk)
if Q[1]&1:sk=N-sk; Q=mul(sk)
xQ=b32(Q[0]);msg=H(b'R377 fixed cancellation message test-only')
nonce=1+int.from_bytes(H(b'R377 public test nonce'), 'big')%(N-1)
R=mul(nonce)
if R[1]&1:nonce=N-nonce;R=mul(nonce)
r=b32(R[0]);e=int.from_bytes(tag('BIP0340/challenge',r+xQ+msg),'big')%N
s=(nonce+e*sk)%N
assert mul(s)==plus(R,mul(e,Q))
def bip340_verify(rbytes,svalue):
    # Full x-only BIP340 equation, including even-y lift of nonce.
    ee=int.from_bytes(tag('BIP0340/challenge',rbytes+xQ+msg),'big')%N
    pver=plus(mul(svalue), mul((N-ee)%N,Q))
    return pver is not None and pver[1]%2==0 and pver[0]==int.from_bytes(rbytes,'big')
assert bip340_verify(r,s)

# A purported witness-dependent signature without sk: s'=s+t, R'=R+tG.
# It satisfies an equation with STALE challenge e, but BIP340 recomputes e'.
rows=[]
for j in range(1,65):
 t=1+int.from_bytes(H(b'R377 public path token '+j.to_bytes(2,'big')),'big')%(N-1)
 r2=plus(R,mul(t));s2=(s+t)%N
 assert mul(s2)==plus(r2,mul(e,Q))
 parity_ok=(r2[1]%2==0)
 e2=int.from_bytes(tag('BIP0340/challenge',b32(r2[0])+xQ+msg),'big')%N
 valid=bip340_verify(b32(r2[0]),s2)
 rows.append({'j':j,'parity_even':parity_ok,'challenge_equal':e2==e,'valid':valid})
assert all(not r['valid'] and not r['challenge_equal'] for r in rows)
# Native ECDSA ±s malleability is a public transform of an ALREADY KNOWN signature.
# It gives no method to release an unknown base signature from a source witness.
priv=ec.derive_private_key(sk,ec.SECP256K1())
pk=priv.public_key()
der=priv.sign(msg,ec.ECDSA(utils.Prehashed(hashes.SHA256())))
r_e,s_e=utils.decode_dss_signature(der)
def verify_e(r_,s_):
 try:pk.verify(utils.encode_dss_signature(r_,s_),msg,ec.ECDSA(utils.Prehashed(hashes.SHA256())));return True
 except InvalidSignature:return False
assert verify_e(r_e,s_e) and verify_e(r_e,N-s_e)
assert all(not verify_e(r_e,(s_e+i)%N) for i in range(1,65))
print(json.dumps({'scope':'public additive signature tweak only, not a generic signature impossibility or FE','native_bip340_valid_initial':True,'path_tweaks':len(rows),'fixed_challenge_equations':len(rows),'new_challenge_equal':sum(r['challenge_equal'] for r in rows),'bip340_accepted':sum(r['valid'] for r in rows),'distinct_claim_or_source_implemented':False,'source_witness_extracted':False,'ecdsa_base_valid':True,'ecdsa_sign_flip_valid':True,'ecdsa_simple_additive_tweaks_accepted':0},sort_keys=True,indent=2))
