#!/usr/bin/env python3
"""R260 second attempt: equivocation-triggered hash-only gate (NOT a bridge WKEM)."""
import hashlib,json

def H(*p):return hashlib.sha256(b''.join(p)).digest()
def X(a,b):return bytes(x^y for x,y in zip(a,b))
def bits(m):
 d=H(b'Lamport-message:',m)
 return [(d[i//8]>>(7-i%8))&1 for i in range(256)]

def run(seed):
 p=[[H(b'one-time-key:',seed,i.to_bytes(2,'big'),bytes([b])) for b in range(2)] for i in range(256)]
 K=H(b'frozen-cancel:',seed)
 c=[X(K,H(b'dual-pad:',p[i][0],p[i][1])) for i in range(256)]
 def sign(m):return [p[i][b] for i,b in enumerate(bits(m))]
 def recover(m0,s0,m1,s1):
  bs0,bs1=bits(m0),bits(m1)
  for i in range(256):
   if bs0[i]!=bs1[i]:
    a,b=(s0[i],s1[i]) if bs0[i]==0 else (s1[i],s0[i])
    return X(c[i],H(b'dual-pad:',a,b))
  return None
 f0=b'real-claim-alternative:' + seed
 f1=b'competing-real-source:' + seed
 m0=b'unrelated-nonsource-A:' + seed
 m1=b'unrelated-nonsource-B:' + seed
 assert bits(f0)!=bits(f1)
 assert recover(f0,sign(f0),f1,sign(f1))==K
 assert recover(m0,sign(m0),m1,sign(m1))==K
 # The issuer with two preimages from the beginning can release K before any signature or source evidence.
 assert X(c[0],H(b'dual-pad:',p[0][0],p[0][1])) == K
 assert recover(f0,sign(f0),f0,sign(f0)) is None
 return True
for i in range(32):run(H(b'case:',i.to_bytes(2,'big')))
print(json.dumps({'run':'R260_EQUIVOCATION_HASH_GATE','instances':32,
                  'two_conflicting_signatures_open':32,
                  'two_unrelated_signatures_open':32,
                  'signer_knows_cancel_key_at_setup':32,
                  'single_signature_no_dual_row':32,
                  'status':'semantic two-OTS gate; fails actual source integrity and source-key separation'},indent=2,sort_keys=True))
