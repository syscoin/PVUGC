#!/usr/bin/env python3
"""Exact functional negative control for public quadratic mask in dual-LWE lift.
Not a QPT/security experiment.  Standard library only."""
import random, json, hashlib
q=65537; g=101; B=1
# z=(2a-1, 2b-1, 2c-1, 2s1-1, 2s2-1, 2s3-1)
C=[(1,0,-1,-1,0,0),(0,1,-1,0,-1,0),(1,1,-1,0,0,1),
   (1,0,0,0,0,0),(0,1,0,0,0,0),(0,0,1,0,0,0)]
t_false=(1,1,0,-1,1,1)
t_true=(1,1,0,1,1,1)
z_bad=(-1,1,1,-3,-1,1)
z_good=(1,1,1,-1,-1,-1)
def mul(M,z):return tuple(sum(a*b for a,b in zip(row,z)) for row in M)
assertions=0
def chk(b):
 global assertions
 assert b
 assertions+=1
chk(mul(C,z_bad)==t_false)
chk(mul(C,z_good)==t_true)
# No signed-unit solution for false instance (fixed a=0,b=1,c=1).
from itertools import product
chk(not any(mul(C,z)==t_false for z in product((-1,1),repeat=6)))
chk(any(mul(C,z)==t_true for z in product((-1,1),repeat=6)))
rng=random.Random(202610300310)
count=0
for case in range(1280):
   false=(case%2==0)
   t=t_false if false else t_true
   z=z_bad if false else z_good
   a=case%2
   r=[rng.randrange(q) for _ in range(6)]
   v=[rng.randrange(q) for _ in range(6)]
   eta=[rng.randint(-B,B) for _ in range(6)]
   xi=[rng.randint(-B,B) for _ in range(6)]
   eta_d=rng.randint(-B,B)
   # c=C^T r+eta; h=v+xi; d=t^T r + g*a - sum(v) + eta_d.
   c=[(sum(C[j][i]*r[j] for j in range(6))+eta[i])%q for i in range(6)]
   h=[(v[i]+xi[i])%q for i in range(6)]
   d=(sum(t[j]*r[j] for j in range(6))+g*a-sum(v)+eta_d)%q
   # Authorized algorithm binds one use of z to both linear and quadratic terms.
   official=(d-sum(z[i]*c[i] for i in range(6))+sum(z[i]**2*h[i] for i in range(6)))%q
   # Unauthorized algorithm *replaces the quadratic monomials by 1* while
   # retaining the affine pseudo-opening of the FALSE linearized circuit.
   bypass=(d-sum(z[i]*c[i] for i in range(6))+sum(h))%q
   e=(eta_d-sum(z[i]*eta[i] for i in range(6))+sum(xi))
   chk(bypass==(g*a+e)%q)
   chk(abs(e)<=1+sum(abs(a) for a in z)+len(xi))
   # Recovered genuine precommitted bit using nearest two centers.
   distance=lambda x,y:min((x-y)%q,(y-x)%q)
   recovered=min((0,1),key=lambda bit:distance(bypass,g*bit))
   chk(recovered==a)
   if not false:chk(official==bypass)
   else:
      # Formal quadratic polynomial differs by public multiples of h_i.
      chk((official-bypass)%q==(sum((z[i]**2-1)*h[i] for i in range(6)))%q)
      count+=1
# Complete precommitted 256-bit native-secret mock across independent related capsules.
# Testing the full key, rather than one digit, prevents a partial-only claim.
sk_bits=[rng.randrange(2) for _ in range(256)]
sk_bytes=int(''.join(map(str,sk_bits)),2).to_bytes(32,'big')
pk_mock=hashlib.sha256(sk_bytes).hexdigest()
related=[]
for j in range(2):
    recovered_bits=[]
    for a in sk_bits:
        r=[rng.randrange(q) for _ in range(6)]
        v=[rng.randrange(q) for _ in range(6)]
        eta=[rng.randint(-B,B) for _ in range(6)]
        xi=[rng.randint(-B,B) for _ in range(6)]
        eta_d=rng.randint(-B,B)
        c=[(sum(C[k][i]*r[k] for k in range(6))+eta[i])%q for i in range(6)]
        h=[(v[i]+xi[i])%q for i in range(6)]
        d=(sum(t_false[k]*r[k] for k in range(6))+g*a-sum(v)+eta_d)%q
        bypass=(d-sum(z_bad[i]*c[i] for i in range(6))+sum(h))%q
        recovered=min((0,1),key=lambda bit:min((bypass-g*bit)%q,(g*bit-bypass)%q))
        chk(recovered==a)
        recovered_bits.append(recovered)
    secret=int(''.join(map(str,recovered_bits)),2).to_bytes(32,'big')
    chk(secret==sk_bytes)
    chk(hashlib.sha256(secret).hexdigest()==pk_mock)
    related.append(hashlib.sha256(secret).hexdigest())
chk(related==[pk_mock]*2)
chk(1+sum(abs(a) for a in z_bad)+6<g//2)
output={'candidate':'public_quadratic_masked_dual_LWE','status':'reject: public monomial substitution','q':q,'g':g,'sampled_cases':1280,'false_cases':count,'full_secret_bits':256,'related_capsules':2,'native_pk_mock':'SHA256(secret)','assertions':assertions,'executable':'check.py','security':'finite classical functional counterexample only'}
print(json.dumps(output,sort_keys=True,indent=2))
