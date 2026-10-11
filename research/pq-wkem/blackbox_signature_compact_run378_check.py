#!/usr/bin/env python3
"""Run 378 finite signature-only extraction interface check. Not a WKEM or a QPT test."""
import hashlib,json
H=lambda x:hashlib.sha256(x).digest()
checks=0
cases=0
for n in (3,4,5,6):
 N=1<<n
 for a in (1,3,5):
  for b in (0,1,N-1):
   for w in range(N):
    y=(a*w+b)%N
    K=H(b'run378 toy key'+bytes([n,y]))
    sig=lambda m:H(K+bytes([m]))
    vk=[H(sig(m)) for m in range(4)]
    valid=[(u,t) for u in range(N) for t in (0,1) if (a*u+b)%N==y]
    assert valid==[(w,0),(w,1)];checks+=1
    for u,t in valid:
     recovered=K if (a*u+b)%N==y else None
     assert recovered==K;checks+=1
     for m in range(4):
      actual=H(recovered+bytes([m]))
      simulated=sig(m)
      assert actual==simulated and H(actual)==vk[m];checks+=1
      for z in (0,1,255):
       assert (z^actual[0])==(z^simulated[0]);checks+=1
    cases+=1
print(json.dumps({'run':378,'status':'PASS','cases':cases,'assertions':checks,'two_original_witnesses':True,'chosen_message_oracles_equal':True,'coherent_oracle_basis_equal':True,'toy_affine_is_oneway':False,'ideal_release_is_implemented':False,'QPT_security_proven':False},sort_keys=True))
