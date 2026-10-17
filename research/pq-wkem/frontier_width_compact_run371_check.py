#!/usr/bin/env python3
"""Run 371: finite callable-frontier enumeration only; NOT PQ security."""
import hashlib,json
checks=0
def ck(v):
 global checks
 checks+=1
 assert v
for d in range(1,5):
 n=1<<d
 for mask in range(1<<n):
  states=[z for z in range(n) if (mask>>z)&1]
  found=next((z for z in range(n) if (mask>>z)&1),None)
  ck((found is not None)==bool(states))
  if states: ck(found==states[0])
for d in (6,10,14):
 n=1<<d
 secret=hashlib.sha256(f'run371-key-{d}'.encode()).digest()
 vk=hashlib.sha256(b'target-branch|'+secret).digest()
 accepted={int.from_bytes(hashlib.sha256(f'{d}/{i}'.encode()).digest(),'big')%n for i in (0,1)}
 ck(len(accepted)==2)
 for z in range(n):
  candidate=secret if z in accepted else None
  valid=candidate is not None and hashlib.sha256(b'target-branch|'+candidate).digest()==vk
  ck(valid==(z in accepted))
 ck(any(z in accepted for z in range(n)))
 ck(not any(z in set() for z in range(n)))
print(json.dumps({'run':371,'status':'PASS','assertions':checks,'functions_checked':{str(d):1<<(1<<d) for d in range(1,5)},'scope':'finite publicly callable frontier; no NP/QPT/SLH proof'},sort_keys=True))
