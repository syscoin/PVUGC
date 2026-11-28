#!/usr/bin/env python3
"""Bounded explicit-state reachability demo; NOT an ORIGINAL witness-KEM."""
from hashlib import sha256
import json
N=48
M=257
DOMAIN=b'R395-EXPLICIT-PUBLIC-STATE-MACHINE'
def step(position,state,bit):
    return int.from_bytes(sha256(DOMAIN+position.to_bytes(2,'big')+state.to_bytes(2,'big')+bytes([bit])).digest(),'big')%M
def evaluate(bits):
    state=0
    for pos,bit in enumerate(bits):
        state=step(pos,state,bit)
    return state
seed=sha256(b'public planted witness just to ensure nonempty language').digest()
planted=tuple((seed[i//8]>>(7-(i%8)))&1 for i in range(N))
target=evaluate(planted)
reachable={0:()}
counts=[len(reachable)]
evaluations=0
for j in range(N):
    nxt={}
    for state,pref in reachable.items():
        for bit in (0,1):
            q=step(j,state,bit)
            evaluations+=1
            if q not in nxt:
                nxt[q]=pref+(bit,)
    reachable=nxt
    counts.append(len(reachable))
assert target in reachable
found=reachable[target]
assert evaluate(found)==target and len(found)==N
assert evaluations<=2*M*N
result={
  'scope':'SHA-based explicit polynomial-state program; not ORIGINAL source/FE/WE',
  'positions':N,'states':M,'sha_transitions_evaluated':evaluations,
  'maximum_reachable_states':max(counts),
  'reachable_after_positions':{str(k):counts[k] for k in (0,4,8,12,16,24,32,48)},
  'planted_witness_hex':''.join(str(b) for b in planted),
  'publicly_extracted_witness_bits':''.join(str(b) for b in found),
  'extracted_is_actual_accepted_witness':True,
  'extracted_may_differ_from_planted':found!=planted,
  'public_state_target':target,'no_source_or_full_public_security_claim':True
}
print(json.dumps(result,sort_keys=True,indent=2))
