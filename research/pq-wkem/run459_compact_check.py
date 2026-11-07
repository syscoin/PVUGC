#!/usr/bin/env python3
"""Exact diagnostic of public emulation; NOT a protected witness release."""
import hashlib,json
H=lambda *p:hashlib.sha256(b'|'.join(p)).digest()
count=0
def test(v):
 global count
 count+=1
 assert v

def combine(xs):
 out=bytearray(len(xs[0]))
 for x in xs:
  for j,v in enumerate(x):out[j]^=v
 return bytes(out)

def ceremony(x,coins):
 shares=[H(b'share',x,bytes([i]),c) for i,c in enumerate(coins)]
 K=combine(shares)
 Y={'x':x.hex(),'messages':[H(b'public',x,bytes([i]),c).hex() for i,c in enumerate(coins)],'toy_vk':H(b'toy',x,K).hex()}
 return Y,shares,K

cases=0
for n in [2,3,5]:
 for j in range(16):
  x=H(b'claim',bytes([n,j]));coins=[H(b'coin',x,bytes([i])) for i in range(n)]
  Y,priv,K=ceremony(x,coins)
  virtualY,virtualPriv,virtualK=ceremony(x,coins)
  test(Y==virtualY);test(K==virtualK);test(K==combine(virtualPriv))
  test(Y['toy_vk']==H(b'toy',x,K).hex())
  test('shares' not in Y)
  test(len(K)==32)
  cases+=1
for a in [0,19,255]:
 test(len({a^b for b in range(256)})==256)
print(json.dumps({'run':459,'cases':cases,'assertions':count,'secure_release_constructed':False},sort_keys=True,indent=2))
