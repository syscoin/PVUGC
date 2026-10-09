#!/usr/bin/env python3
"""Run377 scoped syntactic-completeness proof fixture; NOT a secure KEM."""
import hashlib,json
G=(('XOR',0,1),('XOR',2,3),('XOR',6,7),('XNOR',8,5),('AND',9,4))
n=0

def ck(x):
 global n
 n+=1
 assert x

def op(g,a,b):
 return {'XOR':a^b,'XNOR':a^b^1,'AND':a&b}[g]

def R(x,w):
 return bool(x[0] and (w.bit_count()&1)==x[1])

def comp(x,k,m):
 tabs=[]
 for j,(g,a,b) in enumerate(G):
  tabs.append([op(g,u^m[a],v^m[b])^m[j+6] for u in (0,1) for v in (0,1)])
 return (x,k,hashlib.sha256(str(k).encode()).hexdigest(),m[:6],tuple(map(tuple,tabs)),(k,None) if m[10] else (None,k))

def evaluate(p,w):
 x,k,vk,inp,tabs,release=p
 state=[((w>>i)&1)^inp[i] for i in range(4)]+[x[0]^inp[4],x[1]^inp[5]]
 for j,(g,a,b) in enumerate(G):
  state.append(tabs[j][2*state[a]+state[b]])
 return release[state[-1]],tuple(state)

fixtures=0
for im in range(1<<11):
 m=tuple((im>>i)&1 for i in range(11))
 cases=[((1,im&1),0x1234)]
 if im%32==0: cases=[(x,k) for x in ((0,0),(0,1),(1,0),(1,1)) for k in (0x0000,0x1234,0xffff)]
 for x,k in cases:
  p=comp(x,k,m)
  ck(p==comp(x,k,m))
  valid=[]
  for w in range(16):
   got,s=evaluate(p,w)
   ck((got==k) if R(x,w) else (got is None))
   if R(x,w): valid.append(s)
  ck(len(set(valid))==len(valid))
  bad=list(p);bad[2]='0'*64
  ck(tuple(bad)!=comp(x,k,m))
  bad=list(p);bad[4]=tuple(tuple(1-v if i==0 and j==0 else v for j,v in enumerate(row)) for i,row in enumerate(p[4]))
  ck(tuple(bad)!=comp(x,k,m))
  if valid:
   # Deliberate leak; a proof of compilation correctness is NOT authorization hiding.
   ck([v for v in p[5] if v is not None]==[k])
   ck(p[5][0]==k or p[5][1]==k)
  fixtures+=1
print(json.dumps({'run':377,'status':'PASS','assertions':n,'fixtures':fixtures,'exhaustive_mask_vectors':2048,'all_witness_correctness':True,'malicious_compiler_edit_rejected':True,'toy_key_leak':True,'qpt_security':False,'ZK_or_MPC_implemented':False},sort_keys=True))
