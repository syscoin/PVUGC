#!/usr/bin/env python3
"""Synthetic noncommutative nilpotent local-gate source release screen.
Exact algebra only. Not ORIGINAL Bitcoin/Syscoin evidence nor FE/WE.
"""
import hashlib, json
P=103
I=((1,0),(0,1)); N=((0,1),(0,0)); ZERO=((0,0),(0,0))

def mul(a,b):
 return tuple(tuple(sum(a[i][k]*b[k][j] for k in range(2))%P for j in range(2)) for i in range(2))
def sc(k,a):return tuple(tuple((k*a[i][j])%P for j in range(2)) for i in range(2))
def det(a):return (a[0][0]*a[1][1]-a[0][1]*a[1][0])%P
def inv(a):
 d=det(a)
 assert d!=0
 return sc(pow(d,-1,P),((a[1][1],-a[0][1]),(-a[1][0],a[0][0])))
def trace(a):return (a[0][0]+a[1][1])%P

def sample_mat(seed):
 for z in range(10000):
  raw=hashlib.sha256(f'{seed}|{z}'.encode()).digest()
  m=((raw[0]%P,raw[1]%P),(raw[2]%P,raw[3]%P))
  if det(m):return m
 raise Exception('no invertible')

def ch(x,y,z):return (x&y)|((1-x)&z)
# A t=ch(x,y,z); B t=ch(x,z,y); C y!=z (all share xyzt).
def pred(j,w):
 x,y,z,t=w
 return (t==ch(x,y,z),t==ch(x,z,y),y!=z)[j]

def public_fixture(seed):
 K=1+int.from_bytes(hashlib.sha256(f'{seed}|K'.encode()).digest(),'big')%(P-1)
 R0,R1,R2=(sample_mat(f'{seed}|R{i}') for i in range(3))
 R=[R0,R1,R2,sc(K,R0)]
 # For each clause, PUBLIC transition for each local 4-bit tuple, not secret material.
 transitions=[]
 for j in range(3):
  table={}
  for n in range(16):
   w=tuple((n>>(3-i))&1 for i in range(4))
   d=I if pred(j,w) else N
   table[n]=mul(mul(inv(R[j]),d),R[j+1])
  transitions.append(table)
 def eval_selected(indices):
  v=I
  for j,n in enumerate(indices):v=mul(v,transitions[j][n])
  return v
 assert all(not all(pred(j,tuple((n>>(3-i))&1 for i in range(4))) for j in range(3)) for n in range(16))
 # Each global choice gives zero or a nonzero nilpotent so scalar trace/det probes vanish.
 for n in range(16):
  e=eval_selected([n]*3)
  assert trace(e)==0 and det(e)==0 and mul(e,e)==ZERO
 # Three individually valid clause assignments, but no common valid assignment.
 chosen=[next(n for n in range(16) if pred(j,tuple((n>>(3-i))&1 for i in range(4)))) for j in range(3)]
 spliced=eval_selected(chosen)
 assert spliced==sc(K,I)
 assert spliced[0][0]==K
 return {'seed':seed,'valid_global_assignments':0,'all_16_global_probes_nilpotent':True,
         'locally_satisfying_choices':chosen, 'choices_inconsistent':len(set(chosen))>1,
         'spliced_product_is_K_times_identity':True,'recovered_secret':spliced[0][0],
         'hidden_scalar':K}

assert mul(N,N)==ZERO
rows=[public_fixture(s) for s in range(24)]
out={'model':'noncommutative gauge with nilpotent invalid traces; synthetic FALSE Ch clauses',
     'fixtures':len(rows),'all_trace_det_fixed_probes_hidden':all(x['all_16_global_probes_nilpotent'] for x in rows),
     'all_spliced_locals_recover_secret':all(x['recovered_secret']==x['hidden_scalar'] for x in rows),
     'example':rows[0],
     'scope':'not a practical serialized source-conditioned FE/WE; does not process ORIGINAL certificates or attest security'}
print(json.dumps(out,sort_keys=True,indent=2))
