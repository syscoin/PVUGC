#!/usr/bin/env python3
"""Run 221: exact GF(16)-adjoint closure-five census for the Run-214 N=3,R=1 false fixture."""
from itertools import product
from collections import Counter
import json,sys
A=0
def ck(x,m='assertion failed'):
 global A; A+=1
 if not x: raise AssertionError(m)
class F16:
 def __init__(s):
  s.mul=[[s.m(a,b) for b in range(16)] for a in range(16)]
  s.inv=[0]+[next(b for b in range(1,16) if s.mul[a][b]==1) for a in range(1,16)]
 def m(s,a,b):
  z=0
  while b:
   if b&1:z^=a
   b>>=1;a<<=1
   if a&16:a^=0b10011
  return z
 def pow(s,a,n):
  z=1
  while n:
   if n&1:z=s.mul[z][a]
   n>>=1;a=s.mul[a][a]
  return z
 def sm(s,x):
  z=0
  for a in x:z^=a
  return z
F=F16()
def rref(M):
 M=[r[:] for r in M];p=[];r=0
 if not M:return M,p
 for c in range(len(M[0])):
  q=next((i for i in range(r,len(M)) if M[i][c]),None)
  if q is None:continue
  M[r],M[q]=M[q],M[r];u=F.inv[M[r][c]];M[r]=[F.mul[u][x] for x in M[r]]
  for i in range(len(M)):
   if i!=r and M[i][c]:
    u=M[i][c];M[i]=[x^F.mul[u][y] for x,y in zip(M[i],M[r])]
  p.append(c);r+=1
  if r==len(M):break
 return M,p
def null(M,n):
 R,p=rref(M);o=[]
 for c in range(n):
  if c not in p:
   v=[0]*n;v[c]=1
   for i,q in enumerate(p):v[q]=R[i][c]
   o.append(v)
 return o
def span(M):
 R,p=rref(M);return [R[i] for i in range(len(p))]
def dot(a,b):return F.sm(F.mul[x][y] for x,y in zip(a,b))
def enc(w):
 v=[1]+list(w);out=[]
 for t in range(7):
  # R=1: ell_t=sum_i t^i v_i; alpha is 0 or 1.
  l=F.sm(F.mul[F.pow(t,i)][v[i]] for i in range(4))
  for h in (1,l):
   for x in v:
    for y in v:out.append(F.mul[h][F.mul[x][y]])
 return out
# Exact Run-214 relation w0+2w1+4w2=8 over GF(16).
W=list(product((0,1),repeat=3)); E=[enc(w) for w in W]; stride=16
eq=[]
for h in range(14):
 eq.append([F.mul[e[h*stride]][(w[0]^F.mul[2][w[1]]^F.mul[4][w[2]]^8)] for e,w in zip(E,W)])
C=null(eq,8); BB=span([[F.sm(F.mul[a][E[j][i]] for j,a in enumerate(c)) for i in range(224)] for c in C])
ck(len(BB)==4);ck(len(BB[0])==224);ck(not any((w[0]^F.mul[2][w[1]]^F.mul[4][w[2]]^8)==0 for w in W))
# 56x4 field source; compress its 16 columns to their exact 6D field ambient.
M=[[b[i:i+4] for i in range(0,224,4)] for b in BB]; cols=[[row[j] for row in m] for m in M for j in range(4)]
R,p=rref(cols);U=[R[i] for i in range(len(p))];ck(len(U)==6)
CF=[]
for m in M:
 cc=[]
 for j in range(4):
  v=[row[j] for row in m];c=[v[q] for q in p];rec=[0]*56
  for a,u in zip(c,U):rec=[x^F.mul[a][y] for x,y in zip(rec,u)]
  ck(rec==v);cc.append(c)
 CF.append([[cc[j][i] for j in range(4)] for i in range(6)])
# Adjoint E_a: 6 generators, each 4 rows x 4 source coordinates.
G=[[[CF[k][a][j] for k in range(4)] for j in range(4)] for a in range(6)]
ck(len(rref([[x for row in g for x in row] for g in G])[1])==6)
def pre(normals):
 Q=[]
 for h in normals:
  for j in range(4):Q.append([dot(h,G[a][j]) for a in range(6)])
 return 6-len(rref(Q)[1])
def points4():
 for q in range(4):
  for z in product(range(16),repeat=3-q):yield [0]*q+[1]+list(z)
def planes4():
 for a,b,c,d in product(range(16),repeat=4):yield ([1,0,a,b],[0,1,c,d])
 for a,b,c in product(range(16),repeat=3):yield ([1,a,0,b],[0,0,1,c])
 for a,b in product(range(16),repeat=2):yield ([1,a,b,0],[0,0,0,1])
 for a,b in product(range(16),repeat=2):yield ([0,1,0,a],[0,0,1,b])
 for a in range(16):yield ([0,1,a,0],[0,0,0,1])
 yield ([0,0,1,0],[0,0,0,1])
H=Counter(pre([h]) for h in points4()); P=Counter(pre(list(q)) for q in planes4())
ck(sum(H.values())==4369);ck(H==Counter({2:4352,3:17}));ck(sum(P.values())==70161);ck(P==Counter({0:69632,1:529}));ck(max(P)==1)
# Proof is in the note: supermodular deficiency + scalar-core closure uses exactly these maxima.
out={'run':221,'python':sys.version.split()[0],'assertions':A,'fixture':{'N':3,'R':1,'field':'GF(16), x^4+x+1','field_source_dimension':4,'field_matrix_shape':[56,4],'field_column_ambient_dimension':6,'field_column_ambient_rref_pivots':p,'field_adjoint_domain_dimension':6,'field_adjoint_row_ambient_dimension':4,'field_adjoint_injective':True},'exact_preimage_census':{'row_hyperplanes_total':4369,'row_hyperplane_preimage_dimension_histogram':dict(sorted(H.items())),'row_planes_total':70161,'row_plane_preimage_dimension_histogram':dict(sorted(P.items())),'maximum_field_domain_preimage_dimension_for_row_plane':1},'closure_five_theorem':{'statement':'Every binary 15D adjoint-domain subspace whose GF(16)-closure has field dimension 5 has binary row support at least 12.','binary_15D_closure5_row_support_lower_bound':12,'consequence':'No e15(D)<=11 witness can have GF(16)-closure dimension 5.'},'scope':{'proved':'Exact finite closure-five exclusion for this literal false-source fixture.','not_proved':'Closure six, global e15(D)=12/d5(C)=10, full false-instance hiding, arbitrary-QPT ORIGINAL extraction, malicious distributed setup, or a practical WKEM.'},'status':'PASS'}
out['assertions']=A;print(json.dumps(out,indent=2,sort_keys=True))
