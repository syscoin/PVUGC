#!/usr/bin/env python3
"""Run 381: exact finite linear projection bypass; NOT a secure WKEM."""
import itertools,json
q=11
checks=falsecases=0

def ck(b):
 global checks
 checks+=1
 assert b

W=list(itertools.product((-1,0,1),repeat=2))
for a,b in itertools.product(range(q),repeat=2):
 if not (a or b):continue
 for x in range(q):
  honest=[w for w in W if (a*w[0]+b*w[1])%q==x]
  if not honest:falsecases+=1
  z=(x*pow(a,-1,q)%q,0) if a else (0,x*pow(b,-1,q)%q)
  ck((a*z[0]+b*z[1])%q==x)
  for h,K in itertools.product(range(q),repeat=2):
   p=(a*h%q,b*h%q); C=(K+h*x)%q
   ck((C-sum(p[i]*z[i] for i in range(2)))%q==K)
   for w in honest:
    ck((C-sum(p[i]*w[i] for i in range(2)))%q==K)
   ck(((p[0]*pow(a,-1,q)) if a else (p[1]*pow(b,-1,q)))%q==h)
ck(falsecases>0)
a=b=1;x=4
ck(not any((sum(w)%q)==x for w in W))
for h,K in itertools.product(range(q),repeat=2):
 p=(h,h);C=(K+4*h)%q
 ck((C-4*p[0])%q==K)
# Even a rank-deficient A has in-image false-short words.
A=((1,1,0),(2,2,0));x=(4,8);z=(4,0,0)
W3=itertools.product((-1,0,1),repeat=3)
ck(not any(all(sum(A[i][j]*w[j] for j in range(3))%q==x[i] for i in range(2)) for w in W3))
for h1,h2,K in itertools.product(range(q),repeat=3):
 p=[(A[0][j]*h1+A[1][j]*h2)%q for j in range(3)]
 C=(K+h1*x[0]+h2*x[1])%q
 ck((C-sum(p[j]*z[j] for j in range(3)))%q==K)
print(json.dumps({'run':381,'status':'PASS','assertions':checks,'false_short_matrix_word_cases':falsecases,'claim':'public linear projection releases K via unrestricted field preimage','QPT_security':False,'complete_WKEM':False},sort_keys=True))
