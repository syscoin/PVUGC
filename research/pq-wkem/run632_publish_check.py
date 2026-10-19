from fractions import Fraction as Q
import json
from random import Random
r=Random(632)
checks=0
cases=0
orbits=0
for b in range(1,7):
 N=1<<b
 for h in range(b+1):
  k=1<<h
  for _ in range(11):
   p=[Q(0)]*N
   for weight in [Q(1,2),Q(1,3),Q(1,6)]:
    for s in r.sample(range(N),k):p[s]+=weight/k
   a=[Q(r.randrange(5),4) for s in range(N)]
   correct=sum((p[s]*a[s] for s in range(N)),Q(0))
   density=sum(a,Q(0))/N
   assert sum(p,Q(0))==1 and max(p)<=Q(1,k);checks+=1
   assert density>=Q(k,N)*correct;checks+=1
   nu=Q(r.randrange(5),16);j=r.randrange(N)
   p2=[(1-nu)*p[s]+(nu if s==j else 0) for s in range(N)]
   tv=sum((abs(p[s]-p2[s]) for s in range(N)),Q(0))/2
   assert tv<=nu;checks+=1
   correct2=sum((p2[s]*a[s] for s in range(N)),Q(0))
   assert density>=Q(k,N)*max(Q(0),correct2-nu);checks+=1
   cases+=1
  # Exact tightness for uniform support, acceptance only there.
  assert Q(k,N)==sum([Q(1) if s<k else Q(0) for s in range(N)],Q(0))/N;checks+=1
for b in range(1,9):
 for t in range(b+1):
  root=r.randrange(1<<(b-t)); orbit={root<<t ^ u for u in range(1<<t)}
  assert len(orbit)==1<<t;checks+=1
  assert orbit=={s for s in range(1<<b) if s>>t==root};checks+=1
  for s in orbit:
   for u in range(1<<t):
    assert s^u in orbit;checks+=1
  orbits+=1
print(json.dumps({'run':632,'checker':'run632_publish_check.py','cases':cases,
 'orbits':orbits,'assertions':checks,'status':'PASS','scope':'finite algebra only'},sort_keys=True))
