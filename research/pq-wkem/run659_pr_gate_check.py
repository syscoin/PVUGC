import itertools,json
p=[t for t in itertools.product(range(5),repeat=4) if sum(t)==4]
c=list(itertools.product((0,1,2),repeat=4))
n=0
for a in p:
 for b in p:
  tv=sum(abs(x-y) for x,y in zip(a,b))
  for k in c:
   assert abs(sum((x-y)*v for x,y,v in zip(a,b,k)))<=tv
   n+=1
assert len(p)==35 and len(c)==81 and n==99225
print(json.dumps({'run':659,'assertions':n+1,'distributions':35,'channels':81,'scope':'finite data processing only, no FHE security'} ,sort_keys=True))
