import json,random
A=(0,1);B=(1,2);C=(0,2);G=(A,B,C);ODD=(A,B,A,B,C)
def perm(seq):
 out=[]
 for x in range(8):
  y=x
  for a,b in seq:y^=((y>>a)&1)<<b
  out.append(y)
 return tuple(out)
identity=tuple(range(8));assert perm(ODD)==identity
assert perm((A,B))!=perm((B,A))
assert perm((A,C))==perm((C,A))
r=random.Random(461);count=0;recovered=0;moves=0
for trial in range(32):
 for bit in [r.randrange(2) for _ in range(16)]:
  s=list(ODD if bit else ())
  for _ in range(12):
   if r.randrange(2)==0 or len(s)<2:
    g=r.choice(G);p=r.randrange(len(s)+1);s[p:p]=[g,g]
   else:
    indices=[i for i in range(len(s)-1) if perm((s[i],s[i+1]))==perm((s[i+1],s[i]))]
    if indices:
     i=r.choice(indices);s[i],s[i+1]=s[i+1],s[i]
    else:
     g=r.choice(G);s.extend([g,g])
   assert perm(s)==identity;assert len(s)%2==bit;count+=2;moves+=1
  assert len(s)%2==bit;recovered+=1;count+=1
print(json.dumps({'run':461,'assertions_passed':count+3,'truth_table':list(perm(ODD)),'rewrites':moves,'leaked_bits':recovered,'context':'limited rewrite moves; not CCMR/RIO/WE/WKEM'},sort_keys=True,indent=2))
