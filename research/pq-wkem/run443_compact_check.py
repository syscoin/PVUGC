import json
n,k=8,0xa6
N=1<<n
h=lambda r:(r&k).bit_count()&1
D=lambda r,c:c^h(r)^int(r%7==3)
B=lambda r:1^D(r,0)
score=lambda a:sum(1 if B(r)==((r&a).bit_count()&1) else -1 for r in range(N))
coeff=[score(a) for a in range(N)]
assert coeff[k]==2*sum(r%7==3 for r in range(N))-N
assert max(range(N),key=lambda a:abs(coeff[a]))==k
print(json.dumps({'run':443,'assertions':2,'n':n,'key':k,'recovered':max(range(N),key=lambda a:abs(coeff[a])),'signed_correlation':coeff[k]/N},sort_keys=True))
