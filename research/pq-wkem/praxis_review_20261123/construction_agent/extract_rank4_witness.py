"""Extract and verify one rank-four boundary certificate.

This uses the exact boundary checker source to expose its finite linear map,
then Gaussian elimination produces a nonhonest passing stack. The dynamically
exposed environment is only a local code reuse device; no adversary state,
oracle query log, or unknown private information is assumed.
"""
import hashlib
import inspect
import json
from pathlib import Path
import tie_rank4_boundary as check


def nullspace(rows,q):
    a=[row[:] for row in rows]
    n=len(a[0]); r=0; piv=[]
    for col in range(n):
        p=next((i for i in range(r,len(a)) if a[i][col] % q),None)
        if p is None: continue
        a[r],a[p]=a[p],a[r]
        scale=pow(a[r][col],-1,q)
        a[r]=[x*scale % q for x in a[r]]
        for i in range(len(a)):
            if i!=r and a[i][col]:
                k=a[i][col]
                a[i]=[(x-k*y) % q for x,y in zip(a[i],a[r])]
        piv.append(col); r+=1
    out=[]
    for free in range(n):
        if free in piv: continue
        v=[0]*n;v[free]=1
        for i,col in enumerate(piv):v[col]=-a[i][free] % q
        out.append(v)
    return out


q,c,seed=7,3,0
src=inspect.getsource(check.run)
assert src.count("    results=[]") == 1
src=src.replace("    results=[]","    return locals()\n    results=[]",1)
env=dict(check.__dict__)
exec(compile(src,"<expose_rank4_checker>","exec"),env)
d=env['run'](q,c,seed)
width=d['width']; residual=d['residual']; honest=[v for _,v in d['honest']]
cols=[residual([int(i==j) for i in range(width)],'none') for j in range(width)]
rows=list(map(list,zip(*cols)))
kernel=nullspace(rows,q)
hrank=check.row_rank(honest,q)
w=next(v for v in kernel if check.row_rank(honest+[v],q)>hrank)
assert not any(residual(w,'none'))
mats=[]
for a in range(len(d['copies'])):
    mat=[[0]*4 for _ in range(4)]
    for off,(i,j) in enumerate(d['pairs']):
        mat[i][j]=mat[j][i]=w[a*len(d['pairs'])+off]
    mats.append(mat)
stackrank=check.row_rank([r for m in mats for r in m],q)
assert stackrank==4
# The only extra family here may have nonzero key corner; record, don't infer.
out={"scope":__doc__,"q":q,"c":c,"n":6,"seed":seed,"M":d['M'],"z":d['z'],
     "copies":d['copies'],"stack_matrices":mats,"stack_row_rank":stackrank,
     "residual_zero":True,"passing_dimension":len(kernel),"honest_span_dimension":hrank,
     "honest_plus_certificate_dimension":check.row_rank(honest+[w],q),
     "key_corner":mats[0][0][0],"all_corners":[m[0][0] for m in mats],
     "input_checker_sha256":hashlib.sha256(Path(check.__file__).read_bytes()).hexdigest(),
     "source_sha256":hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
print(json.dumps(out,indent=2,sort_keys=True))
