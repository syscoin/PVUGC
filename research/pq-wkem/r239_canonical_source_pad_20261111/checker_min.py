#!/usr/bin/env python3
"""Source-indexed single-pad algebra only; no original BTC/SYS verifier or WE."""
import hashlib,json
H=lambda x: hashlib.sha256(x).digest()
D=lambda x: H(H(x))
P=lambda x: H(b'R239-pad-domain/'+x)
X=lambda a,b:bytes(u^v for u,v in zip(a,b))
child=[D(b'child'+bytes([i])) for i in range(5)]
# Two different parent certificates for every same alternative child.
cert=[(c,D(b'parent'+c+bytes([v]))) for c in child[1:] for v in range(2)]
assert len({p for c,p in cert})==8 and len({c for c,p in cert})==4
sigma=H(b'frozen-sigma')
res={}
for label,indices in [('parent',[p for c,p in cert]),
                      ('child',[c for c,p in cert]),
                      ('baseline',[child[0] for c,p in cert])]:
    ciphertext=X(sigma,P(indices[0]))
    res[label]={'unique':len(set(indices)),
                'correct':sum(X(ciphertext,P(i))==sigma for i in indices),
                'public_baseline_attack':X(ciphertext,P(child[0]))==sigma}
assert (res['parent']['correct'],res['child']['correct'],res['baseline']['correct'])==(1,2,8)
assert res['baseline']['public_baseline_attack']
print(json.dumps(res,sort_keys=True,indent=2))
