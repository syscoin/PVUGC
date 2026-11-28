#!/usr/bin/env python3
"""R242 digest-only ideal-mask demonstration; not actual SHA/AuxPoW or WE."""
import json, sympy as sp
p=17
T=sp.Symbol('t')
sigma=13
c=sp.Poly((T-1)*(T-2),T,modulus=p)
F=sp.Poly(1-(T-1)**(p-1)*(T-2)**(p-1),T,modulus=p)
assert F.rem(c)==sp.Poly(1,T,modulus=p)
results=[]
for seed in range(12):
    r=sp.Poly((seed+1)+(seed*seed+3)*T+(seed+5)*T*T,T,modulus=p)
    pub=sp.Poly(sigma*F.as_expr()+c.as_expr()*r.as_expr(),T,modulus=p)
    rem=pub.rem(c)
    assert rem==sp.Poly(sigma,T,modulus=p)
    for t in (1,2): assert int(pub.eval(t))%p==sigma
    results.append({"mask_id":seed,"raw_coefficients":len(pub.all_coeffs()),"remainder":int(rem.eval(0))%p})
print(json.dumps({"run":"R242_QUOTIENT","attempted_random_mask_samples":len(results),"extracted_sigma":sigma,
"all_remainders_same":all(x['remainder']==sigma),
"scope":"digest-only vanishing ideal; no original SHA/AuxPoW source, not a KEM"},sort_keys=True,indent=2))
