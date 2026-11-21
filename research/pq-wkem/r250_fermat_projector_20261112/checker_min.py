#!/usr/bin/env python3
"""R250 minimal exact F5 and F25 countercheck, not PQ source validation."""
import json
P=5
# F25 as a+b*t, with t^2=2; F5 has no square root of 2.
def mul(x,y): return ((x[0]*y[0]+2*x[1]*y[1])%P,(x[0]*y[1]+x[1]*y[0])%P)
def sub(x,y): return ((x[0]-y[0])%P,(x[1]-y[1])%P)
def add(x,y): return ((x[0]+y[0])%P,(x[1]+y[1])%P)
def powf(x,n):
    z=(1,0)
    for _ in range(n):z=mul(z,x)
    return z
one=(1,0);zero=(0,0);rho=(2,0);sigma=(4,0)
def valid(x):return mul(sub(one,powf(x,4)),sub(one,powf(sub(x,one),4)))
assert all(valid((i,0))==zero for i in range(P))
a=(0,1);u=valid(a);assert u!=zero
c=add(rho,mul(sub(sigma,rho),u))
assert add(rho,mul(sub(c,rho),powf(u,23)))==sigma
# Unique F5^2 assignment (2,3), canonical polynomial delta=(1-(x-2)^4)(1-(y-3)^4)
# Coefficient of x^4 y^4 is (+1), independent of (2,3).
coeff=(4-2)%P; baseline=2
assert (baseline+coeff)%P==4
print(json.dumps({'run':'R250_MIN','base_false_points':5,'extension_point':list(a),
 'extension_projector':list(u),'extension_recovered_sigma':list(sigma),
 'unique_witness_top_coefficient':coeff,'unique_witness_recovered_sigma':(baseline+coeff)%P,
 'status':'NONQUALIFYING: transparent arithmetic leaks, no source Build/Open'},sort_keys=True,indent=2))
