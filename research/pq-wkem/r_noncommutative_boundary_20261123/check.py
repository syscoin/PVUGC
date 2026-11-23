"""Noncommuting boundary transport test; not a FE or cryptographic security test."""
import random, json
P = 101
rng = random.Random(23112026)
def mm(x,y):
 return ((x[0]*y[0]+x[1]*y[2])%P,(x[0]*y[1]+x[1]*y[3])%P,(x[2]*y[0]+x[3]*y[2])%P,(x[2]*y[1]+x[3]*y[3])%P)
def inv(x):
 d=(x[0]*x[3]-x[1]*x[2])%P
 assert d
 t=pow(d,-1,P)
 return (x[3]*t%P,-x[1]*t%P,-x[2]*t%P,x[0]*t%P)
def rand_mat():
 while 1:
  a=tuple(rng.randrange(P) for _ in range(4))
  if (a[0]*a[3]-a[1]*a[2])%P: return a
ident=(1,0,0,1)
assert mm(inv(rand_mat()),ident)
trials=500
independent_equal=0
correlated_equal=0
correlated_shared_step=0
for t in range(trials):
 a0,a1,b0,b1=[rand_mat() for _ in range(4)]
 m0=mm(inv(a0),b0); m1=mm(inv(a1),b1)
 independent_equal+=int(m0==m1)
 u=rand_mat()
 # If a missing variable must vanish from a local transition,
 # matching boundary transport forces a single z-independent u.
 b0=mm(a0,u); b1=mm(a1,u)
 c0=mm(inv(a0),b0);c1=mm(inv(a1),b1)
 correlated_equal+=int(c0==c1)
 correlated_shared_step+=int(c0==u)
assert independent_equal==0 and correlated_equal==trials and correlated_shared_step==trials
print(json.dumps({"scope":"linear-algebraic boundary check only; no WE, SHA history, source, QPT or native signature","field":P,"trials":trials,"independent_missing_bit_transitions_identical":independent_equal,"forced_local_transitions_identical":correlated_equal,"forced_local_transitions_reveal_shared_step":correlated_shared_step},sort_keys=True,indent=2))
