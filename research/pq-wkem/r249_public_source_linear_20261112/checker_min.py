#!/usr/bin/env python3
"""R249 minimal finite-field failures. Not original source WE or consensus."""
import json
p=257
I=[[1,0],[0,1]]
def mul(A,B):
    return [[sum(A[i][k]*B[k][j] for k in range(len(B)))%p for j in range(len(B[0]))] for i in range(len(A))]
def conj(D):
    A=[[1,7],[0,1]];Ai=[[1,-7%p],[0,1]]
    return mul(mul(A,D),Ai)
# Two-character Boolean quotient module. Valid toy witness is 2.
support=[0,2]
P=[conj([[int((w>>i)&1) if j==k else 0 for k in range(2)] for j,w in enumerate(support)]) for i in range(2)]
for X in P:assert mul(X,X)==X
assert mul(P[0],P[1])==mul(P[1],P[0])
Q=conj([[0,0],[0,1]])
sigma,rho=91,131
C=[[(sigma*Q[i][j]+rho*(I[i][j]-Q[i][j]))%p for j in range(2)] for i in range(2)]
assert mul(C,Q)==[[(sigma*Q[i][j])%p for j in range(2)] for i in range(2)]
assert mul(C,Q)[1][1]*pow(Q[1][1],-1,p)%p==sigma
# An implicit ordinary polynomial ignores Boolean quotient restrictions.
def U(x):return x*(x-1)%p
def F(x):return (rho+(sigma-rho)*U(x))%p
assert U(0)==U(1)==0
assert (F(0)+(F(2)-F(0))*pow(U(2),-1,p))%p==sigma
# The first two *occurrences* are the same underlying source bit x,
# but public transition choices can be set inconsistently to (0,1).
A=[[[1,0],[0,1]],[[0,1],[0,1]]]
B=[[[0,1],[0,1]],[[1,0],[0,1]]]
c=[3,11,19]
R=[[[1,x],[0,1]] for x in c]
Ri=[[[1,(-x)%p],[0,1]] for x in c]
M=[[mul(mul(Ri[i],T),R[i+1]) for T in row] for i,row in enumerate([A,B])]
u=mul([[1,0]],R[0]);v=mul(Ri[2],[[sigma],[0]])
def evaluate(a,b):return mul(mul(mul(u,M[0][a]),M[1][b]),v)[0][0]
assert evaluate(0,0)==evaluate(1,1)==0
assert evaluate(0,1)==sigma
print(json.dumps({'run':'R249_MIN','module_supported_toy_witnesses':2,'public_module_sigma':sigma,'false_boolean_off_domain_sigma':sigma,'consistent_source_bit_outputs':[evaluate(0,0),evaluate(1,1)],'inconsistent_raw_output':evaluate(0,1),'status':'nonqualifying algebraic regressions only'},sort_keys=True,indent=2))
