# R160 — Syntactic nonlinear annihilator source (bounded offline test)

**Status: no genuine advance toward a secure generic WKEM.** This is an explicitly rejected attempt to repair R159's invariant-column subroutine through polynomial gate-constraint multiples. It was anticipated in R159 and does not supply a complete source or full-public QPT security proof. No optimization, no internet research, no user notification.

Continuity: syscoin/PVUGC#1, open/draft/unmerged at research/pq-wkem-validation-20260918, initial head ca36b0fd3fe6227c8f2ec43772f43363e7fa78f0. Read exact R159 note blob ea2993beadb26c8e5655f58cc365d3d2f4ce0a40 and latest substantive ordinary comment 6718361572. R159 proves that recognizing an arbitrary witness-invariant column can be coNP-complete even when a valid witness is given. The present test instantiates syntactically known invariants instead of calling that coNP subroutine.

## Candidate and exact release equation

Work in Boolean quotient algebra B_n=F_q[z_1,...,z_n]/(z_i²-z_i), q an odd prime. Let m_D(w) be the vector of all Boolean monomials of degree at most D. Given ORIGINAL gate constraints f_j(w)=0, for any polynomial p_j with degree(f_j p_j)<=D, the coefficient column rho_j=coef_B(f_j p_j) is computable in classical polynomial time for constant D, with O(n^D) monomials. For all valid ORIGINAL witnesses, rho_j^T m_D(w)=p_j(w) f_j(w)=0. Such columns do not require discovering the entire witness-difference annihilator D_x^perp.

For the gate c=a*b take Boolean monomial basis (1,a,b,c,ab,ac,bc,abc). Define h0=coef(1), h1=coef(ab-c), rho=coef(a(ab-c))=coef(ab-ac). Over F_7, rank(h0,h1)=2 but rank(h0,h1,rho)=3. So rho is a new invariant relative to the *old* two-row linear base, and it vanishes on all four Boolean gate witnesses (a,b,c)=(a,b,ab).

Concrete candidate (noiseless test below; noisy extension formal): sample r0,r1,u uniformly F_q, and independent bounded e,e0. Publish C=h0*r0+h1*r1+rho*u+e and phase t=r0+Delta*K+e0. An honest witness computes

    t - m_D(w)^T C = Delta*K + e0 - m_D(w)^T e (mod q).

This identity is independent of the witness, of r1 and of u. In a bounded-noise regime it gives SAME K for all valid witnesses. Distinct witnesses need not share intermediate states.

**Fatal security limitation:** in the actual explicit-vector source C, its constant-monomial coordinate is C_empty=r0+e_empty. In the noiseless version every adversary, including one without a witness, recovers K from (t-C_empty)/Delta. The candidate is not a KEM. Concealing these coefficients behind ordinary LWE would need a genuine fully joint challenge simulator, including checking key, aux/context, related capsules and all openings, not an assumed SourceOpen oracle. Merely adding LWE is not a proof of FALSE hiding or arbitrary hard-TRUE recovery extraction.

Furthermore, the syntactic multiplier rho=coef(f_j p_j) is itself a row of the larger degree-D *lifted* constraint matrix G'. The source can be reparameterized as C=G'^T(r0,r1,u)+e; any added column of this form is rowspace-redundant relative to the expanded relation. It does not independently establish LWE hardness. With plain public coefficients, linear algebra recovers the component; with encrypted coefficients, the exact full-public QPT security problem remains. The fact that it lies outside the old rowspace is a functional compiler fact, not foundational security progress.

R153 separately proves that a witness-independent classical PPT full-public source with every-true-witness opening and STATISTICAL hiding for every FALSE arbitrary NP instance would imply NP⊆SZK. That consequence is conditional; neither ordinary QPT-LWE nor the multiplier above establishes the required computational FALSE hiding. This iteration does not evade the statistical barrier or handle arbitrary unauthorized true-instance recovery.

## Full required distribution and handoff

Let the public experiment contain (R_ORIGINAL,x), source/capsule, checking key J/CK, Aux, native verification key and precommitted path-scoped capability, claim/UTXO, anchors, window, branch, context and arbitrarily correlated related capsules, with permitted classical selective openings and retained nonuniform QPT advice. Honest setup and Open must be classical PPT. Needed: real source-dependent setup/opening data and ONE straight-line challenge simulator for all public correlations, such that every valid ORIGINAL witness opens the SAME precommitted native signature. A QPT adversary recovering that signature or producing an accepted fresh native forgery, with no supplied representation, must yield an ACTUAL ORIGINAL witness or independently justified QPT break. Malicious N-of-N setup, honest erasure, pre-funding DA/abort composition, PQ hardness calibration and conditional BTC native endpoint remain unresolved. Do not perform size optimization. No conclusion from the finite checks below regarding quantum security.

This attempt confirms a familiar syntactic route but fails to decrease the indispensable cryptographic obligation. Do not return to arbitrary D_x^perp membership, and do not advertise these columns as independent security. Next examine a genuinely computationally hidden nonlinear ORIGINAL-dependent release that comes with an explicit complete simulator and arbitrary recovery-to-ORIGINAL-witness reduction, rather than a new algebraic mask.

## Exact executed Python 3 standard-library checker

The following source was executed locally before this write. It passed 3,111 checks; stdout is captured verbatim below. This is an algebra/functional experiment only.

~~~python
#!/usr/bin/env python3
"""R160 bounded exact algebra checks, standard library only. No hardness inference."""
import json, itertools, hashlib
Q=7
MONO=[(),(0,),(1,),(2,),(0,1),(0,2),(1,2),(0,1,2)]
N=len(MONO)
def dot(x,y):return sum(a*b for a,b in zip(x,y))%Q
def plus(*xs):return tuple(sum(row[i] for row in xs)%Q for i in range(N))
def scalar(k,x):return tuple(k*v%Q for v in x)
def unit(i):return tuple(int(j==i) for j in range(N))
def z(w):return tuple(__import__('math').prod(w[k] for k in mono)%Q for mono in MONO)
E=unit(0); F=plus(unit(4),scalar(-1,unit(3))); AF=plus(unit(4),scalar(-1,unit(5)))
checks=0
def ck(x, label):
 global checks
 checks+=1
 if not x:raise AssertionError(f'{checks} {label}')
def rank(rows):
 mat=[list(map(lambda v:v%Q,row)) for row in rows];r=0
 for j in range(N):
  piv=next((k for k in range(r,len(mat)) if mat[k][j]),None)
  if piv is None:continue
  mat[r],mat[piv]=mat[piv],mat[r]
  inv=pow(mat[r][j],-1,Q);mat[r]=[v*inv%Q for v in mat[r]]
  for i in range(len(mat)):
   if i!=r:
    k=mat[i][j];mat[i]=[(a-k*b)%Q for a,b in zip(mat[i],mat[r])]
  r+=1
  if r==len(mat):break
 return r
ck(rank([E,F])==2,'base rank');ck(rank([E,F,AF])==3,'syntactic mask outside base rowspace')
valid=[];invalid=[]
for w in itertools.product((0,1),repeat=3):
 v=z(w)
 ck(dot(F,v)==(w[0]*w[1]-w[2])%Q,'constraint evaluation')
 ck(dot(AF,v)==w[0]*(w[0]*w[1]-w[2])%Q,'multiplier eval')
 (valid if w[2]==w[0]*w[1] else invalid).append(w)
ck(len(valid)==4 and len(invalid)==4,'gate consistency')
for w in valid:
 v=z(w);ck(dot(AF,v)==0 and dot(F,v)==0,'all-valid cancellation')
 for key in (0,1):
  for r0,r1,u in itertools.product(range(Q),repeat=3):
   C=plus(scalar(r0,E),scalar(r1,F),scalar(u,AF))
   t=(r0+3*key)%Q
   ck(dot(v,C)==r0 and (t-dot(v,C))%Q==3*key,'every valid witness common phase')
# The additive mask is equivalent to a FULL lifted-row source with three uniform rows.
for r0,r1,u in itertools.product(range(Q),repeat=3):
 C=plus(scalar(r0,E),scalar(r1,F),scalar(u,AF))
 ck(C==plus(scalar(r0,E),scalar(r1,F),scalar(u,AF)),'lifted-source reparam')
# But a single original F-row alone cannot absorb the a*F column.
ck(rank([F,AF])==2,'new mask not base-row scalar')
out={'run':'R160-SYNTACTIC-ANNIHILATOR-SOURCE-20261108','q':Q,'monomial_basis':N,'base_rank':rank([E,F]),'lifted_rank':rank([E,F,AF]),'valid_gate_witnesses':len(valid),'invalid_gate_assignments':len(invalid),'checks':checks,'status':'functional subcomponent only; no full-public QPT hiding or hard-TRUE extraction'}
print(json.dumps(out,indent=2,sort_keys=True))
~~~

Local executable /mnt/data/r160/checker.py SHA-256: 5ed933be6cc8407274e343baedf45cce908375728f335adff2b22e0290a35f13. Its captured.json SHA-256: 4d754c2387d88b66c9cfa6de3ab64940d8a26dbfc32abe5cabfc9a9dd79d1c75.

## Exact captured stdout

~~~json
{
  "base_rank": 2,
  "checks": 3111,
  "invalid_gate_assignments": 4,
  "lifted_rank": 3,
  "monomial_basis": 8,
  "q": 7,
  "run": "R160-SYNTACTIC-ANNIHILATOR-SOURCE-20261108",
  "status": "functional subcomponent only; no full-public QPT hiding or hard-TRUE extraction",
  "valid_gate_witnesses": 4
}
~~~
