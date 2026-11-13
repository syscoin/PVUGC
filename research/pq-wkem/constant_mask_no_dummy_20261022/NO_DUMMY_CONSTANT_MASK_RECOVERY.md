# Constant-mask SOURCE recovery without dummy variables

Checkpoint: `constant-mask-no-dummy-20261022` (interactive; no scheduler run ID supplied).
Repository: syscoin/PVUGC#1, branch research/pq-wkem-validation-20260918.
Live starting head: fa5c69b4922d142f94fe9c19e38bfd7dfffcaa8f, open/draft/unmerged.

## 1. Exact archived implementation and correction

The owner's argument is correct for the actual extended Run706 Python checker. The archive
`PQ_WKEM_RUN706_PUBLISHED_AND_VERIFIED.zip` was present in the active runtime. Only its relevant
checker and provenance were extracted. The unchanged checker's SHA-256 is
`390e4abcf81650050b0efca13390ea13c08893bf62c3c6241cbf2444cd281c2f`, matching its archived provenance.
Its lines 49-57 choose m=8, s=3, N=19 and one constant full random matrix Q[i] per residual.
Line 68 adds residual*Q[i]. These are not general polynomial multiplier masks.

The actual SOURCE has coordinates y=(u,v,a1,b1,a2,b2). It checks Booleanity of u,v and compiles
clauses (u OR v OR v), (NOT u OR v OR v) using two OR gates and one output gate per clause.
At y*=(0,0,0,1,1,1), the eight residuals in code order are (0,0,0,1,0,0,0,0).
The only failure is r=a1*v-a1-v+b1=1. The quadratic coefficient for v*a1 occurs only in r.
Since M is affine, the published coefficient C_[v*a1] is exactly that residual's mask A.
Consequently the public attacker computes T=C(y*)-C_[v*a1]=K I+M(y*).
Seven typed gates have rank 2; the failed gate has rank 4. Thus rank(T-KI)<=18<19
for every choice of outer factors and internal affine mixing forms. K is a field eigenvalue.
No SOURCE witness, hidden setup factor, retained random seed, or dummy input is used.

The archive's original 1,426 checks still pass. That is compatible with the defect: the
advertised rank threshold is N-s=16, whereas the attacker only needs rank(T-KI)<19.
The attacker is not required to satisfy the advertised rank predicate before using a key.

This supersedes any suggestion that the demonstrated failure needed artificial dummy inputs
or only an external enlargement beyond the actual archived configuration. It does not say
that s=1 is broken by THIS rank argument; a separate committed unmasked regression is below.

## 2. Executed end-to-end coefficient recovery

The unchanged archived script was executed with stdout captured. A separate public_attack
function received ONLY q and the complete public constant/linear/quadratic coefficient arrays.
It computed T and factored its characteristic polynomial over F_101. It did not receive the
key, factors, masks, setup seed, or a witness. The setup reference was consulted only afterward.

Observed exact values:
- point-evaluation rank rank(C(y*)-K I)=19;
- cancelled rank rank(T-K I)=18;
- advertised acceptance threshold=16;
- field-valued roots returned by factorization: [27];
- archived reference K=27.

Thus this fixture recovers the key uniquely WITHOUT adding any selector or enumerating F_101.
In general, factoring the characteristic polynomial lists at most N distinct candidates
containing K. Uniformly selecting a distinct field root succeeds with probability >=1/N;
a correctly scoped public exact-key selector can improve selection under its own assumptions.
NTL's primary documentation describes finite-field factorization and root routines:
https://libntl.org/doc/ZZ_pXFactoring.cpp.html . No native signature or real account was attacked.

## 3. General theorem for this 3CNF compiler and constant masks

Let t original Boolean variables and c clauses be compiled with DISTINCT helpers a_j,b_j.
Every clause contains three possibly repeated or negated variable literals l1,l2,l3. Use
m=t+3c typed constraints and n=t+2c free SOURCE coordinates:
- original-variable Booleanity;
- l1*l2-l1-l2+a_j=0;
- a_j*l3-a_j-l3+b_j=0;
- b_j-1=0.
All appear as scalar typed gates with fourth scalar 1, so valid tuples are nondegenerate.
Assume M(y) is affine and publish C(y)=K I+M(y)+sum_i r_i(y) A_i with CONSTANT matrix A_i.
The A_i can be full matrices, diagonal matrices, or fixed privately conjugated diagonals.

Choose ANY Boolean original assignment x, e.g. all zeros; no satisfiability search is needed.
Set a_j=l1 OR l2 and b_j=1. Every Booleanity, first OR, and output constraint holds. The
second OR residual equals 1 exactly for clauses unsatisfied by x, and is zero otherwise.
Let f<=c be the number of such clauses. If l3=x_k then the coefficient of a_j*x_k is A_j;
if l3=1-x_k it is -A_j. This monomial appears in no other residual because helpers are
clause-local, and it has no contribution from affine M. Thus every needed mask is directly
available as a signed public coefficient. Subtract their known residual-weighted sum from
C(y) to obtain T=K I+M(y).

With scalar block size b=1 and N=2m+s,
    rank(T-K I)<=2(m-f)+4f=2m+2f.
Therefore s>2f guarantees K among T's eigenvalues. The uniform condition s>2c suffices for
EVERY formula and EVERY Boolean assignment in this specified compiler. No dummy variables
are required. With block size b, the analogous sufficient condition is s>2b f, not s>2f.

Run707's conservative diagonal-mask bound is binom(N,s)*q^(n+1-s). To certify any bound
strictly below one through that expression requires s>=n+2. In the scalar compiler,
n=t+2c, so this implies s>2c. Accordingly its normal certified margin with CONSTANT masks
falls within the theorem. The argument covers every 3CNF formula compiled as above, not
arbitrary encoders named 3CNF or arbitrary polynomial mask spaces. If t/c degenerate, the
stated literal/helper syntax is the condition; the standard nonempty 3CNF case is intended.

A constant polynomial is allowed by Run707's syntax, but a mask Q_i(y) with genuine variable
terms can contaminate the isolated coefficient. This proof does NOT establish recovery for
all such choices. In particular, it does not contradict Run704's unit-certificate false-
instance masking theorem: that theorem has a separate mask-space premise.

## 4. Separate unmasked/minimal-margin status, not the same attack

Before this iteration, commit fa5c69b4922d142f94fe9c19e38bfd7dfffcaa8f and ordinary comment
6356389755 already recorded recovery against C0=M0+KI, Cj=Mj at N=2bm+1, without residual
shields, on a complete connected projectively safe false-source family. Its full proof is
`research/pq-wkem/unmasked_spectral_20261022/UNMASKED_SPECTRAL_PUBLIC_RECOVERY.md`, blob
287e824a7c4c9e8dc165a73a77aae2b2ec8e6701. The attached local note matches that Git blob.

This iteration independently reimplemented and reran that existing public matrix attack on
two bounded F_65537 instances. It is NOT claimed as a newly discovered attack:
- b=1,m=32,N=65,s=1: roots [35957,50027], reference K=50027;
- b=2,m=32,N=129,s=1: roots [50027], reference K=50027.
Both use only public slices as attacker input and finite-field polynomial factoring, with
no witness or field enumeration. The shared reference key is a synthetic test value.
The original note separately records 257-bit-modulus runs; those were NOT rerun here.

For b=2 the existing attack uses Q=C_a^-1, A=Q C_c, B=Q C_d, H=[A,B]^2,
F0=[H,Q C0], F1=[H,Q], and the public matrix F1^-1 F0. Its justification and public-inverse
conditions are in the pinned note; no universal claim for every dense/QAP source, larger
block size, or every setup sample is made. The two failures must not be conflated.

## 5. Cumulative disposition and model

The constant-mask Run706 fixture and the specified scalar Run707 3CNF family are broken at
the release layer; their supplied-input rank lemmas are not thereby false. The unmasked
small-block compiler also has a separate scoped executed recovery regression. Neither is
merely waiting for a missing proof of security under the already-broken scope.

Source-rank correctness and public spectral decoding remain reusable mathematical pieces,
but cannot be counted as a secure carrier. Removing padding, changing the official guard,
secretly conjugating constant masks, or losslessly compressing the public coefficients does
not resolve the applicable public attacks. No secure repair is asserted here.

Honest algorithms and attacks are classical. The explicit attack is therefore allowed for
an arbitrary-QPT threat model. There is no QROM, rewinding, advice copying, or oracle access.
The theorem is conditional only on the specified syntax and finite-field algebra, not a
new computational assumption. False-instance security, hard-true extraction, malicious
setup, multi-capsule composition, and actual SYS/BTC integration remain unsolved for a
replacement construction. Production and automation are unchanged; no completion claimed.

Artifacts: original archived checker, exact new archive wrapper, captured original stdout,
validation and public input/output; independent unmasked rerun and output. Reruns are not
additive trials. The full checker files, not only excerpts, are preserved.
