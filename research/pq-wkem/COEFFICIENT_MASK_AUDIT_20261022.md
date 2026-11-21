# Coefficient-mask audit and bounded repair — 22 October 2026

Interactive checkpoint `coefficient-mask-audit-20261022`; no scheduler run ID was supplied. This answers the owner's specific question about cancellation of the currently published residual-mask coefficients. It is not a new generic quotient theorem, nor a complete PQ witness-KEM construction.

## Exact live basis and scope

Connected GitHub reads verified syscoin/PVUGC#1 open/draft/unmerged on branch `research/pq-wkem-validation-20260918`, head `9a49af0af7e8f9e7d917074f25035f2a7f877338`. Latest ordinary comment returned: 6241612333. Relevant exact records:

- Run707 diagonal shield, blob `a201ed7906e53369659a1e56e4a79e904b47b596` (file content read at the head; blob ID also recorded in prior live metadata).
- Run704 residual shield, blob `67e2ea70503c0b4cf9379b89b90d98a536e56bba`, read by blob.
- Run593 typed source gate, blob `29b9168bfff6043810284cd1960400579f224e31`, read at the head.
- Run259 source binding, blob `c7f3b77f0273ca1cbe6f0b31c1a086b8eb3acbf2`, read by blob.
- QUOTIENT_AND_PROBE.md, blob `81e2c51e512afeba8359de29eb4e4daa7b23169b`, read at the head.
- PROOFS.md, blob `9244f23aac6edbfef25243c30164aac27664d2b4`, read through its moment-extraction argument.

The old quotient note already proves that public constraint-span masks can be eliminated by a public quotient. The present work applies that retained fact to the CURRENT residual-shield/spectral interface, gives a complete coefficient-level regression, and verifies a bounded mask-space completion. It must not be presented as a newly discovered general annihilator barrier.

## 1. Exact cancellation criterion

Let V be the finite public coefficient space, with monomial basis including 1, and let P_i be the published multiplier spaces. Put W=span{r_i p: p in P_i} inside V. The public polynomial is

    C(y)=K I + M(y)+sum_i r_i(y) Q_i(y).

A scalar coefficient combination is a linear functional L:V -> F_q, applied entrywise. Normalize L(1)=1 to preserve the coefficient of K. Expanding each Q_i in its published scalar basis gives

    L(C)=K I+L(M)+sum_(i,t) L(r_i p_(i,t)) A_(i,t).

Consequently L annihilates every allowed mask direction exactly when L(W)=0. This statement holds for independent full matrices, diagonal matrices, and secretly conjugated diagonal matrices: it cancels the scalar factors before acting on the hidden matrices or frames. For these families the converse also holds for universal cancellation over all allowed coins, since every direction permits a nonzero matrix.

All coefficients r_i p_(i,t) are public. Construct their coefficient rows as a matrix B. A normalized canceller is just a solution of B*lambda=0, e0*lambda=1. Gaussian elimination needs no ORIGINAL witness and no hidden mask coins; it is polynomial in the explicitly published feature-space dimension.

**Exact alternative:** such a normalized canceller exists iff 1 is NOT in W. Proof: if 1 is in W then L(W)=0 forces L(1)=0. Conversely, if 1 is not in W, extend a basis of W by 1 and define a functional zero on W and one on that new basis vector. Gaussian elimination constructs it.

This is UNIVERSAL symbolic cancellation. Sample-specific cancellation involving the realized matrices can have additional possibilities; absence of the symbolic canceller is not by itself a complete cryptographic security statement.

## 2. Full spectral regression, not merely cancellation of a scalar example

Work over any odd field. Take the complete one-coordinate false SOURCE

    r1(x)=x^2-x=0,  r2(x)=x-2=0.

It has no witness. Initially allow P1=P2=span{1}, which is permitted by the current construction syntax (but has NO Run704 unit-certificate hiding guarantee). With feature order (1,x,x^2), lambda=(1,2,2) has L(r1)=L(r2)=0. It is not evaluation at x=2, which would have vector (1,2,4).

The typed source gates are exactly Run593's

    G(a,b,c,d,xi)=[[a,c,-xi,0],[d,b,0,xi],[0,0,b,c],[0,0,d,a]],

using tuples (x,x,1,x) and (x,1,2,1), and affine private xi. With b=1,m=2,s=5,N=9, independent private mixing factors give affine M(x)=M0+x*M1. At x=2 the source-gate ranks are 4 and 2, so rank M(2)<=6 for EVERY choice of outer factors.

Writing the constant residual masks as A,B gives

    C0=M0+K I-2B,
    C1=M1-A+B,
    C2=A.

The public combination therefore equals

    C0+2C1+2C2=K I+M(2).

Since 6<9, K is an eigenvalue of this matrix without any satisfying SOURCE. The existing field-root decoder followed by public key/tag matching can use this candidate root. Increasing nullity and rejecting rank>4 in a supplied-pair checker does not stop use of an already recovered K: the attacker does not have to obey that checker.

This does NOT contradict Run706/707's point-evaluation rank statement. The combined matrix is not C(2). In fact C(2)=K I+M(2)+2A, which still has the mask. It also does NOT refute Run704's scoped hiding theorem, whose unit-certificate premise is absent for the initial P1,P2.

## 3. An explicit repair of this false-source cancellation

Expand P2 to span{1,x}, so Q2(x)=B+xD with fresh independent D. Keep P1=span{1}. The old probe now leaves -2D. More strongly, there is no normalized functional annihilating ALL allowed mask directions, because

    1=(1/2)r1 - ((x+1)/2)r2.

Thus 1 is in the enlarged W. This is an exact mask-space completion, not an extra evaluator check and not a new hardness assumption. It adds an independently sampled matrix coefficient but no new monomial beyond x^2 in this fixture. It preserves all-witness correctness whenever these residuals are used on a true source, since valid residuals still vanish.

For this false source, full public coefficient hiding follows from the established Run704 translation: for Delta=K'-K set

    A'=A-Delta/2 I,
    B'=B+Delta/2 I,
    D'=D+Delta/2 I.

Then every public coefficient at K' is identical to its previous value at K. Translations preserve each allowed mask distribution, including conditioned secret conjugating frames. The native pk and key tag remain a separate augmented-native security problem. The result is not generic false-instance coverage.

## 4. Why this is NOT a universal true-instance patch

For any valid witness w, Eval_w(1)=1 and Eval_w(W)=0, so a normalized canceller must exist. Gaussian elimination finds a normalized functional whenever this affine system is feasible, without solving the witness relation. It may be a nonmultiplicative moment functional rather than a point evaluation.

Example: for only x^2-x=0, and ANY finite multiplier degree, choose L(1)=1 and L(x^j)=2 for every j>=1 in the feature set. All multiples x^t(x^2-x) vanish, but L(x^2)=2 differs from L(x)^2=4. This functional is -Eval_0+2*Eval_1; linear combinations of valid evaluations inevitably remain in the annihilator. This example has easy witnesses and is not a hard-true cryptanalytic break.

Accordingly the universal requirement cannot literally be 'no one can compute a mask-cancelling combination without a witness.' The meaningful requirement is that no efficient combination or more general processing RECOVERS the capability without enabling ORIGINAL extraction or a separate justified break. Mask cancellation alone need not recover K because L(M) may retain sufficient protection; however the explicit false regression above shows why that residual protection must actually be proved.

A normalized rank-one moment matrix gives a simple consistency test: H=[[1,L(x)^T],[L(x),L(xx^T)]]. Rank one forces L(x_i x_j)=L(x_i)L(x_j); combined with complete quadratic SOURCE residual equations this yields a genuine SOURCE. In our regression H has rank 2. BUT adding this public check to the advertised recovery routine does not constrain an arbitrary attacker. PROOFS.md already has a stronger scoped moment-extraction result. Neither it nor Run259 currently proves that bare key recovery supplies an admissible moment/SOURCE representation. Do not recycle that as a new solved reduction.

## 5. Required cumulative construction change

1. Audit the public quotient W^perp for every proposed multiplier space before crediting residual masks with security.
2. A verified unit certificate closes this specific symbolic mask-removal route on the corresponding FALSE subclass, and permits the Run704 full-view translation proof. Its absence is NOT a general insecurity proof, but leaves this route open.
3. Never infer security of coefficient combinations from an all-point-evaluations rank bound.
4. Analyze the remaining public quotient of M directly, including matrix-valued left/right combinations and nonlinear/QPT processing. Secret diagonal frames, more independent mask samples, lossless compression, public guards, and native signatures do not alone eliminate the scalar quotient.
5. Keep the mask-space completion as a scoped repair; the general hard-true recovery-to-SOURCE arrow is UNPROVED. No claim that all false Syscoin instances have economical certificates is made.

## 6. Execution and adversary model

Honest setup/evaluation here is classical. The cancellation algorithm is classical polynomial time in the published array size and therefore within QPT. It uses public equations and coefficients, no setup oracle, retained secrets, witness, quantum advice, rewinding, or RO programming. The coefficient identities remain true under any later quantum processing. No coherent quantum security theorem is inferred from the test.

The deterministic Python checker passed 1,043 explicit assertions, including 729 exhaustive small linear-space alternatives, nine finite multiplier-degree cases, and 18 independently seeded spectral fixtures split between full, diagonal and privately conjugated diagonal masks. Each of the 18 false-source cancelled matrices contains the intended key as a root; public toy commitment filtering selects it in all 18. All 18 have baseline rank 6 and therefore fail the advertised supplied-pair rank<=4 test while still exposing the key root. Adding the multiplier blocks every normalized symbolic canceller; exact full-coefficient key-shift coupling is verified for four shifts in every fixture. Both executions were byte-identical and Python compilation passed.

Small-field root enumeration is a bounded correctness check, not a cryptographic-scale factoring benchmark. The secret K=67 and deterministic coins are explicitly toy values. No real funds, deployed account, or third-party secret is involved.

Attack taxonomy: scalar seam/linear cancellation is tested directly; secret-frame cancellation follows from scalar linearity; full public coefficient and multi-view processing is allowed; no gate fingerprint claim is needed. Independent fresh masks do not repair the initial symbolic kernel; malicious/retained-randomness and cross-claim security are not proved. Native checking correlations are used only for candidate filtering in the toy experiment and remain part of the security view. Quantum attacks are not needed for the negative result. The positive false-case coefficient coupling is information-theoretic under mask-coin independence.

## Literature and provenance

The underlying quotient fact is already in this repository's QUOTIENT_AND_PROBE.md. Fixed-degree unit-certificate search by linear algebra is established, e.g. De Loera et al., arXiv:0801.3788v1, Sections 1-2 (HTML proof-method discussion checked 22 October 2026). No novel general Nullstellensatz theorem or full new literature audit is claimed. No PDF was analyzed in this checkpoint.

A practical secure PQ WKEM has not been established. The new contribution is the current-interface audit, executable regression, and exact bounded repair, not a complete replacement carrier.
