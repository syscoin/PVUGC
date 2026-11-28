# 2026-11-24 — Explicit multiplicative determinant pencil (NONQUALIFYING)

## Selection and provenance

Actual syscoin/PVUGC PR #1 open/draft/unmerged, branch research/pq-wkem-validation-20260918, start and pre-write head 53da0f700b77099b637d0ec864cc2c40439ef7e3. Read PR metadata, recent substantive discussion through R225, exact head SOURCE_MULTI_TOKEN_CUT_INTERSECTION_20261124.md (blob 98f8b1193f1e2eb5d0b820cf6de325a45d2e8549), and R327 blob ab7602bfc54403bf68294034557206f62d69a5dc. No new Core source claim, real source verification, whole PR diff, web or external literature.

Missing operation: offline polynomial-time serialization of a common hidden pad that can be recovered by each ORIGINAL accepted source trace, with jointly secure public distribution and no raw invalid-trace leakage. Instead of low-degree additive masks or independent cut tokens, this attempt uses a **high-degree multiplicative acceptance polynomial represented by a public randomized determinant pencil**. Its Boolean invalid-trace determinant is identically ZERO, not a noisy value of a private coefficient polynomial. Hence R327's particular invalid-Boolean-trace interpolation attack and the latest independent-cut fake sampler do not apply unchanged. The matrix coefficients are explicitly published; there is no private evaluator. The key question is whether those coefficients allow extending evaluation beyond the Boolean domain. They do.

## 1. Actual candidate algorithms

Compile the fixed full ORIGINAL verifier for the three independent OR grounds to a Boolean circuit on the canonical padded source certificate; let z be its input and gate-trace bits. Use field F of order q exponential in lambda (e.g. GF(2^lambda) with public field representation), with the bounded gate count polynomial in lambda. Represent each Boolean gate and the accept-output constraint by a polynomial f_j of degree at most two whose value on Boolean z is 0 when consistent and 1 when inconsistent. In characteristic two, AND violation is c+ab, XOR violation c+a+b, NOT violation c+a+1, and fixed output c+1. The public statement/context is fixed in these constraints, including ORIGINAL admission/relevance; input formatting, bit lengths, and any external source checks must be compiled, not assumed. Every valid w has its actual full trace z(w).

Set P(z)=product_j (1-f_j(z)). On the Boolean cube P equals 1 exactly on a fully accepting trace and equals 0 on every other trace. Degree is at most 2m. This construction uses no field hardness assumption: field arithmetic is a transparent compiler, not a discrete-log primitive.

Build a directed acyclic arithmetic branching program: each sparse factor 1-f_j is a parallel set of monomial paths (coefficient edge followed by variable edges); concatenate factors in series. Let A(z) be the strictly upper triangular adjacency matrix with affine entries, summing parallel edge labels, s its start and t its terminal. With n vertices, B(z)=I-A(z) has determinant 1 and inverse sum_{k=0}^{n-1} A(z)^k. Define the (n+1)-square pencil

    L(z) = [[B(z), e_t],[-e_s^T,0]].

The Schur complement gives det L(z)=e_s^T B(z)^(-1)e_t=P(z). Size is O(m) for bounded sparse gate constraints. Publish only masked coefficient matrices, not the masks:

    K <- uniform F^*, U,V <- random invertible matrices,
    scale one row of U so det(U)det(V)=K;
    M_i=U L_i V for each coefficient L_i of L(z)=L_0+sum_i z_i L_i.
    C=(context, M_0,...,M_N, S XOR XOF(context,canonical(K),|S|)).

Here S is the exact preauthorized safe native cancel signature, native VK/message included in context. Erase masks and K. For any valid ORIGINAL witness compute z(w), evaluate M(z) and take det M(z)=K, then unmask S. This returns the SAME S for every valid witness regardless of which branch was used. Invalid Boolean z gives determinant zero even if the honest verifier check is omitted. The explicit serialized setup/open are polynomial in N,m,lambda; matrix arithmetic and output mask hashing have no hidden secret evaluator. No claim that the candidate achieves security or that the reference fixture instantiates the actual source circuit.

## 2. Full-public failure: off-domain field evaluation

Every M_i is public. Anyone can compute M(a)=M_0+sum_i a_i M_i for an arbitrary field vector a, not just Boolean trace bits. The determinant identity is a polynomial identity over the field:

    det M(a)=K P(a).

P itself is public. Sample a uniform field vector and, whenever P(a) != 0, return det M(a)/P(a). This is exact K, and yields exact S from the actual capsule, not a substitute signature. The attack never learns U,V, never produces a witness, never needs to query an honest Boolean evaluation interface, and does not break a hash.

For TRUE statements P is nonzero as a polynomial (it evaluates to 1 somewhere). More generally if every factor is a nonzero formal polynomial, their product is nonzero because a polynomial ring over a field is an integral domain, even when the Boolean system is FALSE. A nonzero polynomial of total degree d has probability at most d/q of vanishing on a uniform field vector. This follows by induction in the number of variables: write it as a polynomial of degree r in the last variable, leading coefficient of degree <=d-r; the leading coefficient vanishes with probability <=(d-r)/q by induction and otherwise at most r last-variable choices are roots. Thus success in one evaluation is >=1-2m/q and repeating independently reduces failure geometrically. The field size and dimension permit polynomial-time Gaussian elimination and field arithmetic. A classical PPT attacker is also admissible in the QPT game. The FALSE example with contradictory accept constraints z_i=0 and z_i=1 has P divisible by z_i(1-z_i), nonzero formally though zero on every Boolean trace. No claim that a specific deployed bridge FALSE instance was evaluated. For TRUE the recovery works regardless of the source's witness hardness, so cannot supply the desired reduction except if original witness search itself is easy.

No FALSE simulator hiding S can hold for the example: two distinct fixed S give distinguishable capsules by this public recovery. The native VK correlation, sibling capsules and malicious-source side information are unnecessary to the attack (they cannot restore secrecy once K is recovered). No QROM programming assumption or classical extraction lift is used.

## 3. Repair boundary

Restricting Open to Boolean bits is an unenforceable honest-code check on public coefficient matrices. Even using a tiny base field does not generally prevent evaluations: one may embed the public coefficients in an extension field and apply the identical determinant identity there; any recovered K is canonically in the base field. A single tiny K would in addition have inadequate entropy. Replacing P by its Boolean multilinear normal form would require a new compact, **privately randomized** representation whose off-domain evaluations do not expose a known normalizer. Merely computing a known normalized P in any efficient public arithmetic circuit still allows division at a random nonzero point, and explicit multilinearization may be exponentially large. No such representation or simulator is supplied. Do not follow with other matrix dimensions, field bases, known polynomial scaling, or public arithmetic representations of K times a known P. The relevant changed equation would need a secret-dependent, computationally hiding nonlinear extension with a serialized public evaluation mechanism that neither admits known off-domain normalization nor leaks via the previous invalid trace or splice regressions.

## 4. Executed check and limitations

Local Python 3 standard-library checker below, using prime q=65537 only as a small transparent arithmetic fixture, checked det L=P and det M=KP on every Boolean assignment in two examples. One TRUE fixture has exactly one satisfying Boolean trace; the FALSE one has zero. One arbitrary field trial recovered the hidden scale in each case. This tests the exact matrix identity and recovery algorithm, not real source verification, full-size implementation, security parameters, QPT hardness, or native signature generation.

Actual checker SHA256 f4c9217dd4b556967811627f0f647da7be06bb9de76b693304aa59c9c64d5352; stdout file SHA256 35a853aeb5bc84d47e3d463a51292591cef199b216db9a8d1a9de30d9926a83e.

```json
{"false": {"accepting_boolean_traces": 0, "actual": 6461, "dimension": 10, "field_trials": 1, "recovered": 6461}, "field": 65537, "seed": 20261124, "true": {"accepting_boolean_traces": 1, "actual": 39389, "dimension": 8, "field_trials": 1, "recovered": 39389}}
```

Exact executed checker (including final newline):
```python
import random, json
# Prime field for a small arithmetic check only. No field hardness assumption.
Q=65537
rng=random.Random(20261124)
def inv(x): return pow(x%Q,-1,Q)
def det(A):
    a=[r[:] for r in A]; d=1
    for i in range(len(a)):
        k=next((k for k in range(i,len(a)) if a[k][i]%Q),None)
        if k is None:return 0
        if k!=i:a[k],a[i]=a[i],a[k];d=-d
        p=a[i][i]%Q;d=d*p%Q
        for k in range(i+1,len(a)):
            c=a[k][i]*inv(p)%Q
            for j in range(i+1,len(a)):a[k][j]=(a[k][j]-c*a[i][j])%Q
            a[k][i]=0
    return d%Q
def mul(A,B):
    return [[sum(x*y for x,y in zip(r,c))%Q for c in zip(*B)] for r in A]
def rndmat(n):
    while True:
        a=[[rng.randrange(Q) for _ in range(n)] for _ in range(n)]
        if det(a):return a
# Sparse polynomials: 1-f_j, with each term (coefficient, tuple of variable indexes).
# x2=x0*x1; x2=1 for true. False adds x2=0.
true_factors=[[(1,()),(-1,(2,)),(1,(0,1))],[(1,(2,))]]
false_factors=true_factors+[[(1,()),(-1,(2,))]]
def poly(factors,z):
    out=1
    for factor in factors:
        p=0
        for c,vs in factor:
            v=c
            for i in vs:v=v*z[i]%Q
            p+=v
        out=out*p%Q
    return out
# Each factor is a parallel collection of monomial paths; each path
# begins with its coefficient, followed by one edge per variable.
def pencil(factors,nvars):
    edges=[]; count=1; s=0
    for factor in factors:
        pending=[]
        for c,vs in factor:
            if not vs:pending.append((s,None,c));continue
            p=count;count+=1;edges.append((s,p,None,c))
            for i in vs[:-1]:
                q=count;count+=1;edges.append((p,q,i,1));p=q
            pending.append((p,vs[-1],1))
        t=count;count+=1
        edges.extend((p,t,i,c) for p,i,c in pending);s=t
    n=count+1
    mats=[[[0]*n for _ in range(n)] for _ in range(nvars+1)]
    for i in range(count):mats[0][i][i]=1
    for p,t,i,c in edges:
        mats[0 if i is None else i+1][p][t]=(-c)%Q
    mats[0][s][count]=1;mats[0][count][0]=Q-1
    return mats
def evaluate(mats,z):
    n=len(mats[0]);weights=[1]+list(z)
    return [[sum(w*m[i][j] for w,m in zip(weights,mats))%Q for j in range(n)] for i in range(n)]
def test(factors):
    L=pencil(factors,3);n=len(L[0]);left=rndmat(n);right=rndmat(n)
    K=rng.randrange(1,Q);scale=K*inv(det(left)*det(right))%Q
    left[0]=[x*scale%Q for x in left[0]]
    public=[mul(mul(left,m),right) for m in L]
    accepted=0
    for b in range(8):
        z=[(b>>j)&1 for j in range(3)];p=poly(factors,z)
        assert p in (0,1)
        assert det(evaluate(L,z))==p
        assert det(evaluate(public,z))==K*p%Q
        accepted+=p
    # Adversary knows factors and public pencil, never private matrices or K.
    for trials in range(1,101):
        z=[rng.randrange(Q) for _ in range(3)];p=poly(factors,z)
        if p:
            recovered=det(evaluate(public,z))*inv(p)%Q
            break
    else:raise AssertionError('no nonzero public polynomial evaluation')
    assert recovered==K
    return {'dimension':n,'accepting_boolean_traces':accepted,'field_trials':trials,'recovered':recovered,'actual':K}
print(json.dumps({'field':Q,'seed':20261124,'true':test(true_factors),'false':test(false_factors)},sort_keys=True))
```

NONQUALIFYING: no ORIGINAL secure release, full-public simulator, hard-TRUE recovery/extraction, malicious setup or native endpoint completion. All three ORIGINAL grounds remain independent, R316 is only a coverage regression, R225 requires explicit slot-global or activation-bound native scope. No PR comment, production/deployment/automation change.
