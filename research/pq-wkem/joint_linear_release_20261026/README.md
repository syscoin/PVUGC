# Helper-aware vector release: an explicit joint LWE theorem

Record: `joint-linear-release-20261026`. Offline mathematical research.
Repository continuity: syscoin/PVUGC#1, branch
`research/pq-wkem-validation-20260918`, starting head
`5fc7ca8922b69df2c884ad52721ff088d72533a9`.

## 0. Exact result, and what is NOT established

The user's WPRF-to-native-key wrapper is a correct conditional composition,
subject to its stated joint sampler and native simulation requirements. It does
not instantiate a WPRF. This note analyzes the concrete noisy-linear proposal
rather than assuming its missing hard-true WPRF property.

**New restricted construction/proof:** For a uniformly generated binary-linear
relation, a change of secret coordinates embeds an ordinary decisional LWE
challenge into ALL public opening data while generating the residue helper
without the challenge secret. Parallel independent columns accumulate enough
release entropy with a polynomial modulus/noise ratio. A fixed public bit
projection replaces the proposed random-oracle KDF. A single sequence of LWE
hybrids covers the full native public key, all helpers, all columns, and masked
precommitted capability. No SOURCE-opening oracle is assumed.

**Not a solution for arbitrary NP or the competing-chain relation.** Correctness
is pointwise for any supported A,b, but the standard-LWE security theorem is an
average-instance theorem for an explicitly uniform matrix ensemble. It does not
prove security of arbitrary circuit-compiled matrices, nor security conditioned
on an arbitrary chosen instance being false or true. It does not provide a
reusable WPRF evaluation key for arbitrary future statements. This is a
per-instance release, not a claim to implement the WPRF syntax in the prompt.

No source-to-this-ensemble compiler, PoW-economic reduction, malicious ceremony,
Bitcoin endpoint implementation, or concrete 128-bit parameter set is supplied.
A bounded/noisy linear pseudowitness can still open any compiled instance where
it exists. Vectorization does NOT repair that defect.

This is a substantive joint-simulation and entropy-accumulation result for a
precisely instantiated reference family, not a claimed practical generic WKEM.

## 1. Exact source distribution and honest model

All honest algorithms are classical. Work in Z_q with

    q = 2^a, Delta = 2^d, 0 <= d < a,
    r = a-d, M = q/Delta = 2^r.

Let m>=2, n>=1, k>=1, ell=ceil(k/r). Choose a vector b in Z_q^m with at
least one odd coordinate. Reorder coordinates so b_1 is odd. b is fixed or
sampled BEFORE A, independently of A. It may depend on pre-existing permitted
native public context when the simulators below reproduce that dependency.
The simplest exact ensemble fixes b=(1,0,...,0).

Choose A uniformly from Z_q^(m x n). The reference relation is

    R_(A,b)(w) = [w in {0,1}^n AND A w = b mod q].

The uniform distribution of A is part of the theorem, not shorthand for an
arbitrary deterministic source compiler. Auxiliary public/quantum data must be
simulatable from A,b, permitted native context, and independent randomness,
without unknown LWE secrets or target release randomness. Advice may be
nonuniform quantum advice if LWE/native security are assumed in that same
model; it must not be an unmodeled state correlated with fresh challenge coins.

Let chi be the exact independently sampled LWE error distribution, supported
on integer [-beta,beta]. Assume

    Delta > 2 n beta.

No concrete hardness claim follows from this inequality. Decisional LWE is
assumed against the stated QPT class for the exact dimension m-1, n samples,
modulus q, and error distribution chi. We do not silently invoke a worst-case
reduction for these unselected parameters. For an unbounded error law, a tail
bound and the corresponding correctness/distribution error must be added;
that variant is not used in the exact statements below.

Choose an independent uniform k-bit native key-generation seed K. A prescribed
classical KeyGen maps K to the native secret/public pair. The default public
native context is just pk(K) and fixed public metadata. Any pre-signatures or
additional secret-correlated context need the explicitly matching native
challenge/signing oracle and simulations in Section 7.

## 2. Explicit Build, Encode, and Recover

Build(A,b): for j=1,...,ell independently sample

    s_j <- Z_q^m,  e_j <- chi^n,
    P_j = b^T s_j mod q,
    p_j = A^T s_j + e_j mod q,
    h_j = P_j mod Delta,
    z_j = (P_j-h_j)/Delta in {0,...,M-1}.

Use canonical residues P_j in [0,q). Write each z_j as exactly r binary bits.
Let Z be their concatenation, in a fixed public order. Let L_k be any fixed
rank-k binary linear map on ell*r bits; selecting the first k bits is enough.
Define

    pad = L_k(Z),  D = K XOR pad.

Publish exactly

    V = (parameters, A,b, (p_j,h_j)_(j=1)^ell, D, pk(K), context).

The fixed map L_k can be implicit in the format; there is no random hash seed,
programmed oracle, public seed for the secret masks, or target-secret tag.
The source/capsule/branch identifier must be bound into the native transaction
policy; the present theorem treats that policy only as declared public context.

Erase/protect K, all s_j/e_j/P_j/z_j and excluded setup state under the honest
setup model. This does not establish a one-honest-party ceremony.

Encode(w) returns the same binary vector after checking R_(A,b)(w)=1.
It does not compute a canonical witness or force distinct witnesses equal.

Recover(V,w): reject unless R_(A,b)(w)=1. For each j compute

    t_j = w^T p_j mod q.

Find the unique point P_hat_j in the cyclic residue class h_j+Delta Z_q that
is nearest to t_j (distance measured on the q-cycle). Form Z_hat from the high
r bits of these recovered residues and output

    K_hat = D XOR L_k(Z_hat).

An honest implementation may check pk(K_hat). That check is not used as a
security gate in the proof. Security considers arbitrary computation on V.

### Pointwise all-witness correctness

For every accepted binary w and every setup error array in the specified support,

    w^T p_j = P_j + w^T e_j mod q,
    |w^T e_j| <= n beta < Delta/2.

Residue-class points are spaced by Delta on the q-cycle, so nearest-point
recovery is unique and P_hat_j=P_j. Every valid ORIGINAL witness of THIS
binary-linear reference relation recovers the same K. This assertion is
simultaneous over all witnesses, including ones selected after viewing V.
No union bound over witnesses or probabilistic decoder is required.

The same arithmetic would work for a nonbinary integer z satisfying A z=b
whenever its actual error is small enough. The theorem does not mistake the
honest binary-input check for cryptographic enforcement against such z.

## 3. Secret-coordinate decomposition: helper needs no LWE secret

Define v=b_1^(-1)e_1 and N in Z_q^(m x (m-1)) with column i-1, i=2,...,m,

    N_i = e_i - b_i b_1^(-1) e_1.

Then b^T v=1, b^T N=0, and T=[v N] is invertible over Z_q. Define

    a_vec = A^T v in Z_q^n,
    B = N^T A in Z_q^((m-1) x n).

The map A -> (a_vec,B)=T^T A is invertible. Thus for uniform A, a_vec and B
are independent uniform matrices/vectors, also conditional on any admissible
pre-A choice of b and native public key.

Every uniform s_j has the equivalent sampling rule

    P_j <- Z_q, u_j <- Z_q^(m-1),
    s_j = v P_j + N u_j.

P_j and u_j are independent. Consequently the ACTUAL opening data obeys

    p_j = a_vec P_j + B^T u_j + e_j.                  (1)

This is not a marginal argument. The distribution of

    (A,b, P_j, h_j=P_j mod Delta, p_j)

is exactly reproduced by sampling P_j, deriving h_j, and adding a_vec P_j to
an ordinary LWE sample over the transverse matrix B.

In particular, a reduction receiving (B,c) need not know the secret u in
c=B^T u+e to generate the real helper. It chooses P_j itself and publishes

    p_j = c + a_vec P_j,  h_j=P_j mod Delta.           (2)

It reconstructs A=T^(-T)[a_vec^T;B]. Native K, pad, and all other P_i can be
sampled by the reduction in the same order as honest setup. This closes the
helper/challenge-secret circularity for the specified matrix distribution.

For a fixed circuit-derived A, equation (1) is still an identity but B need
not be uniform. The exact algebra does NOT turn structured-matrix LWE into
standard uniform-matrix LWE.

## 4. Full-joint QPT theorem, with a fixed pad map

The standard decisional LWE challenge is

    B <- Z_q^((m-1) x n),
    c = B^T u + e      OR      c <- Z_q^n,

with uniform independent u and e~chi^n. Write eps_LWE(Budget*) for an upper
bound on the ABSOLUTE output-probability difference for the exact QPT resource
and advice class, including all sampling, matrix arithmetic, native operations,
and the call to the target adversary. No factor of two is hidden in this
advantage convention.

Let H_j replace p_1,...,p_j by independent uniform vectors, while retaining the
REAL K, pk(K), all P_i, all h_i, the fixed-map pad, D and permitted context.
No helper or checking-key correlation is removed in this definition.
Efficient deterministic public bindings/hashes of the released fields may be
appended in every hybrid. Secret-generated auxiliary fields require the
matching simulators of Section 7, rather than an unproved independence claim.

To distinguish H_(j-1) and H_j, the LWE reduction uses (2) in column j. It
samples earlier uniform columns and later genuine columns using known u_i,e_i.
All columns use the SAME B and a_vec. In the real LWE mode, it generates exactly
H_(j-1). In the uniform mode, p_j is uniform even conditioned on P_j and all
other sampled fields, so it generates exactly H_j. The reduction invokes the
QPT attacker once on a classical input; it neither rewinds nor clones quantum
states. Any coherent processing of the public data is already included in the
QPT LWE adversary. There are no oracle queries to program or extract.

This proves, for any common efficiently testable success event and where each
hybrid simulator is admitted,

    |p_real - p_Hell| <= SUM_j eps_LWE,j
                     <= ell * eps_LWE(Budget*).       (3)

The second inequality simply uses a common worst-case budget bound.

### Exact native null simulation

A uniform canonical P_j in Z_q is in bijection with its low d bits h_j and its
high r bits z_j. These are independent uniform bit strings. In H_ell, all p_j
are uniform and independent of every P_i. Therefore Z is uniform independent
of A,b,p_1,...,p_ell,h_1,...,h_ell,K,pk(K) and allowed context independent of
fresh release coins. Since L_k has rank k, pad=L_k(Z) is EXACTLY uniform.

Thus D=K XOR pad is exactly uniform independent of K jointly with pk(K). No
leftover-hash error or random-oracle security term is needed.

A native simulator given pk(K) generates the allowed native context, samples
A,b under the exact source distribution, samples uniform p_j and uniform
h_j in [0,Delta), samples uniform k-bit D, and invokes the attacker. It never
needs K, P_j or an ORIGINAL witness. This is exactly the H_ell public law.
For exact seed recovery, the native game's private success check evaluates
whether the forwarded output equals its original K.

Hence

    Pr[recover exact K] <= eps_native_seed(Budget*)
                          + ell*eps_LWE(Budget*).     (4)

For an independent session key with no native checking material, replace the
native term by 2^(-k), assuming no other allowed data depends on that session
key. For native signature forgery, Section 7 gives the corresponding event.

### What the theorem actually quantifies over

Correctness holds for every supported A,b. Bound (4) is over the specified
uniform-A setup distribution. It is not a per-fixed-instance guarantee and
not an arbitrary-instance WE theorem. Conditioning on a chosen instance being
false/true, or selecting b adaptively from A, is a NEW distribution and needs
its own simulation/reduction. A sampler that plants a known w and sets b=Aw
is not covered by the fixed/pre-A b theorem.

If admissible source witnesses are already given as auxiliary input, their
correlation with A must be reproducible in the LWE reduction. Arbitrary witness-
bearing advice about fresh A is not free auxiliary information. The reference
security result cannot claim to hide a key while an adversary already has an
accepted witness; that would contradict correctness.

## 5. Pad pseudorandomness versus direct capsule security

For the concrete one-statement pad, consider distinguishing

    (A,b,(p_j,h_j), pad)

from the same view with an independent uniform k-bit string in place of pad.
Replace all p_j by uniform, compare pads in the exactly uniform experiment,
and replace all p_j back. This proves a conservative

    eps_pad <= 2 ell eps_LWE.

Native-key recovery uses the direct hybrid (3), so its bound (4) needs only
ell eps_LWE, not this two-sided pad bound. Neither game is a reusable WPRF
construction for arbitrary x after a globally generated evaluation key.

## 6. Entropy accumulation repairs the huge-scalar requirement

The user's scalar helper leaves M=q/Delta possible values when b is primitive.
Using one scalar for a k-bit seed would require an enormous M before generic
candidate checking can have the desired cost. The revised construction uses
ell independent target values, not one scalar, and all are required to form
the pad. Conditional on the helpers in H_ell, the complete release string has

    ell * log2(M) = ell*r

bits of entropy. Thus ell*r>=k suffices for the fixed-map exact uniformity.
For example r=8 and k=256 require ell=32 columns. This is an algebraic count,
NOT a suggested or validated LWE security parameter set. Native security, the
ell-fold reduction loss, and the chosen LWE parameters still require concrete
assessment.

This avoids an exponentially large scalar modulus-to-error ratio: q/Delta can
be polynomial (or a fixed power of two), and ell remains polynomial. It does
not use a public checking key to authenticate separate P_j guesses. The native
public key checks the final native credential only.

If A,b are already the public instance, incremental payload is

    ell*n*a + ell*d + k + |pk| + |context| bits,

plus fixed format overhead. Describing A from scratch costs m*n*a additional
bits. Setup cost is polynomial in m,n,ell,log q and sampling costs; opening
uses ell dot products plus residue decoding and native KeyGen/checking.
No enumeration of the witness domain is used.

For nonprimitive b, gcd(q,b_1,...,b_m)=g reduces the number of P values remaining
per feasible helper to q/lcm(g,Delta). That counting formula is verified in the
checker. The joint standard-LWE theorem above deliberately assumes primitive
b and does not silently extend its dimension argument to a torsion module.

## 7. Native forgery, related capsules, and setup boundaries

**Native forgery:** Use success event Verify(pk,msg,sig)=1 on an intended-scope
message not previously queried to the native signing oracle. The LWE hybrids
can generate K and simulate the signer; the final native reduction instead
forwards the permitted CLASSICAL signing queries to its native challenger.
With precisely that QPT EUF-CMA model,

    Pr[new-message native forgery] <= eps_EUF-CMA(Budget*)
                                     + ell eps_LWE(Budget*).

An arbitrary signature on an already signed message, a transaction-graph bypass,
or misuse of a legitimate pre-signature is not automatically an EUF-CMA forgery.
Exact graph/sighash authorization needs a separate proof. Exact seed recovery
is not assumed to cover all equivalent signing credentials.

**Independent capsules:** For a fixed unopened target, the same simulation can
include other independently generated capsule secrets and their adaptive
openings, provided their complete generation/opening data are efficiently
simulatable from A,b and the allowed native challenge. Shared public A does not
require shared secret s. For a joint hybrid replacing every unexposed capsule,
use the total number of replaced columns in (3). The target s/e/P values must
not be revealed, nor may other capsules leak them through secret reuse. This
is not unrestricted selective-opening or adaptive-statement WPRF security.
The checker only tensors one independent revealed auxiliary transcript into a
finite exact-law test; it does not experimentally prove this general claim.

**Quantum model:** Classical public samples, arbitrary QPT processing and the
matching fixed/nonuniform advice model. Reductions are straight-line, one call
per hybrid, no inverse-adversary access, rewinding, QROM, or ideal mixing.
Independent coherent joint attacks on all release columns are covered by the
hybrid theorem, not dismissed as only classical attacks with a speedup.

**Honest ceremony:** Correct secret sampling, honest generation and protected
or erased setup state are assumed. No one-honest-party malicious MPC, seed-bias,
selective-abort, or retained-coins security is asserted. A builder retaining
s_j computes all P_j; this does not meet the optional keyless Build model.

**Context/replay:** The same recovered K is a bearer capability unless the native
policy adds designated-owner checks. Fresh independent secrets are used per
capsule. Identifiers do not prove joint security when secrets/pads are reused.
No constraints on a rightful post-settlement owner's funds are introduced.

## 8. Why this does not close the user's ORIGINAL PoW/NP theorem

The exact missing step is now an instance-distribution embedding, not hidden
helper programming:

    actual source-compiled joint public data
        <-> a simulator receiving uniform transverse B and an LWE sample c,

while every valid ORIGINAL witness has a computable accepted short opening.
A proof must generate the actual source matrix, statement, chain context,
opening data, and correlations without the challenge secret and without an
accepted ORIGINAL witness. It must preserve the ORIGINAL relation, not replace
it by R_(A,b) and claim equivalence without constructing that compiler.

For the proposed fixed compiler A_x,b_x, calculate v,N,a_vec,B=N^T A_x using
Section 3. If B is structured, standard LWE on a uniform matrix does not apply
merely because p_j has the visual form of an LWE sample. A computational joint
embedding might exist for another compiler, but none is supplied here.

In particular, a known short nonbinary z with A_x z=b_x still yields

    z^T p_j = P_j + z^T e_j

in every column. If its errors satisfy the decoding bound it recovers the full
vector pad. Neither independent columns nor a different KDF removes this fact.
The supplied draft reports such defects in specific subset-sum/Tseitin
compilers; this note does not purport to repair them or reproduce unseen
compiler code. It is not a break of the repository's Fourier construction.

The theorem supplies an independently specified standard-QPT-LWE alternative
to recovery for its random-linear reference family. It supplies no reduction
from key recovery on the actual light-client relation to finding X blocks or
an ORIGINAL burn proof. No quantitative delta_PoW is derived.

## 9. Dependency, novelty, validation and handoff ledger

The current user-supplied WPRF/noisy-linear draft is the direct mathematical
input. Earlier exact repository input read for comparison:

`research/pq-wkem/VTDH_STANDARD_LWE_QPT_LIFT_RUN122.md` at starting head.

Run 122 already proves a QPT-LWE pad hybrid but explicitly leaves SOURCE opening
uninstantiated. The present note does not rebrand that gap as solved. Its
additional content is a fully specified helper-aware challenge embedding for
one binary-linear source distribution, plus polynomial entropy accumulation
and exact fixed-map native capsule simulation. No historical priority claim
is made for these standard linear-algebra/hybrid ingredients.

`check_joint_linear_release.py` contains no network calls and needs only the
Python standard library. Two executed outputs are byte-identical. It checks
exact finite joint distributions (including a deliberately weak toy public
checking function), uniform challenge translation, vector-pad entropy, the
public helper's gcd count, and deterministic all-witness residue decoding.
The correctness fixture is NOT sampled from a purported secure parameter set.
These are algebraic checks, not evidence that LWE is hard or that a native
signature instantiation is secure.

Next equation to establish for a real compiler is the exact law of its
transverse matrix and source correlations under an ordinary LWE challenge.
Do not substitute this restricted reference theorem for that missing result.
The practical generic PQ witness-KEM stopping condition is NOT met.
