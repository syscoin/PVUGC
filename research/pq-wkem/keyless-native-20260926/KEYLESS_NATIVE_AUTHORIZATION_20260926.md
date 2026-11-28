# Single-constructor keyless Bitcoin authorization: the useful simplification and the native-verifier boundary

Identifier: INTERACTIVE_KEYLESS_20260926. Research only, not deployment code.

## 1. Starting checkpoint and scope

Connected GitHub reads verified syscoin/PVUGC PR #1 at
`76e5b632cf00b4372955b871aadd59ded84c5167`, branch
`research/pq-wkem-validation-20260918`, open/draft/unmerged. The latest ordinary
comment was `5850205385`, recording Runs 122-128. Exact-head notes inspected for
this argument were Runs 113, 126, and 128. The newer Run-133 conversation archive
was read locally; its SHA-256 is
`e43324a888590b22c605e33b8be83e8ecbf3947a0453e4944389852ce05c2052`.
None of the previously denied Run-129-134 publication payloads is retried here.

The user's new question asks whether one person can define a program, derive an
address without learning its spending key, and later recover that key using a valid
witness, removing both the distributed setup ceremony and covenant emulation.

There are two distinct targets:

A. **Literal key release with unchanged native verification.** Build the actual
native public key without knowing any usable secret; every valid witness later
obtains the same native secret. This preserves the difficult WKEM-like release
requirement and strengthens security against the constructor's retained state.

B. **Witness-native authorization.** One public verification key can admit several
witness-derived signing secrets. Every valid witness authorizes the same address,
but need not recover one identical bit string. A suitable native proof-of-knowledge
signature can implement this relation directly. This changes the earlier same-key
requirement, and a generalized signature verifier is not available merely because
Bitcoin might someday adopt some PQ signature scheme.

The new constructive work below develops B's algebraic source compiler, while
keeping its consensus and quantum-security prerequisites explicit. It is not a
completion of A or of the standing generic-NP PQ WKEM target.

## 2. What full-key release can and cannot enforce

Let an output accept an ordinary signature under Q, and suppose Unlock returns a
usable secret s. For every otherwise-valid spending transaction T, signature
correctness gives Verify(Q, sighash(T), Sign(s, sighash(T))) = 1.

Consequently, once s is recovered, an off-chain predicate cannot constrain the
transaction's amount, recipient, change output, or successor state. Checking a
particular transaction before returning s does not fix this: the recipient can
run Sign on a different transaction. Deriving s with a transaction-specific KDF
does not fix it either if s is the usable secret for this fixed funding key.

This is an authority statement, not an attack on a signature scheme. An ordinary
key intentionally confers this power. A native key can sometimes be replaced by a
single restricted signature, but producing that signature without ever exposing
a signing key is a different cryptographic functionality.

A useful application therefore segregates value:

- One unique deposit identifier corresponds to one dedicated BTC UTXO and one
  transferable off-chain claim to its ENTIRE value.
- Only a terminal, authenticated, irreversible burn of that whole claim authorizes
  exit. Ownership evidence while the claim remains transferable is insufficient.
- The witness includes both burn/finality evidence and private control of the owner
  named by the burn, not merely a public event or public SNARK proof.
- The authorized owner receives unrestricted ownership of that entire UTXO. There
  is no remaining change output or partial balance to protect with a covenant.

Releasing a key to a 100-BTC pool in response to a 1-BTC burn is unsound regardless
of how well the burn is proven. Dedicated full-value claims avoid that mismatch,
but are not a drop-in fungible pooled bridge.

If all unlocking inputs are public, anyone can run the same public decoder. Naming
an owner inside public inputs does not confer exclusivity. Requiring the owner's
private secret in the relation is one way to restrict local unlocking. Merely
placing that secret inside a publicly replayable signature and accepting the
signature alone as the unlocking witness does not have the same effect.

Offline knowledge is monotone: fixed public parameters and a witness that once
unlocked a key still unlock it later. A newer off-chain owner cannot erase an old
owner's capability. Terminal burns, no re-use of the escrow address after release,
and explicit external-chain finality assumptions are therefore necessary.

The manifest should have a unique identifier BEFORE funding. Do not define the
funding key circularly from a funding outpoint whose txid already commits to that
key. A separately validated registration can bind the identifier and generated
address to an exact outpoint, without duplicating the claim.

## 3. Why deleting MPC does not make ordinary WE setup keyless

Generating (s,Q), encrypting s to a statement, and deleting s is not security
against a malicious single constructor. A classical constructor can log s or the
coins used to derive it while producing exactly the same public transcript.
A proof that the encrypted secret matches Q proves consistency, not erasure or
ignorance. This applies even when the constructor originally deposited its own
coins: other people subsequently rely on the off-chain claim's backing.

The literal desired interface is instead

    Build(R,x;rho) -> (P,Q)
    Unlock(P,x,w) -> s, with NativePub(s)=Q whenever R(x,w)=1.

Its adversary receives the COMPLETE retained constructor view, including rho and
all internal classical state, plus all public output. Security is conditioned on
not already possessing a valid source witness. A constructor that already has a
valid witness is entitled to unlock; 'nobody ever knows a key' cannot override
correctness.

A genuinely transparent construction must avoid creating a signing secret that
its constructor can retain. Public reproducibility can bind a constructor to a
particular Build algorithm but is not by itself a proof that its output has the
needed witness-only inverse. Chosen programs and builder-selected salts must
also be included in the security game; nobody can certify security for an
arbitrary malicious program without verifying the intended program semantics.

This changes the Run-112/126 setup-known-target obstruction in a useful way:
Build need not know the extraction target. However, the missing obligation is now
how to compute its NATIVE PUBLIC IMAGE and enable every source witness to invert
it, without a constructor-known preimage or an ambient alternate signing key.

## 4. Public-address consistency requires a different security game

Let V be the deterministic public-key map on a finite key space K of size N.
Publish Q=V(s), with s uniform. Given either Z=s or independent uniform Z, the
public test V(Z)=Q accepts with probabilities

    1                         (real)
    sum_y (|V^{-1}(y)|/N)^2    (independent random).

Proof: condition on the image fiber of s and count uniform candidates in that
fiber. For an injective V the distinguishing advantage is 1-1/N. For balanced
fibers of size f it is 1-f/N.

This does NOT recover s. It is the standard distinction between one-wayness and
pseudorandomness in the presence of a public consistency check.

The Run-113/133 recovery-to-comparison lemma remains correct when its independent
challenge premise holds. But a theorem saying that EVERY real-versus-independent-
random distinguisher extracts a source witness cannot simply include V(s) in its
view: the trivial consistency checker would qualify. The native-address variant
needs a direct recovery/forgery-to-source theorem under the actual correlated
public output, not that unmodified challenge game. Pre-setup auxiliary-state
restrictions do not remove the constructor's own retained state.

## 5. Constructive alternative: compile the program into the signing relation

The following is an explicit algebraic interface construction, not an assumed
WE compiler. Boolean moment lifting and rank-one extraction are reusable known
techniques; the point here is to use their relation AS the public signing key,
instead of trying to hide a common value behind it.

Express the original verifier as Boolean quadratic constraints on n wire values
z_1,...,z_n, including source witness bits, internal gates, fixed public inputs,
and an accepting output. Use AND and NOT gates, so the encoding works over any
finite field. Put z_0=1. A valid original witness computes all internal wire
values in polynomial time.

Define a public affine family of symmetric (n+1)-square matrices X by

    X_00 = 1,
    X_ii = X_0i                       for i=1,...,n,
    sum_{i,j} c_{gij} X_ij = 0        for each quadratic verifier equation g.

For example, z_i z_j=z_k becomes X_ij=X_0k; NOT becomes
X_0i+X_0k=X_00. All equations in the entries of X are LINEAR. Public Gaussian
elimination either detects inconsistency or outputs

    X = A_0 + sum_{j=1}^k a_j A_j.

It never receives an original witness. If the affine equations are inconsistent,
use a distinguished empty relation, or a fixed rank-two matrix as a no-instance
of the rank-at-most-one relation.

### Exact source correspondence

Every accepting Boolean assignment yields X=(1,z)(1,z)^T in this affine family,
with rank exactly one. Conversely, any rank-at-most-one X in the family has
rank exactly one because X_00=1. Its two-by-two minors give

    X_ij = X_i0 X_0j.

Symmetry and the diagonal equations imply z_i^2=z_i for z_i=X_0i. Over a field,
this forces z_i in {0,1}. The remaining equations are precisely the verifier's
constraints, so the first row reveals an ORIGINAL valid witness.

Thus, for the publicly constructed family, exact rank-one solutions correspond
to accepting full Boolean wire assignments. Multiple valid source witnesses
produce different solutions of ONE fixed public relation. They do not need to
be canonicalized to one hidden scalar.

### Fixed rank and fixed support chart

A rank threshold r>=1 can be accommodated algebraically by

    Y = diag(I_{r-1}, X).

For ALL X, rank(Y)=r-1+rank(X), hence rank(Y)<=r iff rank(X)<=1.
For an honest X=vv^T, v=(1,z), its first r columns are independent and

    Y = S [ I_r | C' ],

where S consists of the first r columns and C' has r-1 zero rows followed by
z^T. This exact chart is useful because the high-level Mirath signing relation
uses this form; it does not require a witness-dependent choice of pivot columns.

The alternative syndrome description is H vec(Y)=y with all public matrix and
gate constraints included. It is statement-derived, NOT a random syndrome
MinRank instance. A compact Mirath seed is not supplied by this construction.
Arbitrary vector-coordinate column permutations used in systematicization need
not preserve matrix rank and cannot silently repair the format mismatch.

### Conditional signature composition, with the missing premise explicit

Suppose a signature-of-knowledge verifier accepts this exact public relation and
has an all-instance QPT knowledge theorem for message-bound proofs, including the
required quantum auxiliary information and prior-public-transcript exposure.
Given a source witness, compute its rank-one solution and prove knowledge of it
with the transaction digest in the proof statement/challenges.

A QPT successful unauthorized signer then yields, under THAT theorem, a valid
rank-one solution (or a named proof-system hardness failure). Reading its first
row yields the ORIGINAL witness. This final algebraic composition is deterministic
and straight-line; it introduces no extra rewinding or quantum-state copying.
Any rewinding, QROM programming, circuit/adjoint access, or extraction loss belongs
to the proof-system theorem and must be audited there.

No average-case MinRank hardness assumption is needed merely for this last semantic
arrow. Nor does NP-hardness establish the proof-system theorem. Stock EUF-CMA for
keys sampled by native KeyGen does not automatically establish knowledge security
for these chosen statement-derived public keys.

This is a route to witness-native SIGNING, not a common-secret witness KEM. It is
usable on Bitcoin only if its native verifier actually accepts such keys and
proofs. A new general-purpose proof-checking opcode or a generalized signature
suite would cross the standing no-custom-on-chain-verifier boundary. Merely saying
'PQ in the future' does not make the boundary disappear.

## 6. Primary literature check: promising interface, not a drop-in scheme

The primary MIRA paper (arXiv:2307.08575v1), Sections 2.3-2.5, explicitly uses a
locally simulated MPC-in-the-head proof of a MinRank solution. This is not a
multi-user key-generation ceremony. MIRA/MiRitH have since merged into Mirath.

Mirath v2.1.0, Algorithms 19-21, generates secret matrices from a secret seed and
public matrices from a public seed; DecompressPK expands that public seed. Its
high-level public relation is syndrome MinRank, but the concrete key format does
not accept our arbitrary source-derived matrix system. Its Section 7 theorem
starts with KeyGen-generated keys. The May 5, 2026 team note describes a path
toward QROM proofs after conservative primitive changes. The primary record for
Kosuge-Xagawa ePrint 2025/1999 addresses QROM security with rejection/grinding.
This run does not audit that paper's full proof or establish arbitrary-instance
source extraction for the proposed extension. Native small-key/signature size
figures therefore cannot be transplanted to a generic verifier program.

The PIPE v2 author explanation, February 12, 2026, explicitly retains distributed
setup and describes raw-key release as binary authorization without output
restrictions. We use those interface facts, not its WE security/performance claims.

BIP341 documents unknown-discrete-log NUMS internal keys and ordinary signature
spending. Such a point removes knowledge of a scalar but provides no arbitrary-
program witness-to-scalar map. BIP360 is presently a draft P2MR proposal removing
the key path; it is not a native witness-to-key construction or adopted PQ
signature rule.

## 7. Concrete size boundary and exact security ledger

The dense symmetric matrix has (n+1)(n+2)/2 coordinates. A naive explicit affine
basis has O(n^4) field elements and naive elimination takes O(n^6) field operations.
A sparse equation description is much smaller, but a verifier must process that
description rather than pretending it is an ordinary fixed-size native public key.
For n=1000, the ceiling-sized dense basis is roughly 2.5e11 field elements. This
is not a practical bridge-verifier parameter choice. These are representation
bounds, not measured signer/verifier costs; no generic-NP resource estimate for a
finished scheme exists here.

- Algebraic compiler/factorization: deterministic classical polynomial time;
  no hardness assumption; supplied exact-rank object -> ORIGINAL witness. Applies
  to objects output by QPT algorithms but is not arbitrary-QPT extraction itself.
- Key-image consistency and full-key authority: unconditional counting/functional
  statements; classical tests suffice; no random oracle or extraction assumption.
- Literal keyless native key recovery: missing public-image compiler and full
  constructor-view QPT one-way/source-extraction theorem. UNPROVED.
- Witness-native signature composition: conditional on an explicitly QPT-valid
  all-instance knowledge theorem for the exact proof system, plus exact consensus
  support and message binding. UNPROVED for this extension; not a WKEM.
- External burn/finality/exclusivity: separately assumed protocol conditions,
  not implied by any algebraic rank proof.

This approach could remove the common-value canonicalization and gap/spectral
release problems only by changing what the native verifier checks. With today's
unchanged signing verifier and literal same-key recovery, those problems remain.

## 8. Executed evidence and next handoff

The new standard-library checker passed Python syntax validation and ran twice
with byte-identical output. It records 22,400 assertions: 21 fixtures over fields
of size 2, 3, and 5; 18,604 affine matrices exhaustively enumerated; all 48 valid
witness instances represented; exact source extraction for every accepted matrix;
fixed-chart factorization; 1,200 arbitrary rank-padding trials; 1,794 finite
public-image maps; and 100 tiny Schnorr correctness checks on two message types.
The tiny group has no cryptographic security. No signature-of-knowledge, Mirath,
Bitcoin integration, or witness-KEM was implemented or tested.

Next handoff: preserve two branches. For unchanged Bitcoin, seek a concrete
source-preserving keyless native-public-key compiler secure even with all builder
coins, and test all helpers/native forgeries. For a separately authorized future
signature-design fork, examine whether the uncompressed chosen-instance MinRank
proof can obtain an exact QPT knowledge theorem with practical sparse key encoding.
Do not claim either branch complete, and do not silently weaken the original
same-key/no-new-verifier target.

The complete practical generic-NP PQ WKEM stopping condition is NOT met.
