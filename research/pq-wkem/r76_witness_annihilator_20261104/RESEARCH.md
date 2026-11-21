# R76 — Independent additive source masking and the all-witness annihilator

**Outcome: no positive WKEM advance.** This is a bounded unsuccessful construction attempt at R75's missing hard-TRUE source. Not a generic impossibility theorem or a quantum hardness claim.

## Pinned continuity and prior component

Authorized project: syscoin/PVUGC PR #1, branch research/pq-wkem-validation-20260918. R75 exact head 8580a5534b6f0b918cf94691887d51468ac2c9d4; latest ordinary substantive comment 6647454146. Read R75 research at blob 26c7c14932bceab441ee4751eff0cf43a0a7d2e7. R75 proves an exact same-root adaptive FALSE-source simulation for publicly certified degree-d refutations only, not hard TRUE, and does not remove R58/R63/R67 attacks.

## Candidate release and actual source distribution

For the public ORIGINAL statement x and its R74/R75 moment compiler, a valid ORIGINAL witness w supplies normalized Boolean moments r_w with r_w^T A_x=0 and r_w^T e_0=1 over Z_q, q=2^k. The old classically sampled source encodes each precommitted key word mu as

\[
C = \operatorname{Round}_{q\to p}(A_x z+e+\Delta\mu e_0),
\quad z\leftarrow\mathbb Z_q^D,\quad e\leftarrow\chi_{\rm src}.
\]

All ORIGINAL witnesses must recover the SAME capability, not a witness-dependent key. The attempted hard-TRUE repair appends an independently uniform ordinary-LWE-like random mask:

\[
C_B=\operatorname{Round}_{q\to p}(A_xz+B u+e+\Delta\mu e_0),
\quad u\leftarrow\mathbb Z_q^s.
\]

B is publicly generated, u independent of the old source coins, key, CK, auxiliary fields and related capsules. We tried to use B u as an actual independent ordinary-LWE challenge surface while keeping all original openings correct, before trying any full-public hybrid. This attempt fails at correctness.

## Exact necessary condition (unrounded linear form)

For one valid normalized witness r, before rounding, its source opening equals

\[
r^T C_B=\Delta\mu+r^T e+r^T Bu\pmod q.
\]

For fixed r^T e and any independent public/auxiliary conditioning, H={r^T Bu:u in Z_q^s} is an additive subgroup, and r^T Bu is uniform on H. If r^T B is nonzero modulo q, H is nontrivial. Every nontrivial subgroup of Z_{2^k} contains q/2. Pair each h in H with h+q/2. A correct-word decoding interval of radius strictly below q/4 cannot contain both pair members. Thus its success probability is at most 1/2, even for a classical adversary, whatever the independent error distribution.

Consequently high-probability all-ORIGINAL-witness completeness in this **specific** uniformly additive, unrounded linear source requires

\[
\forall w\in W_x,\qquad r_w^T B=0\pmod q.
\]

The grid-aligned rounded subclass has the corresponding statement over p when all terms lie exactly on the q/p rounding lattice and the correct interval has radius less than p/4. **No theorem is claimed** for arbitrary non-grid rounding, correlated compensating errors, a nonlinear opening algorithm or an arbitrary nonadditive encryption design.

Define Ann(W_x)= intersection of ker(r_w^T). The allowed B columns must lie there. Choosing B=A_x T guarantees this but

\[
A_x z+B u=A_x(z+T u),\qquad z+T u\stackrel{d}{=}{\rm Uniform}(\mathbb Z_q^D),
\]

so this changes neither the complete source distribution nor supplies the missing ordinary-LWE challenge embedding. Under the additional *field-specific* span condition span({r_w})=ker(A_x^T), Ann(W_x)=im(A_x) and **all** compatible additive masks are absorbed. The field span condition is not asserted for generic NP or composite-modulus modules. A different B in Ann(W_x) outside im(A_x) remains conceivable; there is no witness-oblivious classical-PPT sampler or independently justified joint-QPT source simulation for it here.

## Exact executed finite checks

The separately published deterministic JavaScript checker uses two distinct normalized valid rows r1=(1,1,0), r2=(1,0,1), source column A=(4,-4,-4), q=32, p=8, Delta=8. Compatible B=3A gives **exact joint source distribution identity** and both openings recover the identical root word for every z,u and both mu values. Incompatible B=(0,4,0) makes r1 recover the correct word in only 1/8 of cases although r2 still opens always. Exhausting all 512 grid-aligned B columns leaves exactly eight all-witness-compatible masks, precisely im(A). An independent field-q=17 fixture reproduces the exact source equality and a 1/17 incorrect-mask success rate. The checker output is captured as a distinct file; no QPT or parameter security inference follows. An independent local Python checker ran twice identically with 10,319 passing assertions (local-only checker SHA-256 9d0d7529d0dbd3137f4a02f8fe598881507ed574dc2aa69afe98dfa4b264773c).

## Attempted repair and precise handoff

- A generic independent uniform B breaks at least one ORIGINAL witness unless its columns annihilate every valid witness.
- The efficiently available choice B=A_xT preserves correctness but is absorbed, so R75's structured hard-TRUE release remains unsimulated.
- Additional annihilator columns require a constructive witness-oblivious sampler AND an actual ordinary-QPT-LWE challenge simulator for the *entire* x-dependent source, not a promise of source opening or arbitrary structured-LWE hardness. Neither was found.

An independently justified classical-PPT candidate must instantiate source setup/opening, checking key, context, auxiliary data and all related capsules together. Its still-unproved security obligation for any QPT adversary with coherent joint processing, arbitrary classical adaptive public outputs and appropriately restricted selective openings is

\[
\Pr[\mathcal A(V_x)\text{ obtains an accepted native capability}]
\leq
\Pr[R_{\rm ORIGINAL}(x,\mathrm{Ext}^{\mathcal A}(V_x))=1]
+\mathrm{Adv}_{\rm independent\ QPT\ break}+\mathrm{negl}(\lambda).
\]

The extractor cannot require an adversary-supplied representation, generic quantum rewinding, or an independently assumed witness-releasing functionality. Also required are arbitrary FALSE full-output security, malicious setup/abort and N-of-N ceremony composition, DA, 128-bit quantum parameterization and a conditional no-EC-key-path native PQ Bitcoin endpoint. No original verifier is moved on chain. R76 changes none of R75's restricted FALSE theorem and does not complete the WKEM. The research automation must remain enabled.
