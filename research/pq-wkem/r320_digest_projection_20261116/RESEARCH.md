# R320 — source-digest projection simulator for nonlinear public release (NONQUALIFYING)

**No ORIGINAL-source hash-only witness-KEM Build/Open, hard-TRUE/FALSE QPT reduction, or native cancellation endpoint is established.** This bounded iteration extends R317/R319's scalar SHA-pad test to **any publicly evaluable nonlinear digest-factorable release**, under an explicit source-projection simulation premise. It is not a general impossibility theorem for hash-only WE.

## Verified start and scope

At start, syscoin/PVUGC PR #1 was open/draft on `research/pq-wkem-validation-20260918` at `4d7cc5b025a2e62cb6e943870d6f7399f9add25d`. Exact latest R319 note blob `6e6d4310657c2c65733daf72f2b517a218155277`; R317 `ff26d166afbc3c52a1838c2ecfae966e7053fc03`; R318 `d1fcd7053601d35117c1a61d4d23f0fe2eeaba08`; R315 `385f653c0579dca00ba812b08558d78a9381d2cb`. Read-only Core #609 metadata head `c91539de3c34937e57d7f5fda47c7b0502ff33f6`, draft/release-disabled; no Core C++ tests or new source read. R225 PR comment `6796383617` remains the separate native activation portability issue. No web or literature research.

The ORIGINAL relation is the independent OR of (1) same-anchor strictly greater exact linked Bitcoin work, (2) finite authenticated fault in the particular burn/authorization, (3) qualified actual ancestor inconsistency at claim-relevant Syscoin height and LC depth, or independently authenticated exact claim-wrapper tag fault with explicit maturity. Activated contextual modern AuxPoW ID, exact 41-byte SYS tag and *separate* deterministic indexed child commitment all matter. Different parent certificates for one child are not a fork. Claim/UTXO/burn/amount/recipient/anchors/window/deadline/reset/native VK/message/capsule all remain bound. The toy work predicate below is NOT an ORIGINAL-qualified certificate.

## A precise nonlinear public-release attack

Let `T=(x,C,VK,M_cancel,aux,sibling_capsules,setup)` be the full public transcript and `S` the frozen safe native capability. Consider classical-PPT Build and a public opener of the restricted form

```
Build(x,S;rho) -> C
Open(C,w) = G(C,x,proj(w))   for every qualifying ORIGINAL w,
```

where `proj(w)` is a parent SHA256d digest or its public deterministic projection, and **G can be evaluated at an arbitrary projection without possessing its real parent preimage/whole authenticated source witness**. G can contain arbitrary nonlinear SHA or lookup operations. A verifier run only after raw G recovery is not part of the protected release.

For an explicitly specified strategy generating genuinely qualifying original evidence conditional on T, write `W_T` for its distribution and `Q_T=Law(proj(W_T)|T)`. Suppose average completeness is

```
Pr[T,W~W_T](G(C,x,proj(W)) == S) >= 1 - epsilon.
```

If a classical-PPT adversary can, without producing ORIGINAL evidence, sample `Y'~Q'_T` with `E_T TV(Q'_T,Q_T) <= delta`, then `A(T)=G(C,x,Y')` returns the exact frozen S with probability **at least 1-epsilon-delta**. Proof: for each T, the successful projections are a measurable set E_T. Total variation bounds the change in its probability from Q_T to Q'_T by delta(T); average over T. This is an unconditional classical attack, hence a QPT attack, requiring no query logs, rewinding, adversarial witness representation, feature linearity or hash preimage/collision break. If S is a real native signature it can be directly replayed or publicly checked with VK, subject to the separate R225 endpoint policy.

**Important qualifications:** The theorem only concerns hard-TRUE source distributions with a qualifying witness. It neither supplies a FALSE witness nor claims every real qualified source-projection distribution can be sampled. The sampler must match the *joint distribution conditioned on the public capsule/auxiliary inputs*, not an unrelated PoW marginal. A G consuming true preimage-dependent cryptographically hidden state and unavailable on synthetic projections is OUTSIDE the class. No general SHA cryptographic impossibility is claimed.

For SHA as an **ideal random oracle** on fresh independent parent nonce trials, conditional on a hash satisfying only `0<=uint256(SHA256d(header))<=T_pow`, its digest integer is uniform in `[0,T_pow]`, efficiently samplable WITHOUT mining its preimage. This idealized PoW-only sampler does not imply a sampler for full ORIGINAL Bitcoin membership/linked child history, contextual target/anchor, canonical tag, true fork, or burn evidence; selection strategies and adversarial source retention can bias the conditional law. Concrete SHA is NOT a programmable QROM proof here.

## Attempted repair and limitation

A small nonlinear public SHA row-selector capsule was built for four accepted high-digest projections. Every synthetic easy-work parent opened the same 256-bit S, but an adversary supplied the integer projection zero directly to public G, recovering S with NO parent work/header, bitcoin membership, Syscoin source relevance or burn fault. More complicated public hashing of the *digest projection* does not fix this; the computational work resides in finding a **preimage**, not choosing an accepted digest.

A promising **interface requirement, not an instantiated solution**, is a release computation requiring cryptographically enforced authenticated full SHA/AuxPoW preimages *inside the concealed key path*, rather than only checking source bytes after unmasking. An ordinary hashlock `Y=H(t), C=S xor H'(t)` requires Build to know the future t, which preauthorization does not; a public-key-like encryptor under a commitment to an unknown future preimage would be a genuinely different missing cryptographic primitive. It must work across EVERY original valid branch/witness, malicious coins, related capsules and source re-randomizations. This is not supplied by ordinary SHA preimage/collision resistance, a label invented at setup, an online signer or an extra source constraint.

## Actually executed bound / local provenance

A CPython3 stdlib regression hashed synthetic 80-byte SHA256d headers with little-endian uint256 work comparison to artificial target `2^250-1`. Found 96 different accepted headers among nonce trials 0..5716; top-byte bucket counts `[32,16,27,21]`. Public four-row nonlinear SHA-selectors returned the exact synthetic S from all 96, and directly from artificial projection 0 without any header. Exact discrete TV transfer control: `Q` success 0.9, `Q'` success 0.8, TV 0.1. Two invoked runs produced byte-identical JSON with **5,822 assertions each**. Checker SHA256 `90b93dd43e66ae34321ca4d8daf6b0648b7b87f2b6329973033b0d34d2a8625b`; each output SHA256 `c1c305a57e149a89308a90c33b527fd8bc3af76920c32ba10c22c939b019ccf3`. The full local-only archive includes complete expanded derivation, exact executable checker, paired JSON and provenance, SHA256 `1d2a64d5bcc3829ea7a78b112c4d61398458aac7948e93bd58055b193f9c89e6`. This GitHub note DOES NOT claim the checker bytes were committed. No real Core/BTC admission, SLH signature or QPT experiment was run.

## Exact unfinished obligation

```
ClassicalPPT Build_inc(x_W,sigma_cancel;rho) -> C before unknown future w;
forall ORIGINAL-qualified w: Open_inc(C,w) = same frozen sigma_cancel;
any QPT recovery / accepted native forgery => actual qualifying ORIGINAL
 source certificate or independent justified PQ SHA/native break,
in full joint public T, malicious setup, sibling selected opening,
retained source secrets, post-activation contextual and network rules.
```

The next valid advance requires an actual publicly executable **preimage-sensitive, nonspliceable, source-authenticated nonlinear gate**, not another publicly samplable digest or work-prefix release. No PR progress comment, production change, deployment or automation change.