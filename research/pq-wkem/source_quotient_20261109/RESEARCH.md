# Source-quotient hash release: exact compiler trilemma and a stronger generic-transport implication

**Outcome:** No secure generic ORIGINAL-witness KEM, no practical hash-only source compiler, and no PQ-security claim. This is a bounded, completed construction/repair investigation of the specific source-quotient family in the preceding working checkpoint. We retain a precise failure classification and an independent strengthening of the R166 necessary implication. These are not equivalent to an end-to-end construction. No outside literature, lattice/group fallback, web search, or independent agent.

## Authority and continuity

- `syscoin/PVUGC#1`; branch `research/pq-wkem-validation-20260918`, observed start commit `44e0519506be699aba052e30ddb5081ae8b7fd4b`, open/draft/unmerged; git tree `0a65a2e850559b42d35ae51d8bdfd86c8257304e`.
- Exact branch checkpoint `research/pq-wkem/source_quotient_20261109/CHECKPOINT_01.md`, blob `6d177204cf9c3d62996c69615194082176378feb`. Read exact prior `ots_dual_attestation_20261109/RESEARCH.md` at blob `7072da1871274bf4ee42748376f449c36aaa5efd`, and `merkle_consistency_source_20261109/RESEARCH.md` at blob `28149c44e1dbd0a32f1147f6cf3a772abfe707d2`. Scoped later PR issue-comment read returned no new comments. The existing accepted-Merkle-transcript -> ORIGINAL witness-or-collision lemma does NOT link arbitrary final key recovery to the transcript.
- `CHECKPOINT_02.md` written locally before checker execution. All work here is research-only. Current source validity and public best-chain state are not simulated by actual BTC or SYS data; synthetic tests explicitly show their limits.

## Candidate family: quotient table keyed by authenticated source class

Build knows `x`, context and a pre-frozen ordinary native signature sigma, but not any future authentic source witness. Choose uniform k-bit K and domain-separated quantum-accessible random oracles T, F, C, P. For a polynomially sized selection of source-class labels `u_1,...,u_q`, publish

    CK = C(ctx,K), D=sigma XOR P(ctx,K),
    record_j = (T(ctx,u_j), E_j=K XOR F(ctx,u_j)).

The proposed off-chain PublicDerive(Capsule,w) calculates `u=g_x(w)` from complete original source evidence `w`, finds the corresponding tag, decrypts K and the same frozen sigma. In honest code R_original(x,w) is checked first. **Cryptographic release must remain protected even if an adversary calls public hash functions and raw record decryption directly**, so this post-hoc check is not a security boundary.

The event source has two distinct IDs:

    OutcomeID = H(ctx, claim, slot, pure-child-hash),
    WorkID = H(ctx, complete authenticated Syscoin/AuxPoW/Bitcoin-parent evidence).

Two parent work certificates referencing the SAME qualifying child are not conflicting forks. Qualified incompatible *child* state, required authenticated tags/ancestors, actual claim/UTXO, work and canonical-chain snapshot, observation windows and censorship/DA are all ORIGINAL predicate dependencies. A bare `hash(parentheader)` or self-consistent coinbase isn't canonical membership.

### Case A: `u=OutcomeID` (polynomially enumerated from known child outcomes)

Two honest parent-work certificates for one child map to one label, preserving their common semantic state. But a fabricated invalid parent, wrong-ancestor history or a raw claimant who simply knows the *child header* obtains the SAME u. Since T,F are public, any existing table record gives K with no ORIGINAL evidence. A one-bit `R_original` check in honest Open cannot restrict direct evaluation. This is an unconditional classical raw-release attack on THIS candidate, independent of SHA collision/security.

If OutcomeID itself remains a high-entropy unpredictable FUTURE child hash, Build has exactly the setup-uncertainty problem of case B. Using a finite list of preknown child IDs is not a source compiler for arbitrary future valid children.

### Case B: `u=WorkID` (complete future source bytes)

A raw fake parent no longer shares the same class as a genuine parent unless its complete work representation collides. However Build must publish *one matching pad for every genuine future w*. In an ideal source model where a future genuine WorkID is independent uniform in a b-bit class space after setup, and the q setup-selected labels are arbitrary but independent of this future random WorkID,

    Pr[future accepted WorkID matches any setup label] <= q / 2^b.

For t independently sampled fresh certificates, `Pr[all t open] <= (q/2^b)^t` when q distinct labels; if the future labels are drawn with some nonuniform min-entropy h and independent of setup, replace bound by q * 2^-h per witness (with independence separately justified for the all-t product). An adaptive adversary may select candidate work inputs to hit a label by mining, but the EXTRA work is then an independent target-matching puzzle: honest and invalid inputs are both hashable. This is not an every-ORIGINAL-witness release compiler; requiring all source certificates to mine a target changes the ORIGINAL relation and mining economics.

`g=H(Merkle root of w)` has identical future-root uncertainty; the sound accepted-transcript-to-witness extraction lemma starts **after** a full transcript is output and supplies no pre-funding correlation.

### Case C: compressed Merkle table with no extra trusted opener

Commitment root `root=Merkle(record_1,...,record_q)` authenticates only existing records. If the public records and their paths remain available, the Case A raw attack is unchanged. If records/paths are withheld, honest PublicDerive cannot obtain a pad merely from the future source witness: it has no index/opening for a class not covered by setup. If a trusted party provides paths or newly encrypts source-specific rows after observing source, that party becomes the prohibited online release authority; an untrusted path issuer cannot manufacture the secret K-associated record from public inputs. Hash collision resistance proves authenticity of the table, not a valid-source-dependent secret release.

### Precise conclusion scoped to this construction class

No quotient/map/commitment variant evaluated here simultaneously achieves (1) polynomial witnessless Build, (2) every genuine ORIGINAL witness recovers the exact frozen K, and (3) raw false-evidence hiding. This is NOT an impossibility theorem for all hash-based WE. A new **nontrivial, computationally protected cross-witness correlation** is still required; class labels or Merkle roots are not that mechanism.

## Executed tests (synthetic only)

`checker.py` and `captured.json` are fully reproducible Python 3 standard-library files. It uses SHAKE256 with canonical domain tags to form 128 independent *toy* contexts, frozen 96-byte mock capabilities, two distinct allegedly valid parent certificates for the same child, and an invalid parent with the same child. Both valid parents open the OutcomeID class and the invalid parent is rejected by honest software; direct raw decryption with the invalid parent nevertheless opens the frozen signature for all 128 fixtures. The two WorkIDs differ; a setup table holding one WorkID opens one but not the other. 2,048 idealized independent future-WorkID trials against 32 setup classes in 16-bit space yielded 0 hits (expected <=1; this small count is not a statistical assertion about security). Total 1,410 explicit assertions; exact second run SHA-256 was identical.

`hardcore_check.py` and its captured stdout independently verify an 8-bit Walsh/Fourier identity relevant to the stronger R166 reduction below. They do not test quantum algorithms or instantiate real cryptography. Exact hashes in `PROVENANCE.json`.

## Additional structural implication: generic hard-TRUE WKEM -> one-bit IND-CPA PKE

R166 established a *one-way* public-key-transport implication from the full generic-NP hard-TRUE requirement. Under the **same premise plus explicitly polynomially re-runnable nonuniform QPT adversaries**, the consequence strengthens to one-bit computational *indistinguishability*, not just exact-session-key nonrecovery. This is a necessary condition on future hash-only generic WKEM, not a construction from SHA or a security proof of the current candidate.

Take a quantum-preimage-resistant hash family h and NP instance y=h(s), with s random secret. The ORIGINAL relation R_y(y,w)=[h(w)=y]. The receiver's PKE secret key is s, public key y. To encrypt b in {0,1}, sender chooses a fresh independent native signature keypair (sk_sig,VK) and fixed intended message M, computes a unique frozen m-bit signature sigma=Sign(sk_sig,M), invokes hypothetical secure `Build_hash(R_y,y,sigma)` with public VK,M and required context, and samples r uniformly in {0,1}^m. Ciphertext is (Capsule,VK,M,r, t=b XOR <sigma,r> mod 2), with fresh capsule/keys per encryption. Receiver uses s (a true ORIGINAL witness) to call PublicDerive(Capsule,s) and gets exactly sigma, then decrypts b=t XOR <sigma,r>.

For IND-CPA b uniform, t uniform conditioned on (Capsule,VK,M,r,sigma). Suppose a QPT distinguisher D outputs b with probability 1/2+epsilon on this public view. Construct a parity predictor for sigma on chosen challenge r by drawing t uniformly, running D on the corresponding (Capsule,VK,M,r,t), and returning `t XOR D(...)`. Its probability of predicting `<sigma,r>` is exactly 1/2+epsilon. The standard *classical* Walsh/Fourier list-decoding argument (Goldreich-Levin), applied to repeated classical-input executions of this QPT predictor, lists polynomially many candidate sigma with probability polynomial in epsilon for epsilon nonnegligible. The reducer simply selects a *uniform candidate from the polynomial-size GL list*. When the correct frozen sigma is on that list, this gives an inverse-polynomial probability of outputting the **exact** sigma, without needing a native signature uniqueness assumption, a new public σ checker, or an oracle telling it which candidate is correct. This contradicts the assumed hard-TRUE exact frozen-sigma recovery security (via its ORIGINAL-witness extractor) or a separately justified PQ break. A different accepted native signature is handled by the separately stipulated native-forgery game, not by treating it as the frozen sigma. The hard-TRUE extractor then yields a preimage of y (or one of the stipulated independent breaks). Thus IND adversary implies violation of the hypothesized generic-WKEM assumption.

**Quantifier caveats:** The `Build` premise must be honest classical PPT and accept *sender-selected* native capability and fresh VK,M (or offer an equivalent sender-owned signature sampler). The exact-key/frozen-sigma security game must include (Capsule,VK,M,CK,ctx,Aux and all related public fields), chosen r and t, adaptive adversarial auxiliary inputs and multi-capsule/selective-opening rules where required. The reduction needs polynomial independent executions of the adversary on one fixed capsule. Standard nonuniform QPT circuits with polynomially many identically prepared advice copies support this. A single-use, non-replenishable entangled quantum advice state correlated with fresh honest signature coins is not covered without a separate argument. The proof works with classical random challenge r, not a classical rewind of a coherent oracle query. When the premise only promises native-forgery resistance but NOT exact frozen-sigma hiding, the implication needs an additional hypothesis.

The finite checker uses a 256-entry Walsh transform with 4 disclosed bits of an 8-bit secret: exactly 16 possible full secrets share the public view; the parity-prediction correlation is 1/16 and prediction success 17/32, and every one of the 16 candidates has equal Fourier weight. It verifies algebra, not the generic QPT theorem.

This strengthens the diagnosis: a fully generic hash-only solution with the **requested strong hard-TRUE security** would deliver IND-CPA public-key encryption for a hash-preimage public key, not merely a specialized PoW puzzle. We do NOT assert an impossibility theorem for hash-only PKE, oracle separations, or arbitrary SHA circuit use.

## Exact unfilled equation and next fundamental experiment

Find an explicit **classical-PPT** `Build_hash(R_original,x,sigma)` and `PublicDerive_hash(Capsule,w)` jointly, before future source and without a witness, such that

    forall w with R_original(x,w)=1:
      PublicDerive(Capsule,w) == SAME precommitted sigma,
    QPT arbitrary recovered frozen sigma or native target forgery
      => an ACTUAL ORIGINAL witness or an independently justified PQ hash break.

Any proposed source certificate must bind the real claim/UTXO, original evidence semantics, authenticated Syscoin child and incompatible fork, AuxPoW parent work, coinbase tags, ancestor, exact time window, canonical snapshot and relevant observation/censorship assumptions. Every hash token used at raw release must remain unavailable before that predicate holds **without making Build unable to predict all honest releases**. A first useful repair target is a *polynomial* correlation source where the future WorkID may be any valid authenticated parent work for the same child (no canonical witness), yet an adversary with fabricated same-child work cannot compute the common terminal K. To make a new claim, supply both actual compiler AND a full-public joint QPT simulator; Merkle-verifier acceptance alone is not enough.

No inference of production readiness, honest-erasure/malicious N-of-N composition, actual native SLH-like signature implementation, deployed P2MR, or 128-bit PQ security follows. No routine PR comment and no automation-disable condition met.
