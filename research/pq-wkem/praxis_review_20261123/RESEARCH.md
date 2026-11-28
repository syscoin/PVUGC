# Praxis review: conditional advance, no verified classical break

## Finding

This bounded review did **not** establish a break of the stated classical bilinear-generic-group theorem in *Praxis: Practical Witness Encryption for NP*, David Tse, Nikhil Vanjani and Psi Vesely, ePrint 2026/2971. Its common-key construction and extraction argument materially improve on our earlier uninstantiated FE interface. Credit belongs to the authors. Our work is an adversarial review, not a new construction or an independent security certification.

We derived a witness-free DLP-conditional recovery route, examined the consistency algebra, checked selected exact parameters, and separately audited efficient lifting. The quantum route is outside the authors' classical claim. The original hash-only/QPT bridge goal remains unfinished.

Run: Praxis review 2026-11-23. Initial observed clock: 2026-11-23 14:16:17 UTC. Fresh PVUGC PR #1 head: `67dea8d5cb19b083e4f29cfa86bf2a306359107a`; branch `research/pq-wkem-validation-20260918`. Head was reread before publication preparation. Comments queried since 2026-11-21 were empty. The latest Merkle-preimage screen remains NONQUALIFYING.

## Sources

- [Supplied paper](https://eprint.iacr.org/2026/2971.pdf), read through [ePrint's mirror](https://eprint.iacr.asia/2026/2971.pdf): 66 pages, 5,565 extracted lines. Local direct downloads returned HTTP 403; no PDF checksum is claimed.
- [Pinned praxis-lean repository](https://github.com/psivesely/praxis-lean/tree/60d3defeebd77caa0e57babe97991e672b948bb6), commit `60d3defeebd77caa0e57babe97991e672b948bb6`.
- [README](https://github.com/psivesely/praxis-lean/blob/60d3defeebd77caa0e57babe97991e672b948bb6/README.md), blob `878751b193ecad0470d46134fa29efa86ab9a359`.
- [Main.lean](https://github.com/psivesely/praxis-lean/blob/60d3defeebd77caa0e57babe97991e672b948bb6/Praxis/Main.lean), blob `3e8c1e086bb1a96530e2dcf50c32fd2f9a1f7739`.
- [Enc.lean](https://github.com/psivesely/praxis-lean/blob/60d3defeebd77caa0e57babe97991e672b948bb6/Praxis/Enc.lean), blob `f12e3cbe20895ccc5047f4e08fdd72a95d16c50a`.
- [Dec.lean](https://github.com/psivesely/praxis-lean/blob/60d3defeebd77caa0e57babe97991e672b948bb6/Praxis/Dec.lean), blob `6c684b07b1ddd40af62272f11ce84c5ac1faeb58`.
- [Games.lean](https://github.com/psivesely/praxis-lean/blob/60d3defeebd77caa0e57babe97991e672b948bb6/Praxis/Games.lean), blob `9c559cab60c9064af3f0fdbcfcbfca0f71d2447c`.
- [Constants.lean](https://github.com/psivesely/praxis-lean/blob/60d3defeebd77caa0e57babe97991e672b948bb6/Praxis/Constants.lean), blob `494e9eac6cc1ddc94e1cddb92f8e8d69a57a7276`.

## Why our previous attacks do not transfer automatically

Public-scalar recovery requires access to scalar factors. Here factors are encoded in groups, and extension-field weights and ties constrain their combinations. The paper combines a fixed low-rank threshold, concrete search at decryption, and width-two QAP factors. Removing group hiding or the ties changes the construction.

Lemma B.6 gives a specific defense against mixing witnesses. In dimension at most three, consecutive conjugates span the extension-field space when the public forms have no kernel on that row space. The ties define a symmetric trilinear tensor. Booleanity decomposes it into Boolean cubes; conjugacy fixes their coefficients in the base field. The corresponding Boolean squares are independent, so assignment residuals cannot merely cancel. A heavy kernel direction is handled by the short-multiple/MSIS reduction.

Our independently written checks compared the whole linear space of passing tied stacks with an independently enumerated honest-stack span. Forty sampled rank-three subspaces over F_5/F_17 gave 120 exact comparisons, all equal. The tested FALSE Boolean system `x+y=1, xy=1` had zero passing space. These are equation/transcription checks, not security proofs.

The rank-four probe produced a nine-dimensional passing space with an eight-dimensional honest span, plus an explicit rank-four stack outside that span. This refutes an extension of the classification to rank four; the paper only claims rank at most three. The tested FALSE policy still had zero passing space, and no ciphertext attack was derived. The proof separately charges rank-four coincidences by their low probability. See `construction_agent/` for exact matrices, checkers and outputs.

## Common-output release is actually constructed

For a valid witness w, Lemma 5.4 and the decryption specification give

    Lambda_w = [xi_w*kappa + r_w*psi_w]_T,   Psi_w = [psi_w]_T.

An alpha-scaled copy enables a centered search for r_w. For nonzero xi_w,

    xi_w^(-1)*(Lambda_w - r_w*Psi_w) = [kappa]_T.

Different witnesses can have different xi, r and psi and still recover the same key. A frozen cancellation signature can be the protected message or sealed under that key. No common future hash preimage is required. This is the paper's construction, not an assumed release oracle.

Theorem 5.6 bounds failure at xi_w=0 by 2/q for each witness fixed before oracle sampling. That is meaningful randomized correctness, not automatically a simultaneous guarantee for every adaptive future witness under malicious capsule generation. No efficient bad-ORIGINAL-witness attack was found here. `recovery_equations_check.py` checks the algebra in tiny groups; it is not a Praxis implementation.

## Explicit DLP-conditional recovery

Figure 9 and `Enc.lean` publish nonzero-alpha copies

    S=[s]_2,  S_alpha=[alpha*s]_2,  K_alpha=[alpha*kappa]_T.

A relative logarithm of S_alpha to base S gives alpha. Then

    alpha^(-1)*K_alpha = [kappa]_T,

and the public KDF unmasks the message. Pairing the first two elements with G1 alternatively transfers the relative-log problem to GT. No witness or MSIS solution is needed. A quantum DLP algorithm therefore defeats this concrete release primitive, even after a future PQ Bitcoin signature upgrade.

For a classical attacker the logarithm remains expensive. This identity is not a sub-100-bit attack or a contradiction in the declared classical model. The user's earlier relaxation for ordinary Bitcoin signatures only concerns the endpoint; it does not automatically approve groups and Module-SIS for the release foundation.

## Extraction and exact resource scope

Theorem 5.9 supplies a universal straight-line extractor that reconstructs sketches from answered generic-group operations, including guessed labels. It does not require a volunteered algebraic representation. Its target-query bound is

    Pr[target KDF query and no BQS witness | b] <= (Q+1)/2^lambda + s_b,

where s_b is the success of an explicit MSIS reduction. Distinguishing advantage epsilon implies BQS-witness probability at least

    2*epsilon - (Q+1)/2^lambda - (s_0+s_1)/2.

An MSIS solution remains a separate reduction alternative, not an authorized witness. For FALSE BQS instances the theorem implies hiding.

The instance, messages and advice are fixed before random encodings/oracles; access is classical. An instrumented generic-group transcript is legitimate model access, not a log an opaque concrete program must supply. This is substantive model-relative extraction. It is not automatically arbitrary concrete-encoding or QPT security, malicious-setup security, or a theorem for every public bridge correlation.

Section 6.2 discloses an MSIS attack estimate near 2^103.5 and a reduction cost near 2^108 for a 2^100-time attacker, excluding lifting. This leaves a concrete reduction gap. It does not produce a 2^95.5 attack, since reduction overhead is not an attacker and a short MSIS vector need not yield a heavy decrypting stack.

Selected exact checks pass: minimal g, threshold inequalities, interval size, `2*beta<q`, `24*beta^4<q^3`, root orders and Kummer non-power conditions. Exact rational calculations give `log2 E(2)=-122.955605878...` and positive endpoint slack about `2^(-20.222377913...)`. The script assumes the published scalar order is prime; it does not certify primality. A split-ring zero divisor was found, but not a random-matrix kernel solution. No lattice estimator/security estimate was independently certified. Full details: `parameters_agent/ASSESSMENT.md`.

## Lifting and Lean review

Daybreak independently audited Lemma B.9's mathematical steps. Bounded 4-by-4 minors are divisible by q^3 yet smaller in magnitude, so bounded vectors span dimension at most three. Prefix extension uses at most four generators. Integer functionals excluding the currently found span give at most eight fixed-dimensional programs per round, at most four rounds. Saturation/HNF stays in coefficient dimension at most four. Cramer's rule supplies the stated `18*beta^3` and `24*beta*max(18*beta^3,q)^3` bounds. No proof-breaking gap was found. The detailed derivation and actual action log are in `daybreak_agent/LIFTING_AUDIT.md`.

The pinned README discloses formalization boundaries: correctness uses `Enc` with exponent groups; security uses `encGame`, `encAt`, `pubView`; no refinement lemma ties those definitions together. Root inspection confirms shared exponent formula functions, with no demonstrated disagreement. A missing lemma is proof-coverage debt, not a counterexample. Lean's short-multiple reduction is exhaustive; the efficient algorithm is justified separately in the paper. Groth16 knowledge soundness and its verifier encoder, concrete BN254 attacks, lattice estimates and optimized implementation are outside the final Lean statement.

We read the no-sorry/axiom claims but did not build Lean. An optimized executable end-to-end Enc/Dec engine was not identified or run in the reviewed artifacts. Arithmetic counts are not measured wall-clock or deadline guarantees. Decryption deliberately has an exponential-in-security-parameter search; this does not meet the original asymptotic classical-PPT Open requirement without a scope change.

## Original bridge: the remaining equation

For a fixed withdrawal, the relation remains

    R_orig = R_more_BTC_work OR R_bad_burn OR R_Syscoin_inconsistency.

The inconsistency branch needs qualified authenticated histories/tag faults, not greater Syscoin work or a winning-branch choice. The separate BTC branch needs relevant strictly greater exact work from the same anchor. Claim, source, native message, outpoint, window, depth and capsule binding remain mandatory. This paper audit did not reread Core or run Core tests and makes no deployment claim.

The compact instantiation initially extracts an accepting Groth16 proof, not an ORIGINAL AuxPoW/burn certificate. The paper adds knowledge soundness and an honest CRS. Retaining the trapdoor allows false accepting proofs and decryption. A one-honest-party ceremony must establish the right CRS, capsule and native graph. A ZK proof of generation does not prove erasure or the security of the compiler.

Let P_pi construct the context/ciphertext, run A, then apply the outer extractor:

    T_pi = T_Enc + T_A + T_E(Q) + T_context,
    E_orig = K_Groth16(P_pi).

With the reported outer cost approximately `2^37*Q`, `Q=2^65` and `T_A=2^100` give `T_A+T_E` near `2^102.322`, below the quoted DLP budget 2^103. That arithmetic is consistent; it is not a combined 2^100 claim. The next knowledge extractor's time and loss still require specification.

The original-source bound would need a fully justified form such as

    p_cancel <= L*FindOriginalCert(T_orig)
                + epsilon_Praxis + epsilon_Groth16
                + epsilon_native + epsilon_setup.

Neither T_orig nor L can be silently replaced by the attacker's budget and one. An expensive extractor does not show the attacker expended comparable source work before the deadline. Directly compiling the original verifier removes the inner-proof layer but changes circuit size/cost and leaves other obligations.

The joint experiment must cover native verification data, sibling capsules, selective openings and retained malicious-source coins. Same-curve CRS/ciphertext cross-operations merit explicit modeling; no cross-pairing attack was found. Separate generic-group arguments are not automatically a concrete joint theorem.

Setup remains N-of-N with one honest participant; challenge remains permissionless with no online cooperation. One original certificate must open every needed contribution. The native signature must bind the actual claim or follow an explicit slot-global veto policy. Capsule witness-ID binding alone does not repair R225 common-outpoint portability.

## Conclusion and execution boundary

This is a serious conditional classical candidate and an external advance on common-output release. It does not finish original-source work security, hash-only/QPT security or the bridge. The next indispensable step is faithful executable/refinement work and original-certificate extraction with explicit resource loss and joint setup/native context. Repeating exposed-scalar attacks against hidden factors would not answer that obligation.

Actual computation: independent Python tie/subspace checks, rank-four certificate, parameter arithmetic and recovery identities. Three analysis agents and Daybreak contributed. No full Praxis engine, downloaded project code, Core test, quantum algorithm, funded transaction or deployment was run. No complete proof of the inverse theorem/adaptive reduction was independently reconstructed. No PR progress comment, breakthrough notification or automation change follows from this bounded review. Commit and comment receipts are distinct.
