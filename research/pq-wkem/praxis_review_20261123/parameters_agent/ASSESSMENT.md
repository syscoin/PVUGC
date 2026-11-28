# Praxis parameter, cost, and formalization audit

Date: 2026-11-23. Read-only review; no downloaded project code was executed.
The independently written `check_parameters.py` was executed successfully and
its full exact-rational output is `parameter_output.json`.

This bounded review did not produce a verified attack on Praxis. Its arithmetic
checks do not establish the claimed MSIS attack cost, concrete-group security,
or bridge suitability.

## Sources pinned

- Paper: https://eprint.iacr.asia/2026/2971.pdf, 66 PDF pages. Printed page numbers
  below are one larger than the zero-based PDF page index.
- Formalization: `psivesely/praxis-lean` at
  `60d3defeebd77caa0e57babe97991e672b948bb6`.
- Constants: `Praxis/Constants.lean`, blob
  `494e9eac6cc1ddc94e1cddb92f8e8d69a57a7276`.
- README: blob `878751b193ecad0470d46134fa29efa86ab9a359`.
- Main theorem predicates: `Praxis/Main.lean`, blob
  `3e8c1e086bb1a96530e2dcf50c32fd2f9a1f7739`.
- Scheme: blob `a0a4eba9f596f69ce369431fce36868a549e4067`.
- Reference decryption: `Praxis/Dec.lean`, blob
  `6c684b07b1ddd40af62272f11ce84c5ac1faeb58`.
- Reduction: blob `4a2c6abbc178f190b56634bdb4ad75a7eaccb83b`.
- Counted extractor: blob `abf271114dd13ff90d54a422e8649dfa01ca0fdf`.
- Params: blob `f0756a6e5e5971a7a2aee0567e06760b18fcad7b`.
- Kummer: blob `57549428dd59272a537e33cabc7562eaeb38fab4`.
- Complete path inventory: tree `97a6265178ae4ee45012a4c53173ae2d2fdcfc0f`,
  recursive response untruncated, 692 entries.

## Independent exact arithmetic

The script uses integer arithmetic and `Fraction` for the acceptance checks;
floating point is used only for reported base-two logarithms and the explicitly
heuristic GSA sanity calculation. It imports no third-party package.

The modulus checked is the scalar order, not BN254's different base-field prime:

```
q = 21888242871839275222246405745257275088548364400416034343698204186575808495617
eta = 243263909612554812554484966287587365620785086315305388991
```

`eta` is the paper's MSIS norm bound beta. `Constants.beta` is instead a root of
unity; confusing them would invalidate a parameter audit.

Checks passed:

1. `(g-1)^8 < 2^405 <= g^8` for `g=1736375024658487`.
2. `g^-4 <= 2^-202 < theta < 2^-201`, `theta < g^-3 < g^-2`.
3. `24 eta^4 < q^3`, `2 eta < q`, and `2(N+1)(g+1)+1 < q`.
4. `n=4608=2^9*3^2` divides `q-1`, `q mod 4=1`, and 5 is neither a square
   nor a cube modulo q. Thus the finite-field binomial irreducibility criterion
   for `T^4608-5` holds, conditional on q's primality. This script does not
   independently certify that primality.
5. The root-of-unity value in Constants.lean equals `5^((q-1)/4608) mod q`,
   has exact order 4608, and its 2304th power is -1.
6. Dimension and split-ring consistency: `(k+1)d=4608`, `ell=ceil(N/d)`,
   `K1*K2=n/2`, and `128 | q-1`.
7. Exact substitution into Definition B.1, using `L1=151468814`,
   `L2=56828073`, and `LT=2`, gives `E(2)<2^-122` and
   `E(2^101)-E(2) <= 1-2^-100`. The observed logarithms are
   `log2(E(2))=-122.95560587803573` and
   `log2(1-2^-100-(E(2^101)-E(2)))=-20.222377913441505`.

These checks confirm selected consistency and error-budget inequalities. They
do not reproduce every inverse-theorem condition or its analytic constants.

## Structured MSIS probes

Paper Definition 3.3 uses `R_q=F_q[Y]/(Y^64+1)`. I explicitly found 64 distinct
roots by constructing a primitive 128th root and taking its odd powers.
The coefficient system has `71*64=4544` scalar equations and
`6121*64=391744` output coordinates. This large output space alone does not
supply a short nonzero kernel vector.

### One-slot CRT localization is not automatically a short solution

For a nonzero integral polynomial z of degree below 64 and coefficient norm at
most eta, Parseval and AM-GM on the primitive 128th roots give

`0 < |Norm(z)| <= ||z||_2^64 <= (64 eta^2)^32`.

The nonzero norm follows because `Y^64+1` is irreducible over the rationals.
At the split, unramified prime q, vanishing in v distinct CRT components forces
`q^v | Norm(z)`. Exact comparison yields v at most 48. Consequently every
nonzero short coordinate is active in at least 16 of the 64 CRT components.
In particular, taking a kernel vector at only one CRT root and interpolating
does not bypass the shortness requirement. This is a limited obstruction to a
particular shortcut, not a hardness proof.

### There are nevertheless short nontrivial zero divisors

Cornacchia's elementary Euclidean construction gave

```
a = 147946756881789319005730692170996259609
b = 14896984101578546644
a^2+b^2 = q
```

The polynomials `a+bY^32` and `a-bY^32` each vanish at 32 CRT roots. Their largest
coefficient is about `2^126.798`, well below eta. It would therefore be wrong to
argue that this norm bound forbids all zero divisors. The script verifies both
vanishing counts directly.

These polynomials are **not** solutions of the random 71-row MSIS matrix. A
vector multiple still has to vanish under that matrix at the remaining roots,
and multiplying by the displayed factor consumes roughly 127 bits of the
187-bit coefficient budget. I have no verified algorithm that uses this
observation to beat the paper's cost estimate. A rough GSA check for an
unstructured coefficient lattice is consistent with the scale of block 242,
but it is not the MATZOV estimator and certifies no attack cost.

## Security-budget interpretation

Section 6.2, printed page 36, explicitly separates the estimated MSIS attack
cost (about `2^103.5`) from a reduction on a `2^100` adversary (about `2^108`,
before polynomial lifting). This acknowledged loss prevents treating the
parameter choice as a tight 100-bit reduction to the quoted MSIS estimate. It
does not itself give a faster attack on witness encryption.

The distinct extractor-composition arithmetic in Section 6.1 is consistent.
`2^65` calls times an estimated `2^37` extractor operations per call is
`2^102`, and adding adversary cost `2^100` gives `2^102.321928...`. The text
compares the composition with its approximately `2^103` BN254 discrete-log
budget, not with `2^100`. Thus the 65+37 arithmetic is not a discovered error.
The estimates' units and constants still matter for a concrete deployment.

## Formalization scope observed in source

The README discloses, and the inspected definitions confirm, a separation
between correctness of `Enc` over `expGroups` and security of `encGame`,
`encAt`, and `pubView`. There is no proved equality connecting those two
encryption implementations in this reviewed artifact. A mismatch must be
found to turn this proof-coverage gap into an attack; none was established.

Other explicit boundaries:

- The final extraction bound retains MSIS reduction-success terms. It does
  not prove the hardness of the concrete MSIS parameter set.
- The Lean reduction calls an exhaustive short-multiple search. A polynomial
  algorithm and its runtime are arguments in the paper, not that executable
  Lean reduction.
- Correctness is over exponent groups. The concrete BN254 representation and
  its non-generic attacks are not formalized by that result.
- The theorem takes an admissible choice of evaluation points; this artifact
  does not construct one. The paper supplies the existence argument.
- Groth16 knowledge soundness and the verifier-to-BQS encoder lie outside the
  Lean theorem. The README says the encoder is planned for future verification.
- The paper and Lean differ in key derivation (label versus sign-class name),
  message/seed lengths, and monitor access. These differences are disclosed.

I did not run `lake build` or `#print axioms`; the no-sorry/three-standard-axioms
claim was read, not independently established here.

## Search, completeness, and implementation limits

Definitions 3.4-3.5 and Theorem 5.6 use a fixed statement/witness before the
oracles are drawn. A valid witness with nonzero key coefficient reconstructs
the same kappa. The exceptional-coefficient probability is per fixed witness.
This needs care if a bridge asks for a single maliciously prepared package
with simultaneous guarantees for all future adaptively selected certificates;
the standard fixed-witness theorem should not silently be strengthened.

The centered sampler gives the same symmetric law for each fixed Boolean
witness. Appendix B.1 treats rounding and gives a certified analytic tail
calculation, rather than only a normal-approximation heuristic. I have not
independently reproduced its 192-bit ball-arithmetic certificate. The
`2^-40` practical tail figure excludes extra work on false fingerprint matches.

The cost section counts arithmetic. Compression/decompression, hash expansion,
memory traffic, sorting, and probing are not included. A bounded arithmetic
count should not be described as an independently measured end-to-end time.

The reviewed PDF links the project's Lean repository. Its complete pinned
tree contains only Lean source plus seven metadata/documentation files; no
separate optimized Enc/Dec engine or standalone encoder/cost script was
identified there. The paper reports checks and an implementation cap, but a
public optimized executable and end-to-end benchmark were not identified in
the reviewed paper/repository. This is not a claim that none exists elsewhere.

## Bridge consequences, without declaring a break

Praxis does not require different valid witnesses to share a preimage: its
algebra is designed to recover the same kappa. That is relevant to the
bridge's missing release mechanism if its additional foundations are accepted.

To import it into the bridge, one must still establish the exact original
relation, knowledge extraction through the succinct proof wrapper at the
needed resources, honest/verified setup, capsule/signature/claim binding,
malicious-capsule useful completeness, correlated auxiliary information,
multiple capsules, and timely inclusion. A Groth16 trapdoor can create false
accepting proofs and hence release; an honest setup is an explicit requirement,
not a contradiction of the stated theorem. Proving one package's relation and
distribution does not automatically prove all of these deployment properties.

The generic extractor's overhead also prevents claiming an automatically
preserved PoW budget. An implication to a qualifying original certificate
must include the extractor and wrapper costs and success losses.

## Error/provenance notes

The official direct PDF returned 403; the mirror was successfully read via
the linked PDF reference. One guessed read-only path, `Praxis/Parameters.lean`,
returned NOT_FOUND/404; the imported real path `Praxis/Params.lean` was then read.
No policy denial, remote write, Lean build, estimator run, ciphertext benchmark,
or bridge/Core test was performed by this agent.
