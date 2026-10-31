# Joint-view reduction checkpoint: the current pivot-Schur carrier has a certified key-recovery path

**Classification: security correction, not a positive construction advance.** The requested arbitrary-key-recovery-to-ORIGINAL-witness reduction is not proved. A public, key-independent certificate now identifies honest outputs on which ordinary finite-field linear algebra determines the exact capability. The SOURCE compiler and the earlier supplied-representation theorems are not contradicted. No secure replacement is established.

Interactive checkpoint `joint-view-reduction-20261024`; no scheduler run identifier was supplied. Live connected reads pinned `syscoin/PVUGC#1`, branch `research/pq-wkem-validation-20260918`, at `fb1772abab1597cd7821623927b2fb318cb2fa9b`, open/draft/unmerged. Latest substantive comment read: 6379933178. No production, workflow, Bitcoin transaction, actual wallet, real credential or third-party system is involved in the checks.

## 1. Exact continuation, not another quotient-only argument

The pinned quotient-recurrence README and archive were read/verified. Archive Git blob: `445ed01b984f75857aec8f84132f240f24bdab3c`; its `quotient_recurrence_check.py` SHA-256 is `b227773d7fe65e241bd808a54cf5a91192140e561f67c3b96953da9023a4a464`. The predecessor full-extension archive is Git blob `75af2bea31ff5389804f17e3087b09353d695532`. The last local canonical-quotient note was also inspected; it was not on the live branch.

The earlier quotient-only reconstruction did not recover the third local frame. This result instead combines BOTH families of nonconstant original-coordinate projections with the labeled quotient markers. All certificates and recovery computations use the public matrices; hidden factors and the actual key are used only afterward by the synthetic checker to verify its answer.

For each node, write the columns of its hidden left factor as u1,u2,u3, and the rows of its hidden right factor as v1,v2,v3. The exact current gate is

    G(y) = [[c, a*, s], [b*, pi, 0], [s, 0, pi]].

All these entries are linear in the extended source. The private orientation selects one of

    type 0: a*=a,       b*=b+mu*c, pi=z+mu*a;
    type 1: a*=a+mu*c, b*=b,      pi=z+mu*b.

Here a,b,c include the existing SL2 and Boolean-Frobenius transformations. The derivation below does not remove those transformations or assume their coefficients are known.

The public constant matrix is C0=K I+M0. The nonconstant ORIGINAL matrices are C1,...,Cn. Public quotient slices have the established form Qj=A D^j B, rank(Q0)=2L. The field is E, of characteristic two; F is its stipulated source subfield. Only honest setup is analyzed. No new cryptographic hardness assumption is introduced.

## 2. Public support certificate

On rank(Q0)=2L, the existing public rank factorization and labeled eigenspaces yield each rank-two node marker

    Re = ae*(u1*v3 + u3*v1),

where ae is public and nonzero. This follows from the already verified quotient recurrence, without secret-factor recovery.

Let PL be a full-row-rank left annihilator of Q0 and PR a full-column-rank right annihilator. Thus PL kills every u1,u3, and PR kills every v1,v3. Form the public spaces

    SR = rowspan of the vertically stacked PL*Ci, i=1,...,n;
    SL = columnspan of the horizontally concatenated Ci*PR, i=1,...,n.

They contain no key-bearing constant slice. Let L0,L1 be the numbers of the two private orientations. From the exact gate and z=0 on every Ci with i>0:

    SR is contained in span({v1,v2 for type 0}, {v1+mu*v2 for type 1});
    SL is contained in span({u1+mu*u2 for type 0}, {u1,u2 for type 1}).

Consequently dim(SR)<=2L0+L1 and dim(SL)<=L0+2L1. A PUBLIC equality

    dim(SR)+dim(SL)=3L                                      (A)

forces equality in both containments and independence of the listed spanning vectors. The attacker need not know the orientations to check (A).

For every node also check PUBLICLY that

    (dim(rowspan(Re) intersect SR),
     dim(colspan(Re) intersect SL)) is either (1,0) or (0,1). (B)

The first pattern certifies type 0 and exposes the line spanned by v1. The second certifies type 1 and exposes the line spanned by u1. This is a deterministic implication: type 0 already puts v1 in SR, and type 1 already puts u1 in SL. Extra accidental intersections cause certificate failure, not an assumed success.

Let H span the left annihilator of SL, and Z the right annihilator of SR. These are again public. Put a=rows(H)=L0+h and b=columns(Z)=L1+h, where N=2L+h.

## 3. Recovering the remaining projected matrix space

For type 0, Z kills v1 and v2. Therefore

    H Ue Ge(y) Ve Z = (s*H*u1 + pi*H*u3)*(v3*Z).            (C0)

For type 1, H kills u1 and u2. Therefore

    H Ue Ge(y) Ve Z = (H*u3)*(s*v1 + pi*v3)*Z.              (C1)

The two-dimensional space containing each expression is publicly reconstructible, even though the third private factor itself was not reconstructed from the quotient alone.

For type 0 choose any public rank factorization

    Re = [r1,r3] * [t3; t1]

with t1 spanning the certified row line v1. This is ordinary basis extension in a known rank-two row space. The supplementary rank-one matrix Te=r3*t3 satisfies

    H*u3*v3*Z belongs to span(H*Re*Z, H*Te*Z).

Indeed the freedom in choosing the other row replaces v3 by a nonzero multiple of v3 plus a multiple of v1. Z kills the latter; the corresponding column change only adds a multiple of the already known projected marker.

For type 1 use the analogous factorization with r1 spanning the certified column line u1. H kills this line, giving the same two-dimensional containment. The known nonzero ae and choices of scaling do not affect either span.

Define the entirely public matrix space

    S = span_E{H*Re*Z, H*Te*Z : every node e}.

Equations (C0),(C1) prove, simultaneously for EVERY source value y, that

    H*M(y)*Z belongs to S,       dim(S)<=2L.                (D)

This is a statement about the complete matrix, not a rank test and not an assumption that an adversary supplies a source.

## 4. Exact public-view recovery theorem

**Theorem.** For any honest current-gate capsule satisfying rank(Q0)=2L, (A), (B), and

    H*Z not in S,                                          (E)

a deterministic classical polynomial-time computation on its PUBLIC output recovers the exact K. It requires neither an ORIGINAL witness nor a key selector.

**Proof.** Conditions (A)-(D) construct S publicly. By (E), finite-field Gaussian elimination supplies a linear functional ell with ell(S)=0 and ell(HZ)=1. Then

    ell(H*C0*Z) = ell(K*H*Z + H*M0*Z) = K.

Every operation before this final contraction uses only nonconstant public matrices. There is no enumeration of possible K, no native forgery oracle, and no cryptographic assumption. QED.

The theorem is CERTIFICATE-CONDITIONAL, not a claim that every relation or every parameter set satisfies its certificates. Failure of a certificate is not a security result.

For the last local two-sided canonical format, replace I by its mandatory public metric W. The last condition is H*W*Z not in S and the contraction is normalized by ell(HWZ)=1. The known diagonal quotient markers can be generated from the canonical node description. Two-sided public coordinate normalization therefore does not remove this mechanism. Random invertible two-sided changes with the transported W are exercised by the checker; the exact fixed canonical chart was not independently rerun in this checkpoint.

### A scoped probability statement for the final metric condition

Conditioned on (A),(B) and the quotient rank event, the independent-uniform outer-factor distribution is invariant under multiplying all left factors by an independent uniform T in GL_N(E). The projected baseline space is invariant up to a public basis change, whereas the metric becomes H*T^(-1)*Z in fixed reference coordinates. For a uniform unrestricted N-by-N matrix A, HAZ is uniform over Mat_(a,b)(E). An unrestricted square matrix is invertible with probability greater than 1/4, for every finite field. Thus

    Pr[metric in S | preceding invariant certificates]
        <= min(1, 4*|E|^(dim(S)-a*b))
        <= min(1, 4*|E|^(2L-a*b)).

This does NOT bound the earlier support-saturation probability. It shows that the last separating-functional step is not being justified by dimension counting alone.

## 5. Generic asymptotic corollary, with its parameter-choice qualification

The finite checker supplies a nonzero algebraic certificate, not merely empirical success: seed 1000 has all eight SL2 p coordinates nonzero, orientation pattern (0,0,0,0,0,0,1,0), saturated spaces of dimensions 9 and 15, all required intersections, and a 16-dimensional projected space excluding the metric. The full list of SL2 values is recorded in validation.json.

Consider this FIXED false source (four Boolean wires, seven rows), eight release nodes, h=5, over F=GF(2^(4s)) and E=GF(2^(8s)). Embed the same GF(16) gate nodes and six deterministic off-domain nodes. The other two off-domain nodes may be sampled distinctly as in the sampled compiler. Permit the public extension parameter theta to be sampled uniformly outside F. This last parameter choice is explicit; the statement does not claim the same bound for every prescribed fixed theta.

Write tau=sqrt(theta), r_ei=sqrt(b_ei), and eta_e=sqrt(e). Then alpha_ei=r_ei+tau*eta_e^(i-1). All setup entries are rational functions of field coordinates, of degree bounded independently of s: use the SL2 chart t=(1+q*r)/p with p nonzero, the public fixed-degree QAP polynomials, independent outer factors, and these polynomial shear coordinates. Sampling r_ei is uniform in F; tau and private pivots are sampled outside F. No q-dependent square-root exponent is needed in this algebraic argument.

Each desired lower rank and upper intersection bound can be certified by selected nonzero minors; structural inclusions supply the corresponding upper ranks. Choose the minors and rational bases witnessed by seed 1000. Clear their nonzero denominators. The resulting product is a NONZERO polynomial over GF(16), of fixed finite degree D. A nonzero evaluation in the embedded GF(256) proves this algebraic fact. For larger fields that particular evaluation need not lie in the sampling domain; polynomial nonzeroness does not require that. The actual sampling sets have size at least |F|-O(1), so the ordinary polynomial root bound applies to them. Conditioning the two sampled nodes to be distinct and off-domain changes only the O(1/|F|) term.

Conditioned on the displayed orientation pattern and the nonzero-p charts, all certificates therefore hold with probability 1-O(D/|F|). The orientation pattern has probability 2^-8 and the charts have probability 1-O(1/|F|). Hence this allowed generic parameter family has classical exact-key recovery probability at least

    2^-8 * (1 - O(D/|F|)).

D is independent of the security parameter but was NOT numerically computed; this is an asymptotic corollary, not a concrete 128-bit attack-success estimate. For a fixed theta, specialization can have exceptional values; no universal fixed-theta or arbitrary-circuit support-saturation bound is claimed. Nor was the 11,000-variable / 381-TB parameter instance executed.

This corollary is enough to rule out an unqualified false-instance hiding theorem for the current construction across its allowed parameter choices. More generally, the public certificate theorem identifies individually exposed outputs regardless of any asymptotic estimate. A classical polynomial-time algorithm is within the arbitrary-QPT threat model.

## 6. Exact false SOURCE and honest-correctness control

The ORIGINAL wires are (u,v,a,b). Include their four Booleanity rows, followed by

    u*v=a,   a=1+b,   a=b.

Every wire is used. The final two equations contradict one another in every characteristic-two field, not just for Boolean values. No valid ORIGINAL witness exists. There are no unused dummy input coordinates. This fixture uses the actual R1CS interpolation, unique Frobenius quotient coordinates, private SL2 terms, extension-separated shears, private random orientation/pivot, and independent two-sided outer matrices of the current carrier.

The public-only routine receives only the published coefficient matrices, public node labels, and original-coordinate count. The secret key and node factors are compared AFTER recovery in the test driver; neither is a recovery input.

For a true control, replace the final row by b=1. Its three Boolean witnesses are (0,0,0,1), (0,1,0,1), (1,0,0,1). Exact QAP division and public evaluation confirm the intended common-key rank correctness for all three. Thus the failure is not manufactured by turning off the compiler or breaking honest recovery.

## 7. Repair attempted, not promoted to a solution

A natural repair is to use both private pivot orientations at once:

    a*=a+nu*c, b*=b+mu*c,
    pi=z+mu*a+nu*b+mu*nu*c.

The exact identity pi*c+a* b*+s^2 = z*c+a*b+s^2 preserves the determinant and valid-witness rank behavior. It does NOT repair the complete public view. When the nonconstant support spaces saturate, both contain the first and middle local factor directions. Their public dimension sum is 4L, both node intersections expose the first-factor lines, and the doubly projected baseline lies in the public span of the supplementary u3*v3 terms. The same final functional recovers K. Twelve fresh synthetic setups confirm this failure. This repair is rejected, not counted as constructive progress.

Simply re-randomizing the public frame is also insufficient: the theorem transports with W. A generic LWE encryption wrapper is not a repair: the existing Run-122 LWE pad proof does not supply the missing simulation-aware SOURCE-opening interface, and a wrapper keyed by an already recovered capability provides no witness restriction. No new assumed release oracle is substituted.

## 8. Executed validation and exact scope

Final `check.py` is standalone Python 3 standard-library code. It has no network, external-ciphertext loader, Bitcoin/wallet interface or production capability. It runs only its own synthetic fixtures. The finite field tables are GF(16) inside GF(256), not cryptographic-size parameters or a claim that the generator is production-ready.

Two final executions produced byte-identical `validation.json`. The final run records 24,979 explicit algebraic assertions, including:

- 128/128 distinct synthetic false-source setups passed the public certificates and returned the exact setup key.
- 12 true setups passed the public-view check; their 36 valid-witness evaluations retained common-key correctness.
- Four independent invertible two-sided public-frame changes recovered the same key using the transported public metric.
- Twelve two-sided-pivot repair setups remained exposed.

No key brute force, native signature forgery, quantum simulation, cryptographic-size matrix generation or independent external review was performed. Test counts are not security evidence. The deterministic theorem is proved above; the generic asymptotic corollary has the stated fixed-fixture and public-parameter qualifications.

During development the first standalone integration omitted the local `sl2` helper and raised AttributeError. It was corrected before both final executions. An attempted binary GitHub content read returned INVALID_ARGUMENT / HTTP 400 (UTF-8 only); directory metadata succeeded and the mounted archive's independently calculated Git blob matched the live entry. These are distinct from policy blocks, and no policy block occurred.

## 9. Cumulative record and handoff

Retain: ORIGINAL R1CS semantics, Frobenius projective normalization, same-capability correctness, exact quotient serialization, and their precisely scoped supplied-representation results. Do NOT promote them to arbitrary-key secrecy. The current 3-by-3 pivot-Schur carrier must not be described as a secure construction merely awaiting a proof. The displayed joint-view exposure is a material counterexample class.

No positive secure-carrier replacement was established in this invocation. The remaining constructive obligation is to instantiate a release distribution whose ENTIRE public joint view admits an independently justified QPT reduction. For the current representation, that obligation must account for both projected original-coordinate support spaces, not merely quotient-only or fixed-probe hiding. Further padding/compression or another triangular pivot is not an established repair. Run 259 remains downstream SOURCE binding only; it is not invoked as an extractor for the key-only procedure above. The Run-122 QPT-LWE pad theorem remains scoped to its unsolved source-opening interface.

The conditional native PQ endpoint and N-of-N honest-erasure baseline are unchanged and do not repair this algebraic exposure. No malicious-setup, multi-capsule, early native-forgery or practical-package theorem is claimed. Single-capsule false-source recovery is already sufficient to invalidate an unqualified security claim. Keep the PR open/draft/unmerged and do not disable the research program.

Publication status is recorded separately from this mathematical status. Publishing this correction is not a positive construction advance or evidence that scheduled execution has recovered.
