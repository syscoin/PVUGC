# Exact-amplitude nonzero-decoy tensor capsule — 2026-11-25

Status: new repair trial rejected in its separable row-support serialization; not a qualifying ORIGINAL-source release advance. No ordinary PR comment.

## Continuity and selection before implementation

Actual PR #1 open/draft, head repo syscoin/PVUGC, branch research/pq-wkem-validation-20260918. Start and prewrite recheck 798ed697457c4d91b3e6f091c5fb21b178d4ef79, base tree e62c0aaa565dce6c04fadf16a3033ec481f6dc64. Read actual PR metadata, recent substantive discussion through R225, exact head changed-file metadata and SOURCE_ENTANGLED_PROJECTOR_CAPSULE_20261125.md (blob 5f178f64890dfeeb74e5cc2c066fb7d2142cb45c), SOURCE_STREAMING_FINGERPRINT_CAPSULE_20261125.md, SOURCE_SCOPED_TELESCOPING_KEYS_20261125.md, SOURCE_PUBLIC_FSS_TERMINAL_REPAIR_20261125.md and SOURCE_FULL_INPUT_PREPROCESSING_20261125.md at that head. New note path absent (404). No external literature or web, full PR diff, new Core fact, or production operation.

Missing operation: actual classical-PPT offline Build of a public capsule that returns the exact same frozen native cancellation S for every qualifying ORIGINAL source witness, with a joint-public arbitrary-QPT security argument. Mathematical change from the immediate preceding candidate: remove separate reset maps, fuse the terminal map into the last source occurrence, make every inconsistent row stream produce a nonzero decoy rather than the zero tensor, and derive the native mask from the EXACT terminal tensor including amplitude, not its projective line. Thus neither the preceding publicly accessible rank-one reset product nor its projective normalization argument applies as stated; weighted-sum annihilation also no longer holds. Allow arbitrary nonzero maps without idempotence or fixed trace, so recovering local projective factors alone need not recover the actual native pad. Screen the joint public operator representation including that missing scalar, rather than increase entangling depth or field size. This is not another R327 low-degree invalid-trace oracle or a per-occurrence input-label scheme.

## Actual candidate

Let x bind the full unchanged bounded original three-ground relation R_x(w), every protocol/claim/chain/window/source/native endpoint field and capsule ID. Compile its deterministic verifier to local Boolean NAND truth-table rows plus unary constants and acceptance. NAND can use distinct input wires: repeated-input NAND(x,x) is NAND(x,one) with a fresh constant wire. Make the accepted output a fresh wire and avoid contradictory unary constraints on one wire by inserting fresh gates. Every globally consistent locally allowed row stream projects to an actual original witness; every original certificate determines a valid stream. This is a proposed generic compiler for the full verifier, not a claim of a deployed BTC/SYS implementation.

For wire i use independent basis u,e0,e1,f over a prime field F_p. Each local first-write M_b sends u to e_b; repeated checks send e_b to e_b, e_(1-b) to f and f to f. At the last occurrence map e_b to a secretly sampled nonzero vector v_i and e_(1-b),f to a nonzero d_i not collinear with v_i; a first-and-last occurrence sends u directly to v_i. Unspecified images can be arbitrary (or zero if unreachable). For a valid local bit sequence the exact final vector is v_i for either bit; for any inconsistent sequence it is d_i. Initial state U0 is the product of u and fixed ancilla states. Terminal V0 is the product of v_i and the same ancilla states. Let T be an invertible secret constant-depth local linear circuit and U=T U0, V=T V0. Publish each complete allowed source row operator A_g,a=T (product of raw local maps M_i,j,a_i) T^-1; no separately published resets, local factors, or T. Publish U and D=enc(S) xor H_expand(domain,x,exactCanonical(V)). Exact canonicalization can use the projective tensor canonicalizer in the preceding note with the actual lexicographically first nonzero entry appended; that entry is computable by suffix-span contraction. Thus its output distinguishes nonzero scalar multiples. The public row operator is serialized as an actual finite support matrix, not a list of independently exposed per-wire factors. Constant arity/depth gives constant support size; exact tensor-train contractions for honest paths remain polynomial because every reached state is T of a product vector. Inconsistent paths are nonzero and noncollinear with V. Honest Open follows the source rows; every qualifying witness reaches exact V, and the same S. No extra source issuer, source common preimage or fake work.

For this explicit serialization choose wire placement so distinct wires of each row have disjoint T lightcone intervals (e.g. separate active wires by a constant number of ancillas exceeding twice the depth). More generally the attack below needs only a known partition of the row's support into disjoint conjugated local-map supports; T may mix neighboring source wires not appearing together in a row if such a layout is used. Constant-depth T is not revealed. The separated-layout condition is a real limitation, not asserted for every possible dense layout.

## New joint-public exact scalar reconstruction

For a gate row (g,a), each conjugated local map L_i,j,b=T M_i,j,b T^-1 is supported on its lightcone. Since those supports are disjoint in this serialization, A_g,a is their tensor product on the known partition (identity elsewhere). All L are nonzero. The adversary factors a public row matrix without recovering T: take a nonzero pivot entry of the tensor, hold all indices except one factor's row/column fixed, and divide that slice by the pivot. Use the lexicographically first nonzero global matrix entry under product row/column indexing, so each slice is the unique factor normalized by its own first nonzero entry. Equivalently reshape to paired row/column indices per factor and use rank-one tensor factorization. Let the public normalized factor be B_i,j,b and the hidden nonzero normalization scalar be t_i,j,b, so L_i,j,b=t_i,j,b B_i,j,b. Factors with the same wire, occurrence and bit across different source rows are identical after normalization. From the public row obtain the scalar rho_g,a exactly (the pivot), satisfying

    A_g,a = rho_g,a product_(i in g) B_i,j,a_i,
    rho_g,a = product_(i in g) t_i,j,a_i.

No individual hidden t is needed. The projective factorization alone would only reveal V up to a scalar. The new step recovers that scalar.

Choose any full baseline bit assignment q consistent with unary constants and the final output check, not necessarily with any NAND constraints. Every baseline bit is locally present at its NAND occurrences. Use the public factors B_i,j,q_i in chronological order, independently of which rows they came from. This path is locally consistent for each wire; by cancellation of T^-1 T its nonzero exact result is

    Y = V / prod_(i,j) t_i,j,q_i.

This computation stays polynomial: at all intermediate steps the state is a scalar times T of a product state, including when the selected factors are not a valid common gate row. It neither enumerates the ambient tensor nor uses an honest source witness.

For each NAND gate with target baseline input/output tuple (a,b,c), define signed integer weights on its allowed rows (0,0,1), (0,1,1), (1,0,1), (1,1,0), respectively:

    lambda00 = 2-a-b-c,
    lambda01 = b+c-1,
    lambda10 = a+c-1,
    lambda11 = 1-c.

These weights sum to one and their three bit marginals are exactly (a,b,c), checked directly by addition. For a unary fixed row take weight one. Because weights are integers, including negative values, for each occurrence and bit the signed marginal count is exactly 1 if it equals the baseline bit and 0 otherwise (the zero-bit count is one minus the one-bit count). Therefore

    Q = prod_(g,a') rho_g,a' ^ lambda_g,a'
      = prod_(i,j,b') t_i,j,b' ^ [b'=q_i]
      = prod_(i,j) t_i,j,q_i.

All inverses exist; no roots or discrete logarithms, no extraction from an adversary's representation, no query log, no affine low-degree oracle, no approximation and no field-size-dependent enumeration. Compute exact V=QY and derive the actual native pad, even though the selected baseline is not an accepting row assignment. This is a classical PPT attack on the specified serialization (also QPT). It works on FALSE as well as hard-TRUE when the simple unary consistency condition holds. Crucially it recovers the exact amplitude, not just the line, and uses no terminal projection or all-zero invalid state. The signed integer identities are used on public row normalization scalars, not on an inaccessible private coefficient evaluator. This is an attack on the local product structure, not an assertion that arbitrary tensor-capsule amplitudes are recoverable.

The same argument covers arbitrary nonzero per-local-event scaling as long as the exact globally valid raw path remains V, since each scalar cancels in the marginal identity. A separate layer-wide scalar can be absorbed into one local factor. An arbitrary per-row scalar that does NOT factor into local events changes the equation. Its exact product must itself be a common hidden value on every accepted source path; the above argument does not prove that for a non-factorized row weight. Adding random row-dependent scalars generally breaks every-witness correctness unless that common-product condition is enforced. That would require an actual source-dependent correlated weight construction and a joint simulator; simply imposing the condition is not a solution. Likewise if a gate's conjugated local supports overlap, tensor factorization by coordinate slices is not justified. Do not apply this proof to arbitrary dense entangling encodings. No further field, depth, basis or scalar sweep is justified without a concrete jointly simulatable serialization that avoids exposing the factors and row scalar relations.

## Executed bounded synthetic check

The accompanying exact executed Python file SOURCE_EXACT_AMPLITUDE_DECOY_CHECK_20261125.py has SHA-256 e9818d5b9b699b2ce14d1dd89aa11413998f1e98aefac3387898d2fe9f4237a5 and Git blob e0eb86785a202ce9e943d3fae62ddc2058ab7f13. Local CPython 3.13.5, NumPy 2.3.5; command python /mnt/data/pq_wkem_20261125_amplitude/check.py, exit 0. Fixture is the FALSE relation x=y=0, z=NAND(x,y), z=0. Three secret random invertible 8x8 maps mix each 4-dimensional wire with a 2-dimensional ancilla. Complete 512x512 NAND row matrices are serialized; the attack receives only U, masked synthetic bytes and public support/matrices. All four allowed gate-row streams produce nonzero decoys. Exact captured stdout:

    Four locally allowed source streams: nonzero decoys, no exact target.
    Exact (not projective) target recovered on FALSE; public scale: 24
    Target SHA256: 89fef88135e62d4b8bec5217809c636aae1da9f476a0c92572db8b376b78b7d3
    Synthetic pad recovery: exact.

The checker is a finite illustration of the algebraic attack, not a real original BTC/SYS certificate, signature, or QPT experiment. It executes no source verifier and makes no claim about concrete SHA security. The synthetic bytes are not live signing material. No native signature was created.

## Next construction boundary

The actual missing operation remains a classical-PPT, jointly simulatable, source-dependent public evaluator of exact same-capability release. Nonzero decoys and exact amplitude remove the prior shortcut but not the demonstrated factorized row shortcut. A candidate with genuinely overlapping supports would need an actual public representation and security argument against factor extraction via operator algebra as well as arbitrary non-path use; not simply a harder-looking representation. A non-factorized row weight must be constructively generated with the required original-source common-product property. Neither supplied here. No joint QPT simulator, malicious setup correctness, multi-capsule/auxiliary/source-retention theorem, FALSE or hard-TRUE reduction, accepted native forgery theorem or endpoint proof. The three independent ORIGINAL grounds, actual relevant authenticated ancestry/maturity, exact same-anchor BTC work, finite burn refutation, tag-fault typing, R316 coverage correction, R225 slot-global/activation-specific choice, offline one-honest setup and native scope all remain unchanged. No ordinary progress comment.
