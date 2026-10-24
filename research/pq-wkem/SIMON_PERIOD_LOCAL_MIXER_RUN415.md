# Run 415 — a genuinely quantum attack on hidden-period local release

Live exact start: `syscoin/PVUGC#1` open/draft/unmerged,
`research/pq-wkem-validation-20260918` at
`5b7371611bc96cc6286d5ad02babf48476ecfd16`.
Last ordinary substantive comment: 6067040320.
Exact dependencies read: Run 413 `CONDITIONAL_FRONTIER_SAMPLER_RUN413.md`
(blob `b9c7177769498f8db49b90682be3b9f25c6043e5`);
Run 259 `GLOBAL_FINGERPRINT_SOURCE_BINDING_RUN259.md`
(blob `c7f3b77f0273ca1cbe6f0b31c1a086b8eb3acbf2`);
CLZ applicability note (blob `c19d9d9cd515140e3ce62eac960cd548c0add622`).

## Scoped hidden-period attack

For any nonzero secret frame s in {0,1}^n and any permutation P on
{0,1}^n, let `c_s(u)=min_lex(u,u XOR s)` and
`F_(s,P)(u)=P(c_s(u))`. Assume the locally protected release region
publishes an independently, deterministically and coherently evaluable
classical polynomial-size implementation of F, while a hidden signing seed
K is exposed as `Y=K XOR s`.

**Exact property:** `F(u)=F(v)` iff `v=u` or `v=u XOR s`.
This is Simon's hidden-XOR-period promise, unchanged by arbitrary injective
output relabeling P, gate-frame randomization, or hypothetical perfect
source-code hiding. If the raw implementation leaks s directly, there is
also a classical attack; the quantum attack needs only black-box coherent
evaluation of its publicly available deterministic function.

A QPT attacker coherently evaluates F, measures the output register and
obtains `(|u>+|u XOR s>)/sqrt(2)`. Hadamard sampling returns y uniformly
from `s^perp`, i.e. y·s=0 over GF(2). With q samples, exact full-rank
probability is
`prod_(j=0)^(n-2)(1-2^(j-q))`;
rank-failure probability is below `2^((n-1)-q)`.
Thus `q=n-1+kappa` coherent evaluations and polynomial GF(2)
elimination recover s with probability >1-2^-kappa. Then `K=Y XOR s`
is recovered without an ORIGINAL witness. This attack is genuinely quantum,
not Grover's square-root improvement. A public checking key PK(K), setup
auxiliary data, and distinct UTXO/branch tags cannot undo already recovered K.
The honest setup/evaluator is classical PPT; the attacker arbitrary QPT;
no QROM rewinding or computational hardness assumption is used.

**Two-witness same-K negative control:** Sample distinct independent
source secrets a0,a1. Let public f be injective and define
`R((b,h0,h1),(i,w))=[b=1 AND i in {0,1} AND f(w)=h_i]`,
with `h_i=f(a_i)`. For b=1, the two distinct valid ORIGINAL witnesses
(0,a0) and (1,a1) recover the same K using different masked views
`Y_i=K XOR a_i`. For b=0, there are no valid ORIGINAL witnesses at all,
yet each period oracle F_(a_i,P_i) enables quantum recovery of a_i and K.
Consequently false-instance hiding fails. For b=1, recovering a_i also
finds an ORIGINAL witness, so this is NOT a true-instance extraction
counterexample. The finite checker uses an injective public toy permutation;
it does not assume a quantum one-way injection exists.

**Applicability boundary:** This is a falsifier for a specific periodic
frontier subroutine, NOT a complete generic-NP WE proposal and NOT an attack
against any actual CCMR/RIO, CLZ, or independently protected inseparable
local mixer. The toy setup samples its own witness/statement pair; it does
not encrypt arbitrarily supplied Syscoin instances. If the public evaluator
has no independently accessible exact XOR-period subroutine, the argument
does not apply. A probabilistic/stateful oracle without the fixed period
promise requires a new analysis.

The attack taxonomy relevant here: functional/global frame symmetry,
two-to-one statistical fingerprint, coherent adaptive chosen-input queries,
honest setup failure, and checking-key/cross-branch exposure. A single
capsule suffices; no malformed setup, reused key, neighboring-gate seam,
or classical key-recovery extractor is needed.

## Validation and literature

The **exact executable checker** accompanies this note and produced the
captured JSON output. It exhaustively checks finite XOR-period promises and
Hadamard spectra for n=2..6, simulates many Simon period recoveries, and
verifies two distinct witnesses recover one K while the b=0 false instance
is broken. These are finite classical simulations of quantum statistics,
NOT quantum computational hardness tests or a practical obfuscator.

The CCMR local-mixing work (https://eprint.iacr.org/2024/006) describes
a conditional RIO-to-iO route under additional reversible-circuit
pseudorandomness; it does not provide concrete PQ WKEM security. The
Gheorghiu–Gupte–Havlíček–Liu 2026 abstract
(https://arxiv.org/abs/2609.40289) discusses quantum iO and a local-mixing
extension. Neither full proof was audited here, and neither is alleged to
expose this Simon oracle.

**Still UNPROVED:** an actual compact source-dependent public release
primitive; general-NP all-witness SAME-K correctness; complete-public
false-instance QPT hiding; unauthorized true-instance signing/recovery ->
accepted complete representation -> ORIGINAL via Run 259 or independent
QPT break; malicious N-of-N ceremony/abort/erasure; joint-capsule security;
128-bit resources; conditional P2MR/native SLH Bitcoin endpoint.
Production unchanged, PR stays draft/unmerged. No stopping condition met.
