# R201 — Source-convergent hash gate and global-consistency regression

**Status:** research-only failed candidate plus exact repair obligations. NO original-source Build/Open construction, NO full-public QPT proof, NO deployed BTC/SYS checker. This is NOT a qualifying constructive breakthrough and does not warrant a PR progress comment.

## Continuity, provenance and actual execution

syscoin/PVUGC PR #1, branch research/pq-wkem-validation-20260918. Observed starting head dce45f27382fc2ee1b79cf4e88e36e364f5a77da (open/draft/unmerged); exact R200 source-binding note read at blob e72d39905fe225f48b8fbd0b8340fc756cc45f04. Intermediate CHECKPOINT_01.md was committed first at 741d8ed258f29628b8da8f88a9fc7af3e8447eb7, parent dce45f2, via expected-head non-force update. Most recent ordinary comments since 2026-11-10 12:00Z: none at initial read. No web, external literature, independent agent, production code update, real native signature, mining, or QPT experiment.

The Python SHA256 fixture checker was actually run twice locally, with byte-identical captured output. Its SOURCE SHA256 is 2bbfb2f778f9e14d434071e5eb38e3965aaca8bed68f509cf676cb2b2bfe76ec; Git blob a9a94f8a92183b26d0436c86ee68dc88394ed53c. Captured SHA256 is abe9cd2aa0748b2898fdb2a76d4bc47135415ecea93074650c4ed97d22291351; Git blob 4df9c65412b0391dc8dd311fecf0da2267bf4428. Total 2,176 deterministic assertions across 128 seeds. This exercises two synthetically defined hashes of branching histories, not genuine AuxPoW or real Bitcoin/Syscoin admission. The verifier branches and labels are NOT a WKEM.

## Candidate A — a common secret-looking fingerprint from the source

Attempt to freeze a claim/path-scoped native cancellation signature sigma by publishing

  E = sigma XOR H_pad(x,t),

then publicly recover with

  Open(C,w) = E XOR H_pad(x,F_x(w)).

For every qualified ORIGINAL BTC-work, PoB-fault or SYS-fork/tag witness w to recover the SAME sigma, the requirement is H_pad(x,F_x(w))=H_pad(x,t) for all w. The builder must fix t before any possible later witness-only one-notary activation. A source-authenticated value is not automatically hidden.

For the claim-prefix SYS fork relation, test actual source-history candidates, not independently sampled tokens:
- F_x(w) = U_baseline = PureChildHash(Ancestor(baseline,h_rel)). This is fixed and known from x, so anyone decrypts E before a conflict.
- F_x(w) = U_alternate = PureChildHash(Ancestor(challenger,h_rel)). Distinct qualified alternate branches can have distinct U_alternate, so their pads differ. Correctness for ALL witnesses fails.
- F_x(w) = H(lowest_common_ancestor). It varies with the first divergence; normalizing it to the globally common anchor makes it public and immediately accessible.
- F_x(w) = H(full source proof). This varies even across distinct Bitcoin work certificates of the SAME Syscoin child, violating the semantic-outcome versus WorkID separation.

The executed synthetic checker produces two different conflicting alternate claim-prefix hashes for one baseline, detects distinct pads, and demonstrates public early opening under baseline or shared-anchor pads. This proves only the scoped fingerprint-family failure, not impossibility of hash-only witness encryption.

## Candidate B — hash-garble the actual SHA/source verifier and publish both witness-bit labels

Hypothesis: freeze a secret final true-output label Z1, publish CK=H_check(Z1) and E=sigma XOR H_pad(Z1), and garble source-verifier gates using SHA256 of gate input labels. Since original evidence is arbitrary and any challenger must evaluate offline without a secret issuer, make both input labels public.

Full-public FALSE security already fails for the deliberately tiny Boolean relation R(x)=x AND NOT(x), which has NO witness. Build NOT(X0)->Y1, NOT(X1)->Y0 and AND(Xa,Yb)->Z_(a&b). All gate rows encrypt output labels under domain-separated SHA256 pads of their input labels; input labels X0 and X1 are both public.

Both globally consistent evaluations x=0,1 produce output label Z0. But an attacker can:
1. Decrypt the NOT row for X0 to obtain Y1;
2. Take the OTHER public input label X1;
3. Decrypt the AND row for (X1,Y1), producing Z1;
4. Pass public CK and recover E XOR H_pad(Z1)=sigma.

No globally consistent x satisfies R; the attack splices two mutually inconsistent local gate evaluations. It is explicit polynomial-time **classical** computation and therefore a QPT attack without any quantum query. The checker verifies honest zero outputs, the forged true label, CK verification and exact raw secret recovery for 128 independent seeds. It does NOT claim SHA or real cryptographic systems broken; the chosen public input-label distribution is insecure.

This is a true attack on the full PUBLIC view of this precise garbling attempt, not an implementation bug in honest Open. Neither an ordinary if-verification before return nor native signature checking after key recovery removes the raw output-label path.

## Repairs examined, and the exact remaining obstruction

(1) **Only one globally consistent input label per source bit.** This would prevent the displayed mixing attack, but actual SYS pure-child headers, AuxPoW, parent coinbases, and SHA traces contain public bit strings, NOT secret labels correlated with a precommitted cancellation pad. Labels L_(i,b)=H(public_context,i,b) are freely generatable for BOTH b. Labels L_(i,b)=H(secret_seed,i,b) are unavailable to any offline challenger even with a genuine source witness. This is not fixed by a capsule-root commitment, which only authenticates bytes.

(2) **Bind every wire to a whole-proof digest t=H(w).** This digest is publicly computable from ANY bytes w, including fabricated evidence, so it does not restrict who can generate both bit labels. Keying labels under a secret makes Open fail; using t as pad fails SAME-secret correctness across different real qualified evidence and future mined activation variants.

(3) **Monolithic truth table over all complete assignments.** It can eliminate this tiny mixing attack by checking global consistency, but direct construction evaluates 2^m assignments for m input bits. That is not a classical PPT compiler for the actual source relation. This observation is scoped to an explicit table, not a universal lower bound against all compressed circuits.

(4) **Add source authentication as a public guard.** An adversary ignores the guard and decrypts existing gate rows; only a cryptographic dependency of hidden label access on the ORIGINAL authenticated witness suffices. It must not silently replace BTC/SYS evidence with synthetic signer labels.

(5) **N-of-N setup and separate branch capsules.** Any N-1 corrupt contributors may retain their own signatures; an honest participant built from this broken gate still opens early. Moreover sharing the same signature among three OR challenge capsules requires JOINT full-public security, not independent marginal claims. One combined OR predicate is preferable until an actual leaf gate exists.

## Mandatory original relation and security boundary

Bind claim/vault outpoint, preauthorization slot and safe native cancellation message/VK, wtxid-authenticated mined notary assertion when witness-only activation is allowed, BTC history anchor/work/window, bound SYS burn state, tag/ancestor semantics and relevant challenge depth. The ORIGINAL OR includes (i) valid heavier competing BTC work, (ii) finite authenticated wrong/missing PoB for THIS withdrawal, and (iii) qualified SYS claim-prefix incompatibility/tag fault. A false tag must be challenged using separately authenticated outer evidence; two WorkIDs for the same pure Syscoin child are not a fork. Source authentication is an input to release, not a standalone public verifier switched on before decrypting.

Honest classical PPT Build(x,sigma) must be possible BEFORE arbitrary later one-notary activation and every qualified ORIGINAL challenge must publicly recover the SAME precommitted safe cancellation signature. For FALSE instance and for arbitrary unauthorized hard-TRUE recovery/accepted native forgery, the FULL public view includes checking key, x, native VK, original source commitments, auxiliary input, malicious setup/source coins, sibling capsules and selective openings. Any arbitrary nonuniform QPT recovery (with coherent oracle access if a QROM is claimed) must imply an actual ORIGINAL witness or a separate PQ hash/native break; no volunteered trace or classical rewinding is permitted. A standard-model SHA theorem cannot be inferred from the synthetic SHA256 fixture.

**Missing construction equation:** publicly bind hidden output labels for the complete authenticated source verification, without either giving the attacker both labels (and occurrence mixing) or withholding a label required by ALL valid original witnesses. No source-secret-label compiler, correlated all-witness pad, joint simulator or QPT reduction is supplied. A smaller relation or more test counts are not substitutes.

No ordinary PR progress comment is warranted. Continue hash-only, source-specific release research; do not resume label/packing optimization or present this as a practical bridge solution.
