# R167 — Nonlinear prefix-hash witness release, safe-cylinder repair, and builder-query extraction

**Research only, no secure or practical generic witness-KEM, no original source compiler or QPT proof.** No lattice, group-based primitive, online authority, browser literature, production change or independent agent. This is one bounded construction-and-repair iteration, not a claimed breakthrough.

## Continuity

syscoin/PVUGC PR #1 (draft/open), branch research/pq-wkem-validation-20260918, observed start SHA 8298b7ee797f57f3943b89c0bca1b9c36a71e334. Read only the current immediate predecessor hash_opaque_correction_span_20261109/RESEARCH.md (Git blob 6fcaa51a5e9cab71d933660d2c5df2210fa97e27) and the recent top-level comment window, which was empty. The predecessor's public-incidence XOR-affine attack is acknowledged; this candidate is specifically nonlinear. An actual intermediate checkpoint was committed at c6d21f788981df54296b308b34350060ffdc2f8f, exact file blob d9febdd65913a0ba1cffd7cdcc95a452be6a7638.

## Candidate: public-root nonlinear prefix-hash leaf dictionary

Take a fixed-length l-bit ORIGINAL NP witness w and explicit R_original(x,w), with context c binding relation identity, exact claim/UTXO, intended branch, window/anchors and native verification key/signing message. Use independent ideal H_root, B, T, P, C, Sig with length-delimited domain separation. Let L_empty=H_root(c) and L_(p||b)=B(c,L_p,b). Let Tag_w=T(c,l,L_w), and Pad_w=P(c,w,L_w) of kappa bits. Every valid w may have a different leaf L_w; they need not share a canonical source or common prefix.

Reference Build selects uniform K, freezes intended native signature sigma, publishes CK=C(c,K), Dsig=sigma XOR Sig(c,K), and for **every** valid ORIGINAL w publishes the record

    (Tag_w, E_w = K XOR Pad_w).

Open verifies the full ORIGINAL certificate off-chain, derives its full prefix path, finds its tag, calculates K=E_w XOR Pad_w, checks CK, unmasks sigma, and checks the native VK/message. If x is FALSE, the dictionary is empty. Every legitimate ORIGINAL witness recovers the SAME frozen capability. This is a concrete deterministic public opening but its builder **enumerates 2^l witnesses**: no practical/generic-PPT Build exists here. No additional on-chain verifier is posited.

The actually executed toy checker uses P(c,L_w) rather than the proof-safer w-bound P(c,w,L_w). This difference matters to quantum extraction: a QPT query to the label-only P reveals a hash label, not an ORIGINAL witness, on measurement. The w-bound formula is a specified repair, **not** code that was executed and **not** an efficient compiler.

## Exact new classical-builder query-transcript lemma for this class

Fix independent random-oracle B and T with t-bit state/tag outputs, classical Build making at most Q oracle queries and emitting at most m explicit tag records. Its auxiliary advice must be independent of the fresh random oracles and root, and it must not receive a satisfying witness. Let eps be the probability that at least one emitted tag equals Tag_w for some w in S_x={w:R_original(x,w)=1}. An extractor runs Build with classical instrumented B/T oracles, reconstructs all complete root-to-length-l paths present in its branch-query DAG, and tests R_original(x,w) on these paths.

Except for lazy-sampling events (tree-state collision, accidental hit of a leaf label by a guessed state, or directly guessed leaf tag), Build can emit an accepted leaf tag only after computing and querying its full public B path from root. Thus

    Pr[extract some actual ORIGINAL w] >= eps - O((Q+m+2^l)^2 / 2^t).

Set t >= 2l + kappa + 2log2(Q+m+2) + a modest constant for a negligible bound in the ideal model. The extractor is classical and polynomial in l,Q,m, because it traverses only Build's queried edges; it never enumerates all possible full witnesses. This is a **restricted black-box lower bound for explicitly recorded nonlinear public-root leaf-tag dictionaries**: to be useful on hard-TRUE hash-preimage instances, their classical Build must itself generate an ORIGINAL preimage. It is NOT a lower bound for arbitrary hash-only WE, implicit encrypted circuits, hidden-key conditional evaluators, quantum builders, other crypto assumptions, or QPT final-key attackers.

A full joint simulator (CK, VK, Dsig, Aux, related capsules, selective openings, malicious setup and arbitrary quantum coherence) has not been established. No appeal to a classical trace can substitute for extraction from a quantum adversary.

## Constructive local repair: sound accepting prefix cylinders

A prefix p is sound iff every remaining completion u gives R_original(x,p||u)=1. Build can publish one nonlinear pad/tag correction on the B-label at each selected sound prefix, provided those cylinders cover all S_x. Open walks its own prefix path and retrieves the first matching correction. Every valid w obtains the same K; an invalid w cannot reach any sound prefix without a tag collision. This **does** build a fully correct, compact release for special relations like first-bit=1: one row replaces 2^(l-1) leaf rows. No post-hoc verifier is needed to protect the raw pad in this simple subclass.

But any sound prefix itself gives an actual ORIGINAL witness by extending it with zeros. A polynomial builder discovering such a useful prefix already solves the hard-TRUE witness search. Soundness is a universal condition on the suffix, not an assumed cheap oracle. On a planted hash-preimage relation, the observed sound prefixes were full-length witness leaves. This repair therefore does not compile generic NP or solve the source-authentication requirement.

OutcomeID of a Syscoin child cannot be used as a sound prefix of a complete work/chain proof: multiple valid parent-work certificates for the same child are not incompatible forks, and fake work or missing canonicality/ancestor/tag evidence remains invalid. Our toy source predicate is not Bitcoin best-chain authentication.

## Executed local checks, accurately scoped

Full executed standard-library source checker.py (SHA256 = deterministic toy backend, NOT an ideal-oracle proof) ran with 4,528 assertions. For SAT first-bit-fixed l=4/6/8/10/12, the full nonlinear reference published respectively 8/32/128/512/2,048 leaf corrections and all satisfying w recovered the same chosen 32-byte K. The explicit FALSE contradiction rejected 512/512 invalid witness strings. The synthetic parent-work source had 999 accepted toy parent nonces for one child and 64 wrong-anchor contexts failed raw opening. It does **not** check real AuxPoW, authenticated best-chain membership, Bitcoin consensus, or source timing.

For 96 planted toy preimage relations (12-bit w and 16-bit y), a witness-free blind Build tried 256 candidate witnesses per fixture. Six produced at least one valid tag; the extractor reconstructed genuine accepted witnesses **from Build's classical branch-hash query DAG only** in all six. Ninety partial capsules were incomplete. This is finite evidence for the exact class, not quantum hardness.

A second actually executed safe_prefix_repair.py ran 13,764 assertions. It reduced first-bit-fixed 8/128/2048 accepted witness leaves to one sound-prefix row at l=4/8/12; a first-two-fixed predicate with 1024 valid leaves likewise used one row; FALSE used zero. The synthetic parent PoW predicate had 999 accepted toy leaves and 869 sound-prefix rows. All 24 toy hash-preimage fixtures needed depth-12 full leaves for their sound prefixes. This is a successful **restricted repair** but does not meet the generic hard-TRUE criterion.

Local-only full sources and exact captured outputs (not falsely marked as GitHub-published) have SHA256:

    checker.py             1122bf28586fd3c14ac8fcaeab901c3d7ff2567ffbab3a5737c93eb6494d8692
    captured.json          0f13707b44ad5e75d2616a8d2688bfddda3cfc2b848f0b3a884addf7bc870146
    safe_prefix_repair.py  2ab0840113837dc46ff785ba77254a4a1fa1c19b4fcef0dbe10c6b74f01748f5
    repair_captured.json   ad81c73b53385a12bae3529f7f4039fb98bccc5bd42d543e943df186bafca187

A much smaller **independently executed** mini_checker.py and its exact mini_captured.json are included in this GitHub research directory; Git blobs match local git-hash-object checks (mini source e7ef5ae00c389115d0dfa73c44bd698a952a58b1; mini output c1cc809d33c860a3b2d46be03499038e6834fd4b). It checks 128 correct nonlinear leaf openings, one sound-prefix row, and 10/10 successful classical query-trace witness extractions over 64 toy hard-TRUE fixtures. No independent security verifier was invoked.

## Unsolved, first-priority construction step

Find a classically PPT, hash-only, non-affine **source-dependent** public correlation compiler for arbitrary ORIGINAL R,x and frozen sigma that does **not** enumerate actual witnesses, reveal K through public circuit constants or local branch-label mixing, rely on future-work hash entropy without a precommitted pad, or assume a hidden online issuer. PublicDerive/Open must recover the SAME sigma from every original authenticated Syscoin/AuxPoW source w, including full claim, child, parent coinbase/work, height/ancestor/window/lag/interval and canonicality data, with OutcomeID distinct from WorkID. An arbitrary QPT final-key recovery/native forgery must yield an ACTUAL original witness or independently justified PQ hash break in the full joint public view. Malicious N-of-N graph/erasure, pre-funding DA, finite observation and conditional native PQ endpoint remain open. Do not optimize the old source table or call this a breakthrough.

No ordinary PR progress comment is warranted, and the recurring research task is not completed.
