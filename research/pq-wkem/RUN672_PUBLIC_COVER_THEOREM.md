# Run 672 — Public-cover search defeats nominally wide local release states

Live initial PR: syscoin/PVUGC#1, draft branch research/pq-wkem-validation-20260918, commit db8f192e0aa3cee1af3383a754d7fed030efdccf. Exact latest published proof: Run671 blob a9d9f7f9533b94889273d9434f45aacfb70f3233. Exact downstream source-binding dependency: Run259 blob c7f3b77f0273ca1cbe6f0b31c1a086b8eb3acbf2.

## Additional premise and theorem

Honest setup is classical PPT, knows the bound statement x and secret challenge credential K but no ORIGINAL witness, and publishes (P_x,pk_x). The classical public prefix evaluated on valid ORIGINAL witness w and evaluator tape r emits a c-bit witness-dependent cut state s_w(r). The public classical release suffix D(P_x,s,r) may return K. Public B_x(s,r) checks the recovered capability against the native branch verification key pk_x. The intended branch, relation, UTXO, anchors, window and context are bound in x.

New premise: there exists a public witness-INDEPENDENT classical PPT cover G(P_x,r,a), with a in {0,1}^h, such that for a fixed valid ORIGINAL w, with probability at least 1-eps over honest public r, the accepted state s_w(r) equals G(P_x,r,a) for some unknown seed a. The attacker does not know that a or w, but can enumerate/evaluate G on all seeds. G need not be injective and no common witness preimage is assumed.

Define A_r={a:B_x(G(P_x,r,a),r)=1} and nu=E_r|A_r|. Exactly

Pr_{a,r}[B_x(G(P_x,r,a),r)=1]=nu/2^h, with nu>=1-eps.

Proof: for each fixed tape r precisely |A_r| of 2^h seeds pass the public checker. Average over r. The covered honest state supplies at least one passing seed on each good tape. No independence of prefix, suffix, or tapes is needed.

A classical public attacker finds the bearer credential in expected 2^h/nu public tests. Any QPT attacker can implement the public classical G -> D -> native checker predicate reversibly and amplitude-amplify over (a,r), obtaining O(sqrt(2^h/nu)) coherent evaluations plus polynomial circuit overhead. No QROM, rewinding, generic-group or obfuscation assumption is invoked. To rule out THIS generic quantum search at the 2^128-query level it is necessary (not sufficient) that h-log2(nu)>=256, up to polynomial factors. State width c does not replace h. Correlation between source and suffix tapes is explicitly retained.

For a QPT-secure one-way permutation f and true-instance relation R_f(y,w)=[f(w)=y], if setup knows y without w, h=O(log lambda), coverage is nonnegligible, and accepted-credential -> ORIGINAL-witness extraction were a QPT reduction to an independently hard problem, public enumeration would contradict those assumptions. This is a conditional HARD-TRUE extraction barrier, not false-instance secrecy.

## Executed finite test

A separate exact published checker expands five public seed bits to 24, 192, and 384 state bits with SHAKE256, then applies an optional public reversible tape-dependent frame. Three genuine witness labels give distinct accepted states per good tape, returning one same toy credential. The public seed/tape domain has 512 pairs and 36 accepted pairs: exact probability 9/128, classical mean 128/9, quantum query scale sqrt(128/9). Physical state-width padding does not alter the search mass. Five explicitly simulated Grover rounds matched their analytical probabilities. Published exact checker passed 3,137 assertions and py_compile; repeated output was byte-identical. SHAKE is only deterministic expansion in a TOY model; toy release explicitly contains K and is NOT secure encryption or a crypto benchmark. Extended local checker separately passed 3,905 assertions and includes context separation, a non-cover negative control, and a second gauge mode.

## Scope and attack checklist

Public-evaluation/chosen-input and coherent quantum search: directly attacked. Public gauge permutations can be absorbed into G and do not change the cover size. Local seam, tensor fingerprints, secret frame recovery, malicious setup, other capsules, replay and key-correlation attacks are NOT resolved by this result. Public native credential checking is part of the adversary view. Single-capsule honest-setup attack suffices under the stated cover premise. A witness-dependent nonseparable state for which NO small public witness-independent cover exists is outside the theorem. It does not assert a break of a concrete published PVUGC release or of RIO.

Run259 only says a supplied complete residual-accepted SOURCE representation yields an ORIGINAL witness, unconditionally under its statistical setup or conditionally under its specified QPT-SIS reduction. A cut state and bearer credential do NOT imply such a SOURCE representation. The missing upstream arrow remains UNPROVED, as do full-public-output false-instance QPT hiding, malicious/abort-secure N-of-N, related capsules, concrete 128-bit resources and conditional P2MR/SLH endpoint.

Literature checked at publication/abstract level (NOT a full proof audit): Canetti–Chamon–Mucciolo–Ruckenstein, TCC 2024 / ePrint 2024/006, https://eprint.iacr.org/2024/006 ; quantum local-mixing discussion, arXiv:2609.40289, https://arxiv.org/abs/2609.40289 . Neither supplies an independently justified concrete PQ release primitive here.

Result: conditional public-cover falsifier, NOT practical PQ witness-KEM. Production unchanged; PR stays draft/unmerged.
