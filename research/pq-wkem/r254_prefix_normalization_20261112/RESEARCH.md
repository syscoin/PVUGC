# R254 — exact AuxPoW claim-prefix / tag-divergence normal form (SOURCE COMPONENT; NOT A WKEM)

**NONQUALIFYING AS CRYPTOGRAPHIC RELEASE.** This checkpoint proves a narrow deterministic source-conflict lemma for already-authenticated, relevant Syscoin histories and records executed synthetic SHA256d/ancestry regressions. It does not instantiate public Build/Open, Bitcoin active-chain membership, full Syscoin consensus or arbitrary-QPT key-recovery security.

## Continuity and original target

Repository syscoin/PVUGC, existing draft PR #1, branch research/pq-wkem-validation-20260918, starting HEAD 64d3f84013eface361821bf44f49eacbed429815 (R253; parent 61a4b0e1654e0bba265b46c68423771b59dbbffd). R253 note research/pq-wkem/r253_merkle_eval_20261112/RESEARCH.md, Git blob e4232628d23e4cd5d8cf6ffc3aacda5e13b7dd7f, read; R252 source kernel note also read. Latest substantive ordinary PR comment remained R225. User-supplied read-only Core #609 activated modern chain ID and exact canonical one-tag behavior inherited; no fresh Core tests or deployment check in this iteration. No web/external literature or other repository writes.

The scoped bridge uses ONE notary withdrawal initiation, ANY authenticated-source challenger, separately N-of-N preauthorization with honest erasure. x_W MUST bind exact claim/UTXO, recipient/amount/burn authorization, source slot and independently authenticated baseline, BTC anchor/window, challenge deadline/reset, final safe native cancel message/VK and capsule ID. No second notary approval, higher SYS cumulative work, winning-branch choice, or future-fork absence proof is required by the prefix-inconsistency branch. Bitcoin best-chain admission and source relevance remain necessary.

## Exact finite source predicate

Let claim reference height h_rel and baseline B_rel = authenticated child hash in x_W. For an independently admitted alternate source certificate w define:

 PREFIX_INC(x_W,w) = Admit_alt(x_W,w)
                     AND height(alt_head)>=h_rel
                     AND Hash(Ancestor(alt_head,h_rel)) != B_rel.

Admit_alt must check independently, not assume: BTC anchor/history membership, real parent work/difficulty, complete parent coinbase proof, AuxPoW chain-root/path/nonce/modern child ID, valid relevant interval tags and activated 41-byte canonical SYS output, fully contiguous child-header ancestry, source-slot relevance, finite time-window/deadline and reset rule. An authenticated parent is not automatically a valid Syscoin child, and a bad-tag witness must authenticate the parent/carrier independently before demonstrating that contextual tag validation fails. For a missing tag require the complete authenticated coinbase. A fabricated baseline must be rejected or independently refutable. This run DOES NOT IMPLEMENT complete Admit_alt; its proof begins AFTER that independent admission.

For a *tag-specific* conflict between separately authenticated heads n0,n1 let a=h_ref(n0) and b=h_ref(n1), where h_ref(n)=10*floor((n-6)/10). If a=b, compare the two exact ancestor hashes. If a>b, first authenticate the higher tag's branch down to height b using the actual contiguous predecessor path, then compare its ancestor hash at b to the other tag; symmetrically for b>a. This positive comparison cannot be replaced by absence from an incomplete list. Distinct Bitcoin parent certificates for one identical Syscoin child are not a fork. Multiple recognized SYS tag outputs and decoy-then-real encodings fail the activated #609 contextual rule, so they are not alternative valid tags.

## Lemma A — sharp canonical-tag maturity

Assume two complete authenticated child chains share all child headers through d-1 and first differ at height d, and SHA256d has not collided in the considered child ancestry. For two self-valid canonical tagged heads n0,n1>=d, a positive TAG_INC conflict occurs **iff**

    min(h_ref(n0),h_ref(n1)) >= d.

Proof: if the lower tag reference h_min<d, both histories share the header and hash at h_min. If h_min>=d, differing block hashes at d propagate through every child hash-linked descendant unless an actual hash collision/reconvergence occurs. A path from the higher tag's head/reference to h_min proves rather than assumes the common comparison height. Equal-height tags are the zero-path case.

The first tag able to reference divergence d occurs at

    n_min(d) = 10*ceil(d/10)+6.
    delta(d) = n_min(d)-d =
        6 if d mod 10 == 0; 16-(d mod 10) otherwise.

Thus the detection lag of this LOCAL TAG SUBCHECK is sharply 6..15 child heights. For d mod 10=1, 15; for d mod 10=0, 6. Both observation heads need their references >=d; having only one mature reference is insufficient. This is NOT a global fork-detection bound, actual source certificate length, Bitcoin-confirmation bound, or liveness promise. Mining, publication, BTC admission, withholding, censorship and challenge expiry still matter.

## Lemma B — one-sided fixed claim-prefix normalization

With an independently authenticated baseline B_rel already fixed in x_W, any separately admitted alternate chain that positively authenticates its ancestor at h_rel yields a claim-prefix inconsistency iff that ancestor hash differs from B_rel. If the first split d<=h_rel, it differs absent a hash collision; if the first split d>h_rel, that prefix is identical and must NOT trigger this *claim-prefix* veto. A later-fork policy, if wanted, is distinct. Because the baseline is fixed, no arbitrary pair-of-forks witness or all-source-signer coordination is required for the semantic comparison.

An authenticated alternate head may demonstrate its differing prefix at h_rel even before the particular local tag has advanced its rounded reference beyond d, provided the original bridge policy expressly accepts authenticated child ancestry as challenge evidence and all contextual tag validity checks for that head still pass. If the protocol specifies a tag-only inconsistency witness, Lemma A's 6..15 maturity requirement remains. Do not silently interchange these two predicate choices.

The comparison is exact for the finite *admitted* histories; this makes no claim about unseen forks or which SYS fork wins. A source must provide positive data at the relevant heights, not merely lack a record.

## Joint release/simulator checkpoint — still UNSOLVED

The common semantic event bit (PREFIX_INC=1) is publicly known in advance, so a proposed pad H(x_W || 1) can be computed by an arbitrary adversary without source evidence. A proposed pad H(SHA256d(parent_header(w))) varies across different legitimately qualifying parent headers, violating all-witness SAME cancellation capability. These were already counterchecked in R243/R252; R254 does not count them as progress. The exact missing equation remains honest classical-PPT Build_inc(x_W,sigma_cancel)->C and public Open_inc(C, original-full-w)->the SAME frozen safe sigma_cancel for EVERY original qualified witness in the BTC-more-work OR burn-fault OR SYS-inconsistency/tag-fault branches. Source validation only in honest software is bypassable. No issuer, future miner secret, private source-signer labels, publicly reconstructible pad, exponential witness table or online cancellation authority can be assumed.

Full-public FALSE security and hard-TRUE arbitrary-QPT final-key recovery/native forgery -> ACTUAL qualified ORIGINAL source evidence or independent PQ hash/native-signature break remain unproved; no extraction from a supplied adversarial representation/query log, no automatic classical rewinding lift. Malicious N-of-N setup, abort/useful completeness, sibling capsules, selective openings, source malice/availability and SHA oracle access need full security treatment. Native Bitcoin cancellation path is only an assumed endpoint, not verified P2MR/SLH deployment or on-chain VM/proof.

## Actually executed limited validation

Local Python standard library, SHA256d used on SYNTHETIC 80-byte child header encodings and exact 41-byte tag scripts, not real BTC/SYS consensus.

- checker.py SHA256 928588f76b32ea6dc250873231a964c1ced64011964f6ac3597d7ce9ed04c5a2 ran twice, identical JSON SHA256 629a976486f23878c291952ae8e9e90b80f62bae9128c1acffdb4036a7eaadfa: 984 sharp scheduler checks; 320 each prefix conflict, mature tag conflict, just-before-maturity nonconflict, unequal-reference conflict, post-claim excluded fork, same-child/multiple-parent semantic case, tampered ancestry reject; 1,280 exact-tag malformed-format rejections.
- exhaustive.py SHA256 5aaa1ba5f02367ba2416cf8eb844065d0d3387916acb465b66ffd182ee31f218 ran twice, identical JSON SHA256 95d84d747fc17b974ad1e394370030a7e8f42783b7b3f1fb0dfbf5af1a1b5e6c: 19,845 tag-reference pairs (5,415 positive; 14,430 negative), plus 945 before/after claim-height comparisons. These confirm only synthetic algebra and hash linkage, not source authentication or cryptographic hardness.
- Genuine local checkpoints SHA256 c2cc2a46ffa7d360a5e02d8088fa63585a933640e6f718042930b9f00b9e2cf5 and 4f9857e8fec76f01587644e4d08e57d6c5a82525f6a0edbf01bbc3833a2c8612. Complete expanded derivation, executable checkers and captured JSON are local in /mnt/data/r254_prefix_normalization_20261112/, bundled as R254_prefix_source_normalization_20261112.tar.gz. This published note is a separately authored concise version, not a claim that the entire local archive was uploaded.

No full original-source compiler, actual native PQ signature, QPT test or post-quantum release proof was performed. No ordinary PR comment or production change. The next *cryptographic* milestone is a compact source-dependent release representation whose raw public evaluation cannot be run using fabricated alternate histories while preserving identical hidden output for ALL qualified original futures; a witness-extraction proof must cover arbitrary QPT algorithms on the whole capsule.
