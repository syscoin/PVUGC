# OR-proof witness-switch release trial — 2026-11-25 UTC (nonqualifying)

## Continuity and selection

Actual syscoin/PVUGC PR #1 is open, draft, unmerged, head repository syscoin/PVUGC, branch research/pq-wkem-validation-20260918, starting head e8ec251a9b2f2a85f7e311051f4d17b1dcbf6094. Read metadata and recent substantive issue comments (through R225), exact head commit file metadata, and SOURCE_WHOLE_CAPABILITY_LIST_INTERSECTION_20261125.md at that head (blob 80158dd082a9998aa125d96f5e80864342274029). No whole PR diff, external research or new Core source claim. New path checked absent (404); head rechecked unchanged.

Missing operation: use any original certificate to recover one fixed cancellation signature from serialized hash-only setup, with authentication inside recovery rather than an honest-code check. Closest existing attack is R289's incompatible local-label splice, and the latest whole-capability list trial fails to generate a hidden label intersection.

Mathematical change tested here: **witness substitution in a single binding proof commitment**, rather than compiling local authenticated labels, low-degree masked coefficients, or a list of keys. Build knows an endpoint witness, so it can genuinely prove an OR relation without knowing any future source witness. Open would substitute the other witness into a fixed commitment transcript. If it could do so while retaining a common hidden view, that view could key one whole-capability ciphertext. There are no exposed independently composable gate labels and no combinatorial list-overlap claim. The proof transcript must actually support witness substitution; ordinary witness indistinguishability cannot be assumed to imply it.

## Explicit trial and attempted repair

Let x be the unchanged fully bound original statement (three independently sufficient OR grounds, actual authenticated histories, relevance, maturity and burn typing). R_x(w) is the complete original relation. Let S be the fixed native cancellation signature, V_x(s) the public native checking predicate for the frozen message and key, and ctx the complete capsule/protocol context. For this attempted compiler only, form the auxiliary Boolean relation

    F_x(w,s) = R_x(w) OR V_x(s).

The V_x branch is a setup-side proof witness, NOT a qualifying original challenge. In particular an independent accepted signature is not permission to release the bridge capability. This distinction is essential when formulating security.

Use a hash-commitment MPC-in-the-head proof shape, with a fixed polynomial-size Boolean verifier circuit and three XOR-shared private input vectors. This does not assume a new primitive beyond the proposed proof transcript; even grant perfect correctness of the underlying private computation. Write the complete padded witness pair as u=(w,s), and choose independent uniform shares a,b of the same length, with c=u xor a xor b. Parties compute F_x(u), yielding output bit shares o_a,o_b,o_c whose XOR is F_x(u). Let T_i be each party's full view including its input share and messages, and h_i=H(ctx,i,r_i,T_i) be independently salted binding commitments (unambiguous encoding). Public proof verification uses the commitments, challenge, and opened views as usual; no proof theorem is needed for the following input-share calculation.

Candidate Build:
1. Use u_0=(w_0,S), with arbitrary padded dummy w_0, so F_x(u_0)=1. Choose shares and compute the views.
2. Fix two opened views T_a,T_b and their salts, commit to all three, and retain the hidden view T_c and salt r_c. Publish E=S xor KDF(ctx,r_c,T_c,|S|) together with the transcript, then erase.
3. The proposed public Open would use any real w with R_x(w)=1 to substitute u_1=(w,s_1), where s_1 is a dummy value chosen without knowing S. It must recreate the hidden view key without exposing S or learning an independent witness to V_x.

This is a concrete serialized Build trial; the missing Open is screened below instead of calling an ideal view-repair evaluator. Setup-only dummy w_0 does not stand in for original evidence. If multiple MPC repetitions are needed for proof soundness, one cannot assume their hidden views are already jointly accessible.

With the two opened input shares fixed, the new hidden input share is forced:

    c_1 = u_1 xor a xor b
        = c_0 xor (w xor w_0, s_1 xor S).

Thus for any actual source substitution with w != w_0, c_1 != c_0, regardless of how the opener chooses s_1. Even grant that it can construct all hidden messages and salts consistently with the two public views, which in an actual MPC transcript need not be possible. Since the full view includes c, T_c' differs from T_c. A valid opening of the SAME h_c under the substituted view would give a distinct preimage of the original commitment. In the collision-resistant commitment model this is not an honest completeness mechanism. Fresh h_c' changes the capsule; it does not recover its original pad. A random-oracle KDF on the fresh distinct view has no enforced equality with the original pad. This is a failure even before asking for arbitrary QPT security. We do not assert that a SHA collision is produced by a real original challenge.

**Repair attempt: change the key-bearing committed object to a witness-invariant semantic output, not a full hidden input view.** Commit only to the hidden output share o_c and use that value as key material; allow Open to re-share and replace private input views without opening the original commitment. If both opened output shares are retained, every accepting computation has exactly

    o_c = 1 xor o_a xor o_b.

This supplies the requested equality across witness substitutions, but it also supplies the hidden output share directly from public data, on a FALSE original instance as well as TRUE: Build's auxiliary V_x(S) branch always accepts. The same equation holds for a vector of public invariant outputs. If the salt is published, anyone derives the key; if it is withheld, a qualifying witness has no specified method to recover it. In particular it cannot be recovered merely by evaluating the auxiliary OR relation. An unsalted one-bit commitment can also be checked by enumeration. Repetitions with public opened output shares give the same public reconstruction componentwise.

A more general projected-view variant would need a function J with J(T_c')=J(T_c) for every substituted original witness, yet with J(T_c) hidden in the entire public transcript. Merely retaining a private signature coordinate fails: the hidden signature share is S xor a_s xor b_s, and substituting s_1 without S changes it. Merely retaining an input-independent accepting output fails by the reconstruction above. Introducing a secret extra output whose value is S does not repair the circuit: evaluating that extra output from the other witness would already implement the missing original-dependent release. A secret salt, equivocation trapdoor, or private view transformation must be actually generated and publicly computable from original evidence before it is a candidate solution.

The special-soundness variant does not remove this obligation. Two challenges on a fixed OR-proof first message normally establish knowledge of *some* witness to the OR, not necessarily S. A source opener already knows one such witness. To target S, one would need two valid responses to different challenges in the specific signature branch with the same first message; a fresh source proof does not supply those responses. Ordinary proof simulation may choose its own first message and cannot be used to equivocate an already published binding commitment. No extractor is handed a rewound adversary or private state here.

## Scope and handoff

This attempted proof-native release deliberately differs from local-token, affine-evaluator and whole-list approaches. It rejected the fixed-view and public-output repair at the exact point where the original-dependent operation is required. It does not imply that all hash-only proof constructions fail, nor that a proof-system indistinguishability theorem is false. Witness indistinguishability compares distributions of independently generated proofs; it does not guarantee that a prover holding a different witness can recreate a hidden value conditioned on one realized proof. No new security theorem about general WE, concrete SHA, QROM, or MPC is claimed.

A next proof-native attempt must first exhibit a noninteractive hash-only *witness-switchable hidden correlation* in an actual serialized Build: a complete source certificate must enable the appropriate transformation without requiring either the erased endpoint witness or a commitment collision. It must show the full-public simulator including the original statement, native key/message, auxiliary input, malicious source retention and related capsules. Do not rerun this trial with more proof repetitions, another salt, another sharing field, another MPC backend, or a proof-system name substituted for the missing switch. No existing source or endpoint requirement has been changed. In particular R316 remains coverage-only; R225 activation binding remains necessary. No code execution, native signatures, source verifier execution, qualifying Build/Open or arbitrary-QPT recovery/forgery reduction. Static mathematical screening only. No ordinary PR comment or notification.
