# R237 — direct branch ciphertexts and attempted PoW-prefix source pad

**NONQUALIFYING.** This is an independently checkable *conditional* hybrid/composition fact, plus a narrowly scoped rejected SOURCE-gate candidate. It is NOT a hash-only witness-KEM, full-public QPT proof, valid Bitcoin/Syscoin source compiler, native PQ signature test, or deployment proposal. No routine PR progress comment.

## Exact continuation and provenance

syscoin/PVUGC PR #1, \`research/pq-wkem-validation-20260918\`, observed starting commit \`7b065f8d0b91a4f457ac796f6f0b0c9699775f6d\` (R236, independent-branch key XOR wrapper). Read R236 RESEARCH.md at blob \`c529427f5cec89bbf0a3f4ccd5277fd9c8eccd4e\`, and the exact R235 source-pad convergence note. Most recent relevant PR comment was R225. No web or other repository write. Local CHECKPOINT_01 was written before executing any tests (SHA256 \`ca5588db0e544b406781b3d181f36bbf34a773c489524ea557f5f99f233f5764\`); CHECKPOINT_02 was written after the first checker but before the PoW range checker (SHA256 \`b6c348a7b2d077366b5670629278036277dc6d04616d81f1543e10812ece0848\`). Exact expanded local derivation is RESEARCH.md SHA256 \`42216bc8c2586cb650e498d902ef1c16e72674984c369f83295d9c0dabafe3d4\`, local-only archive file, not presumed available in another run.

## Direct OR composition attempt

The bridge has three **OR** conditions bound to the ORIGINAL claim, withdrawal slot, native cancel message/VK, and source anchors: (1) qualified BTC competing higher cumulative work, (2) finite authenticated burn authorization fault, (3) qualified Syscoin claim-prefix/tag inconsistency/fault. One notary may initiate; any source-qualified observer challenges; independent N-of-N setup parties preauthorize the fixed cancellation graph.

Unlike R236's public shared-S masks E_j=S XOR H(K_j), a direct construction would create three **independent** branch ciphertexts of the SAME frozen claim-scoped native cancellation signature sigma:

    C_j = Build_j(R_j,x_W,sigma; r_j)   j=1,2,3
    C = (x_W, native VK, checking data, source context, C_1,C_2,C_3)
    Open(C,j,w) = Open_j(C_j,w).

Every ORIGINAL valid branch-j witness must recover exactly sigma, with no other notary responding online. **No Build_j or PublicOpen_j on real source evidence was instantiated.** This formulation only replaces R236's mask correlation with independent direct ciphertexts; it does not provide a branch-gate construction.

### Exact conditional quantum IND hybrid

For two equal-length messages m0,m1, fixed challenge-bit-independent auxiliary z (including native VK and hash-check correlations), independent encryption coins, and arbitrary QPT distinguisher D, consider:

    H0=(Enc1(m0), Enc2(m0), Enc3(m0))
    H1=(Enc1(m1), Enc2(m0), Enc3(m0))
    H2=(Enc1(m1), Enc2(m1), Enc3(m0))
    H3=(Enc1(m1), Enc2(m1), Enc3(m1)).

A reduction distinguishing H_{j-1} vs H_j forwards a single branch-j IND challenge and generates all non-j ciphertexts with the **known** respective message and independent random coins. No quantum rewinding or random-oracle programming. If the *exact* full-public QPT IND assumption holds for each source-bound branch (with z, all source data, quantum-oracle access, and related/adversarial auxiliary information in its declared distribution), triangle inequality yields:

    Adv_joint(D) <= Adv_1 + Adv_2 + Adv_3.

This is proved for the stated encryption model; it does NOT establish ordinary-hash IND, hard-TRUE ORIGINAL witness extraction, native EUF, real source security, malicious N-of-N ceremony correctness, or selective-opening composition where single-branch assumptions lack the requisite joint auxiliary environment. A source witness that legitimately opens ANY branch is allowed to recover sigma. The hard-TRUE extraction property required by the project is **stronger than this IND hybrid** and remains unproved.

### Bounded reproduction (algebra only)

\`checker_min.py\` and \`captured_min.json\` were actually executed and read back twice with byte-identical output. The original larger local checker enumerated 4,096 three-pad tuples, proved message-independent distribution for 16 synthetic messages, and checked 196,608 same-message opens. It also checked an INVALID correlated-pad case where individual ciphertext marginals are uniform but the tuple reveals m through C1 XOR C2. The published smaller reproduction checks the same identities using 512 three-pad tuples, 8 messages, plus 255 toy PoW targets. This tests neither native signatures nor cryptographic leaf security. Local full-checker SHA256: \`d0f68b6589ff7e7bff4bb0b990f2ed001b77de3e49a9a9668e6eca1d0e1ce26e\`; captured SHA256 \`dfa3aa572d73b7ec10e6794def84edaae6a0cee29672c69eea3c0d7b49d4e74a\`. Published minimum checker is SHA256 \`0f6b6b7382a1303770569e34cd1b716204258b56a34abe1cf180344075eed65d\`; published minimum output SHA256 \`53c5dfdd6074c056451ba953427bccc7ae8f91c8a38895fbc63875b69fe647b2\`.

## Original-source leaf hypothesis: SHA256d PoW target-common pad

Could the SHA256d output of any genuine parent work certificate supply a **common hidden** pad because PoW requires y<=T? For an n-bit output range and 1<=T<2^n, the values **permitted solely by the numeric target** are 0,...,T, with exactly n-bitlength(T) shared leading zero bits, all computable from public T. Other bits can differ among permitted digests. Therefore a pad derived solely from those target-implied common prefix bits is **public before any source certificate**, while the varying suffix gives no guarantee that different valid work witnesses recover one common K. The exact 8-bit toy range arithmetic was checked for all 255 nonzero targets. It is **not** a statement that real SHA can attain every range value or that source anchoring follows from a target match. Binding the source to real BTC best chain, coinbase/AuxPoW, tag, window, actual work and SYS history is an entirely separate requirement.

The attempted secret-salt repair is not available to every permissionless source witness unless the salt is published (then the pad is public) or someone reveals it online (forbidden). A future miner-selected hidden value cannot simply be used to preseal a native signature at earlier N-of-N setup without an actual preauthorization compiler. This is only a failure of the precise target-prefix pad family, **not** a hash-only WE impossibility theorem.

Local SHA256 of the full range checker: \`18360df7ff14792168e19f26c96c849652443dfb52a54e91b36fb38bbbcefc5c\`; captured output: \`40db98758581325650e0b3670716d88f197f175d79ea162755e5ac739afc57d2\`.

## Remaining original-source equation

For at least one branch j, construct in classical PPT \`Build_j(R_original_j,x_W,sigma)\` and a public \`Open_j(C_j,w)\` returning the **same precommitted sigma for every ORIGINAL fully qualified witness**, including all source authentication INSIDE cryptographic release. For every arbitrary QPT recovery/native-forgery strategy on the full public joint view, extract ACTUAL ORIGINAL challenge evidence or independently justify a PQ hash/native break, without relying on a supplied representation or private issuer. Preserve one-honest N-of-N setup, manifest/graph/DA audit, later activation binding, sibling capsules, auxiliary-input/malicious source retention, source timing, ChainLocks optionality, and Bitcoin receiving only native cancellation signatures. **No such algorithm or simulator is implemented by R237.**

No lattice or unrelated website used. No routine success report warranted.
