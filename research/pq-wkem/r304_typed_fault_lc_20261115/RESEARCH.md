# R304 — Same-wrapper LC-depth and tag-fault qualification are disjoint (RELATION CORRECTION; NO WKEM)

## Verified source and scope

Start syscoin/PVUGC draft PR #1 at \`18717cfba704fecbeb4fabf5092f0022a43acabd\`, branch \`research/pq-wkem-validation-20260918\`. Read R303 blob \`82b09827599c8378cf6d7425aed2ac2969dc6317\`, and the last substantive ordinary comment R225 #6796383617. Independently re-read syscoin/syscoin PR #609 head \`c91539de3c34937e57d7f5fda47c7b0502ff33f6\` source \`src/validation.cpp\` blob \`a33bb28089a5f5b8b4e68fbe78e17de6209d88de\`, specifically \`CheckContextualAuxPow\` and invocation sites. Source inspection, not a Core test run; the activated rules in code do not establish deployment.

The ORIGINAL relation remains the three OR challenge grounds: same-anchor higher exact cumulative BTC work, finite authenticated defect of this particular burn assertion, and qualified Syscoin inconsistency or relevant tag fault. Exact claim/UTXO/withdrawal/recipient, BTC anchor/window, source-reference height/actual ancestor at h_rel, LC depth, capsule/message/VK, deadline/reset, modern chain ID and the exact canonical 41-byte SYS OP_RETURN script remain bound. One notary initiates; anyone with qualifying evidence challenges; N-of-N is only preauthorization. R225's native signature portability requires a separately explicit slot-global veto or activation-bound native output.

## A distinct logical type error

Let \`omega\` be one **exact mutable AuxPoW parent wrapper** for a postactivation Nexus Syscoin child at height n. Define:

- \`Outer(omega)\`: independent authenticated BTC parent header, complete committed coinbase/Merkle data, work and relevant BTC source-anchor/window.
- \`TagOK(omega)\`: the expected unique canonical SYS tag and its correct ancestor height/hash for this contextual child; distinct from the child-chain merged-mining commitment.
- \`Admitted(omega)\`: the child with that exact wrapper passes the activated contextual checks, including modern nAuxpowChainId and TagOK.
- \`LC_k(omega)\`: that exact child-wrapper certificate participates in an admitted k-deep Syscoin history (k >= 1).
- \`TagFault(omega)\`: for otherwise in-scope outer evidence, the applicable tag predicate is false.

The inspected Core rule proves \`LC_k(omega) => Admitted(omega) => TagOK(omega)\`. Hence, independent of SHA hardness,

\[
LC_k(\omega)\;\land\;TagFault(\omega)=\bot\qquad (k\ge 1). \tag{1}
\]

This is not the already known error of using TagOK as a prerequisite to checking its negation. It additionally shows that **admitted LC depth on the same defective wrapper is impossible**. The same immutable child hash may have a *different valid parent certificate*. Transferring LC depth from \`omega_good\` to a faulty \`omega_bad\` solely because their child hashes agree is a false qualification. Multiple different Bitcoin parents for one child are not a Syscoin fork.

## Type-correct policy alternatives — no silent weakening

**A. Pinned asserted-carrier fault** (only if explicitly adopted as a fault maturity policy):

\[
R_{\rm assertedFault}(x,\omega)=
PinnedWrapper(x,\omega)\land Outer(\omega)
\land RelevantBTCAnchorWindow(x,\omega)
\land ApplicablePostactivation(n)
\land TagFault(\omega). \tag{2}
\]

Here the *claimed* exact wrapper is disproved. The outer BTC carrier must be independently authenticated, including full coinbase, actual source relevance, depth/window and best-chain or explicitly qualified source membership where required. A private mined orphan does not suffice. This does **not** pretend that a malformed child is an admitted LC chain. Refutation of a frozen invalid positive assertion can be rejected at activation before funding where possible. If the approved ORIGINAL fault relation mandates actual Syscoin LC depth through that same wrapper, (2) is a separate policy and cannot simply be substituted.

**B. Admitted Syscoin inconsistency** retains the actual k_LC checks on qualifying admitted histories and tests incompatible actual semantic ancestors at h_rel. Different rounded tag heights require predecessor links. It does not demand greater Syscoin work or selecting a winning branch. Never transfer admission between distinct parent wrappers.

Any future-fork policy requiring two later observations and the claim-prefix maturity qualifications of R176/R177/R195 remain unchanged. Missing/invalid burn proof still needs finite authentic refutation, not missing Merkle inclusion. Historical preactivation permissive parsing is separate.

## Actual release and joint-public attempt

Try to turn (2) into the missing source-dependent key using the simplest SHA-derived fixed source pad:

\[
K_{\rm fixed}=SHA256d(\text{"pad"}\,\|\,x.childHash\,\|\,x.BTCAnchor),\qquad
C=\sigma_{\rm cancel}\oplus K_{\rm fixed}.
\]

Classical Build and Open converge for **every** evidence certificate, but the complete public x computes K_fixed before any challenge. A classical adversary immediately extracts sigma on a FALSE claim; a QPT adversary can run the same attack, irrespective of the native VK or auxiliary data. A post-hoc check of (2) cannot restore secrecy.

Replacing K_fixed with SHA256d("pad"||wrapperID(omega)) is still publicly extractable for a pinned publicly asserted wrapper. Pretending that the source supplies a hidden *future* wrapper-ID pad makes a static ciphertext fail to converge across every qualified alternative. This also fails malicious-setup and sibling release obligations, and does not produce actual ORIGINAL Build_inc/Open_inc. The exact missing equation is a polynomial, noninteractive, hash-only, publicly executable release that accepts a fully authenticated ORIGINAL source witness, not a fabricated source input or reusable cut label, and returns the SAME frozen claim-safe native signature for every accepted witness without revealing it on FALSE or unauthorized hard-TRUE instances. A complete joint-public QPT reduction remains absent.

## Executed synthetic checker and limits

The Python 3 stdlib checker in the local R304 archive makes synthetic 80-byte SHA256d parent headers mined to a five-bit toy target, synthetic two-leaf Merkle commitments, fixture-designated anchored parent identities, modern/legacy modeled child IDs, and exact-length modeled SYS output scripts. 31 assertions in each of two byte-identical executions: valid modern good parent, another valid parent for same child, malformed trailing/duplicate/missing/wrong-ancestor tags, legacy-ID distinct from tag fault, no self-wrapper admitted LC for malformed cases, naive cross-wrapper false acceptance, exact-assertion/outer anchor/coinbase Merkle/deadline checks, and fixed-pad public recovery versus future-wrapper nonconvergence.

It is **NOT** a Core consensus validation or proof of BTC best-chain membership. The fixture does not implement real AuxPoW depth-5 chain-Merkle/index, full Bitcoin targets, full Syscoin LC forks, native SLH signatures, quantum computation, or a deployed network. The checker is an executable logical qualification control, not proof of a working release primitive. Two identical run outputs were SHA256 \`e45e8cb5dbbc5efaebacc2394f88a73c7ff9bfe4dfd1e48d93ba7c32d4e43f3e\`; checker SHA256 \`daec6edc71f843f490f49a0fb2b29a7c651a4a1b35efdfd093427991a50053bb\`. Local derivation/checker/provenance archive \`R304_typed_fault_lc_20261115.tar.gz\` SHA256 \`613f52f84d0d512eeb32d51afd1f5cb990fdab8d68e01b2186595d606ecdb5cf\`, not uploaded to this GitHub tree.

**Outcome:** A claim-relation maturity qualification must distinguish malformed asserted carrier from admitted LC conflicts. This is a source-soundness correction, **NOT** any ORIGINAL hash-only KEM source-release progress, full-public QPT security theorem or a deployment recommendation. Do not add a progress PR comment, notify as a WKEM breakthrough, modify production, or disable the research automation.