# Run 516 — Immutable claim-sector guards: exact shared-frame hiding and sector-switch break

Research only; draft syscoin/PVUGC#1 branch research/pq-wkem-validation-20260918, independently verified starting SHA 2dfbf5e537b11fc6ae60df0e599b31b390d92c3f. This is an ideal, exponential-size interface result, NOT a practical PQ witness-KEM or a PQ-secure local mixer.

## Construction and exact positive result

Let S={0,1}^h x C x {0,1}^n x {0,1} with semantic coordinates (k,d,z,t) and injective full-context claim ID d. Context must bind relation/UTXO/claim/branch/anchors/window. One uniformly random hidden permutation P covers every claim. Public Run-506 witness loaders L preserve both k and d, and per-claim terminal G_{c,i} changes only t by [d=c] AND k_i AND f_c(z), where f_c is the genuine ORIGINAL predicate (or a COMPLETE Run-259 accepted-representation predicate within that theorem's actual scope). Publish conjugated actions P L P^-1 and P G_{c,i} P^-1, together with a_c=P(K_c,c,0^n,0). No public action may change d.

For any valid witness z of claim c, a loader reaches P(K_c,c,z,0), and fixed-point tests of the h guarded actions yield the SAME K_c for every such z. Witness states remain distinct; at most 2n+h public action calls, ignoring exponential interface representation cost.

For a false target x with f_x identically zero, fix arbitrarily many other public claims, witnesses, seeds, and whole action tables. For any K0,K1 set Delta=K0 XOR K1. The permutation T_{x,Delta} translates only the k coordinate in the x claim sector, leaving all other sectors untouched. It commutes with all witness loaders, all other-claim terminal actions (disjoint supports), and the false target's identity actions. Consequently replacing P by P'=P composed with T_{x,Delta} preserves EVERY complete public action table and all other claim anchors, and maps a target anchor for K1 to the old anchor for K0. Uniform P is invariant under this bijection. Thus full ideal mixed-action views conditional on any K0 or K1 are IDENTICALLY DISTRIBUTED even with multiple true-reference capsules.

This is information-theoretic equality, available even to unbounded coherent quantum querying of the specified public functions. It DOES NOT swap independent native verification keys VK(K0)/VK(K1), prove native VK QPT seed hiding, or handle P-dependent auxiliary state. In the full external-key experiment the claim is only zero INCREMENTAL leakage from the ideal mixed-action view, conditional on independent checking-key data.

## Exact negative result

If a public action V=P S_{x,r} P^-1 swaps claim sector x with a reference sector r but preserves k,z,t, a known-valid witness z_star for r yields K_x directly: compute V(a_x), load z_star, and read each bit as [A_{r,i}(y)!=y]. This works for every P, without target evidence. If the reference action omits the semantic guard [d=r], the attack works even without V. Context aliases/collisions have the same problem. A mere external textual claim label, an exposed generic reversible state editor, or a white-box compiler allowing synthesis of V does NOT meet the positive theorem's no-sector-switch interface premise. The attack is classical and thus QPT.

## Relation to prior barriers / exact scope

Run 511's false-target transplant assumes an action from another claim can operate on the target semantic sector. Runs 512–513 use secret independent masks instead; this run uses a block-diagonal action-domain invariant, not a mask. Runs 514–515 distinguish PRP camouflage from true secret hiding: involution and fixed-point fingerprints remain visible here, but by themselves do not disclose the false target seed. RIO random-circuit pseudorandomness does NOT imply this interface can be realized efficiently or securely.

Attack taxonomy: (1) cross-claim seam blocked only by actual semantic guard, (2) hidden gauge proof by sector-local translation, (3) statistical action fingerprints persist, (4) arbitrarily many reference public views allowed in the ideal theorem, (5) one chosen-input public sector switch causes full key recovery, (6) retained P/seed randomness and malicious construction outside guarantee, (7) context collisions or branch aliasing break isolation, (8) native checking-key correlations separately unproved, (9) ideal whole-view identity survives coherent quantum postprocessing but no distinct quantum attack or white-box QPT reduction is claimed.

## Reproducibility and limitations

The EXACT committed JavaScript checker was evaluated before publication; it exhaustively checks all 40,320 S8 frames, 80,640 switch recovery tests, 384 deterministic S16 frames with witness loading and 768 missing-guard controls, and 256 S16 frames with two simultaneous true references. Captured output is committed separately. An independent standard-library Python checker, extended proof and integrity manifest are preserved in a separate local checkpoint.

An ideal P acts on 2^(h+ell+n+1) states and is exponential to represent. Moreover each protected terminal still includes f_c, potentially the whole ORIGINAL verifier. Classical-PPT setup/evaluation, minimizing the protected frontier, full-white-box false-instance QPT security, arbitrary early native authorization -> ORIGINAL extraction, malicious N-of-N setup/abort/erasure, related-capsule composition, concrete 128-bit resources, and the conditional native-PQ Bitcoin endpoint remain UNPROVED. Run 259 binds only accepted COMPLETE representations; Run 509 needs an ideal simulator-held inverse frame; Run 508 requires excluding independently pre-signed bypass edges. No new WE/iO/RIO-equivalent hardness assumption is introduced. No new complete external-paper proof was audited. Production unchanged, PR draft/unmerged; stopping condition unmet.

**Next task:** instantiate or falsify a compact public block-diagonal terminal including all inspectable gate/program interfaces; test synthesized sector changes, actual verifier cost, and arbitrary-QPT signing extraction before any security claim.
