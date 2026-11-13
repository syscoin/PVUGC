# HPW-R167 intermediate: public prefix-hash witness label compiler

Status: construction attempt, not a generic polynomial witness-KEM, no QPT proof, no practical security claim. No lattice, discrete logarithm, external literature or online release authority.

Observed current PR #1 draft/open HEAD 8298b7ee797f57f3943b89c0bca1b9c36a71e334, branch research/pq-wkem-validation-20260918. Exact predecessor `hash_opaque_correction_span_20261109/RESEARCH.md` was read (blob 6fcaa51a5e9cab71d933660d2c5df2210fa97e27); its public-incidence XOR-affine correction failure is not repeated here. Latest ordinary comments since 2026-11-09T01:45Z were empty.

## A specifically nonlinear candidate

For l-bit ORIGINAL witnesses, let L_empty be a publicly known random root, and L_{pb}=H_branch(context,L_p,b), where H_branch is independently domain-separated, injectively encoded and modeled as a random oracle. The terminal tag T_w=H_tag(context,L_w) and pad P_w=H_pad(context,L_w) are nonlinear functions of the complete witness prefix path. Honest Build chooses a fresh precommitted K, frozen native sigma, and *currently* publishes a tagged correction for each accepted ORIGINAL witness w: (T_w, E_w=K xor P_w). It publishes CK=H_check(context,K), D_sigma=sigma xor H_release(context,K), the full source relation, claim, branch, anchors/window, VK and M. Public Open with a full accepted ORIGINAL w follows its prefix path, finds its correction tag and reconstructs exactly K and sigma, with native signature verification. Full witness tag and context are used rather than only semantic child OutcomeID. This is an exponential reference, not an implemented PPT Build.

## Exact unfinished question

Can a classical-PPT public compiler create corrections that cover every ORIGINAL-valid future witness without computing accepting leaf paths, an online releaser, or executable hidden-seed conditional evaluation? A black-box tag dictionary cannot trivially do so. For a planted hard TRUE hash-preimage relation, any builder producing at least one real leaf tag may reveal that witness through the builder's **classical random-oracle branch-query transcript**. This is to be formalized and adversarially tested. Guessing tags, hash collisions, arbitrary correlated advice, quantum *builder* queries, and hidden state merges require explicit treatment. The proposed theorem would be restricted to this public-prefix/leaf-dictionary normal form, never a no-go for hash-only witness encryption.

## Tests pending, no false execution claims

Test witness table correctness on TRUE/FALSE formulas, different valid witnesses sharing frozen K, invalid certificate with same child and wrong work/anchor; measure witness-to-leaf correction counts. Implement instrumented classical oracle queries for a blind hard-TRUE preimage builder, extract actual ORIGINAL w from branch query paths, and state conditional collision probability. Test fake source and source-ID separation only in a clearly labeled synthetic fixture, not Bitcoin canonicality. Preserve exact code and captured output in subsequent checkpoint. No results are asserted at this stage.
