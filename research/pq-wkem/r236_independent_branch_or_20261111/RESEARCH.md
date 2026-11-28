# R236 — independent-branch OR combiner; joint correlation still unproved

**Classification: NONQUALIFYING research-only. Not a hash-only witness-KEM, not a source-dependent Build/Open, not a QPT security proof, and not a deployment proposal.** No PR progress comment warranted.

## Continuity and actual execution
On syscoin/PVUGC draft PR #1, research/pq-wkem-validation-20260918, observed starting SHA fa524a37c842b8caff7db2df531612a94fc012fc (R235). Read current R235 RESEARCH.md and the latest substantive PR comment (R225). Genuine pre-test checkpoint written locally. Full local checker source SHA256 9a3236a04463a0c1186ec1c3aee3b6072b9e36c5a9e9dab34242d91695c99587; captured output SHA256 88f3b12c2d61f72166b89fe1d0d8025446092407b4ac98775967e18e9eaee375; two byte-identical runs. The smaller published checker_min.py was also actually executed twice identically; it implements the same core algebra and an adversarial partial-key leak fixture. Source SHA256 6e928e138a9abde3072b87d6c2e91efdc8bf508a89b7216ffef0c3a85364ef30; result SHA256 30a5d1f66d66ca45e1945fcb9f15ccc8052b16f7b6d113f79e795a7611e7de58. No external web/literature, other-repository write, independent agent, production consensus validation, native signature or quantum attack was executed.

## Exact attempted construction

Bind x to claim/UTXO, exact activation evidence and Bitcoin source anchor, relevant burn and Syscoin root, windows and fork-depth, native cancel message and verification key, and the capsule identity. R1 is a qualified contradictory *higher cumulative BTC work* challenge, R2 a finite authenticated *burn authorization fault*, and R3 a qualified authenticated *Syscoin prefix/ tag inconsistency or explicit tag fault*. Source authentication must be ORIGINAL, not an unconstrained Boolean.

Take independent uniformly sampled 256-bit branch secrets K_1,K_2,K_3, independent S in {0,1}^256 and a precommitted claim/path-scoped native cancellation signature sigma. **Uninstantiated** source-dependent branch gate C_j=Build_j(R_j,x,K_j) would have to recover K_j from *every* qualifying ORIGINAL branch-j witness and remain secure against arbitrary QPT adversaries on the full public view. This is the missing primitive.

Publish for each j in {1,2,3}:
    E_j = S XOR H_branch(x,j,K_j)
and jointly publish:
    D = sigma XOR XOF_cancel(x,S,len(sigma))
    CK = H_check(x,S).

The (still hypothetical) genuine branch-j Open_j(C_j,w)=K_j allows S=E_j XOR H_branch(x,j,K_j), check CK, then recover sigma=D XOR XOF_cancel(x,S,len(sigma)) and verify the exact native challenge authorization. **Correctness identity:** every branch and every witness yielding its installed K_j recovers the very SAME precommitted S and sigma. This is proved by cancellation of XORs, not by a hardness assumption. There is no required canonical witness or common short preimage. For N-of-N preauthorization, repeat under each participant's independent pre-signed cancel contribution; one valid ORIGINAL challenge must release every contribution. The graph must rule out bypass paths and be fully auditable before irreversible funding.

## Full-public simulator and correlation caveat

Public view includes x, all C_j, E_j, D, CK, native VK, source roots and BTC context, related capsules and auxiliary inputs. Even if each C_j individually conceals K_j, publication of E_1,E_2,E_3 sharing S can permit a JOINT attack. A sufficient but unproved hybrid premise would require quantum-safe pseudorandomness of EACH H_branch(x,j,K_j) in the joint correlated public view; replacing these with independent uniform masks would make E_j independent of S. Protection of D and CK conditioned on native VK and quantum random-oracle access would STILL require additional reduction; the premise is NOT automatically implied by SHA one-wayness or marginal branch secrecy. It is not a disguised established QROM theorem. A source-to-K_j ORIGINAL gate, its exact QPT joint simulator and any-original-witness hard-TRUE recovery-to-ORIGINAL extraction remain entirely unconstructed.

## Concrete correlated-leak counterexample

An intentionally INSECURE 8-bit toy capsule reveals each K_j's high 8-t bits, leaving 2^t candidate keys. With E_j=S XOR SHA256(K_j)[0], enumerate candidate S sets and intersect the three; published CK would validate candidates. In 150 fixed-seed trials per t, the **unique** S counts were: t=2: 149; t=3:150; t=4:143; t=5:91. No ORIGINAL witness was supplied. These are classical toy-enumeration facts and establish NO complexity claim at 256 bits, no security theorem and no QPT break. Simple public E_j=S XOR K_j directly reveals every S bit whose corresponding K_j bit leaks; hashing removes that explicit linear equation, not the need for a full-public joint argument.

The minimal reproducible checker here reports 240 exact same-signature algebra identities and unique S in 96 of 100 partial-leak toy trials. All released branch keys in these tests are SYNTHETIC fixtures, never outputs from authenticated BTC/SYS evidence. The full local checker additionally checked context separation, wrong branch keys and 200 synthetic frozen signatures.

## Remaining obligation

Construct the actual classical-PPT hash/SHA/AuxPoW-dependent branch Build_j/Open_j for at least one of R1/R2/R3, with every authentic ORIGINAL witness recovering its same branch secret, but arbitrary QPT key recovery or native forgery implying actual original evidence or independently justified PQ hash/native break. Must cover malicious setup, source-coin retention, coherent auxiliary attacks, sibling capsules, selective openings and windows. The OR wrapper alone does not materially solve that missing source compiler. Do not optimize, advertise, or deploy it as WE.
