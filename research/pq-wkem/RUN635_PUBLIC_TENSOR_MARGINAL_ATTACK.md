# Run 635 — Public tensor marginalization defeats a bounded-bond release carrier

2026-10-19. Research-only note, syscoin/PVUGC#1, starting head `a4116ef1ea02a22f771b61a14b2973d43d00f3fd`. **Not a practical witness-KEM or CCMR/RIO break.**

## Conditional exact contraction theorem

Suppose the entire SOURCE-admission and protected capability-release computation is publicly represented by bounded-domain integer tensors. It has ORIGINAL witness variables `w`, output capability variables `k`, and auxiliary/internal variables `z`. The complete contracted coefficient is

`A_P(w,k)=sum_z product_a T_a((w,k,z)|scope_a)`.

Individual entries may be signed due to invertible local frame changes; require only that every **fully contracted** `A_P(w,k)` is nonnegative. This is a restrictive, explicitly stated interface, not a presumed feature of an arbitrary obfuscator.

For a TRUE statement `x`, ORIGINAL relation `R(x,w)`, and a fixed intended capability `K`, define
- `V=sum_{R(x,w)=1,k} A_P(w,k)>0` (valid-source mass);
- `B_j=sum_{R(x,w)=1,k:k_j != K_j} A_P(w,k)<=epsilon V` (incorrect valid mass for bit `j`);
- `E=sum_{R(x,w)=0,k} A_P(w,k)` (invalid-source mass).

The fully public marginals `Z_j(b)=sum_{w,k:k_j=b} A_P(w,k)` obey `Z_j(K_j)>Z_j(1-K_j)` whenever **`(1-2 epsilon)V>E`**. Proof: the correct-bit marginal is at least `(1-epsilon)V`; the opposite-bit marginal is at most `epsilon V+E`. Thus `K_j=argmax_b Z_j(b)`, independently for every key bit. If every valid ORIGINAL witness releases exactly the SAME key and invalid witnesses carry zero mass, then `epsilon=E=0` and all bits are recovered with no witness.

With a known/efficiently found tree decomposition of **the complete augmented factor graph, including SOURCE, output tests and checking constraints**, domain size at most `q`, induced width `t`, polynomial-size integer factors and a polynomial number of variables, exact variable elimination computes the marginals in `poly(input)*q^{O(t)}` bit operations. Integer intermediate bit lengths remain polynomial because each is a sum of at most exponentially many bounded integer products. For a public matrix-product chain of bond `D`, witness-symbol marginalization is just multiplication of `sum_b M_i^b`. Two chains sharing a witness symbol use `sum_b M_i^b tensor N_i^b` of bond `D_1D_2`. A small mixer whose external hard SOURCE constraints have been omitted **does not** meet the theorem's interface. Nor is arbitrary NP shown to have a small-bond representation.

This is a classical attack, hence an arbitrary-QPT attack against this *specific publicly contractible* architecture; no quantum-specific speedup or universal WE reduction is claimed. In contrast to Run 634's exhaustive `2^ell` state enumeration, contraction can be polynomial for arbitrarily large witness length when the full public network has logarithmic width.

## Exact finite falsifier

For the illustrative toy ORIGINAL relation `R(w)=[xor_i w_i=0]`, publish independently gauge-dressed source and release two-state chains:

`A_i^b=G_(i-1)^(-1) X^b G_i`;
`B_i^b=H_(i-1)^(-1) X^(b xor d_i) H_i`,
where `X=[[0,1],[1,0]]`, each `G_i,H_i` is a product of integer unimodular shears, and `xor_i d_i=K`. The appropriately dressed endpoint vectors weight even-parity witnesses by 1 and odd-parity witnesses by `eta`, while testing candidate output bit `k`.

For **every** witness,
`A_P(w,k)=(1 if parity(w)=0 else eta)*[k=parity(w) xor K]`.

Every even-parity ORIGINAL witness recovers the same K while intermediate states vary. The public four-state joint transfer produces EXACTLY `Z(K)=2^(n-1)` and `Z(1-K)=eta*2^(n-1)`. Attack: contract both complete public matrices and select the larger marginal. No reconstruction/alignment of the secret local gauges is needed. For `eta=0`, invalid source states have zero mass; `0<eta<1` still exposes K. For `eta=1` both marginals tie; `eta>1` gives the wrong majority. These negative controls are essential: **computational soundness alone does not bound invalid mass E**.

The **toy source relation is easy**, and no claim is made about an unauthorized hard-true SOURCE recovery attack. No native transaction signature was generated. The theorem instead identifies a *necessary exclusion*: a proposed cryptographic local release must not expose a complete tractably contractible tensor description satisfying this output-mass premise.

## Execution and attack taxonomy

The exactly executed JavaScript checker is published with this note and its byte-matched JSON output: 10,583 counted checks on 5 independent frame-masked fixtures, 6 key bits each, n=5,8,9,12,18; exhaustive direct evaluation for n<=9, exact public contraction for all, and contamination rates eta=0,1/8,1/2,1,2. The larger independently executed Python diagnostic (17,668 checks; n=5,8,10,12,18) is preserved in the local checkpoint. Both are finite algebra checks, **not evidence of cryptographic hardness**.

Attack families exercised: global gauge-invariant contraction (2), joint views (4), public chosen-input evaluation (5), capability/output correlation (8); classical attack available to QPT adversaries (9). No separate seam/fingerprint attack (1/3), malicious setup attack (6), or replay attack (7) is asserted. Honest classical PPT generation of explicitly bounded integer tables suffices. Arbitrary quantum auxiliary input is irrelevant to this deterministic public attack; positive QPT hiding remains entirely UNPROVED.

**Run 259 scope:** recovered K is not an accepted complete Run-259 representation and does not invoke its conditional SIS/ORIGINAL-extraction theorem. This exposes, rather than repairs, the missing arbitrary-recovery/signature-to-ORIGINAL implication. Run 633's computationally sound false accepting proofs can give E>0, and may defeat the marginal attack when invalid mass dominates. No statement about a real Gaussian SOURCE compiler, CCMR/RIO, N-of-N setup or P2MR activation is derived.

## Literature and handoff

Underlying tensor/BDD tractability is known: Usturali–Chamon–Ruckenstein–Mucciolo, *A Matrix Product State Representation of Boolean Functions*, arXiv:2505.01930; Markov–Shi, SIAM J. Comput. 38 (2008), DOI 10.1137/050644756. CCMR's reversible-circuit local mixing, ePrint 2024/006, is a different interface: **its security is neither attacked nor justified by this checker**. No complete primary-paper proof/errata audit in this iteration.

Remaining challenge: construct a small SOURCE-authenticated protected release region for which **full public-byte** marginalization and all other classical/QPT attacks are infeasible under independently justified assumptions, while every valid ORIGINAL witness yields the SAME native-signing capability, and arbitrary early recovery/accepted forgery implies ORIGINAL witness or explicit QPT break. Malicious one-honest N-of-N ceremony, multi-capsule composition, practical resources, fork context and conditional native-PQ Bitcoin graph remain UNPROVED. No completed WKEM; retain research automation.
