# Run 112 — setup-known invariant correction and adaptor/VRF boundary

## Checkpoint

Starting PR head: `a0803edfa691f184e33ca92620471a81c17c611c` on `research/pq-wkem-validation-20260918`; PR #1 was open, draft and unmerged. Latest ordinary comment was `5843580758`, publishing Runs 104–108 and 110–111.

This run corrects one ambiguity in Run 111 and audits two concrete invariant carriers. The result is not a WKEM, but it removes a misleading extraction target and closes a plausible generic-adaptor composition.

### Result A — value-only extraction is the wrong target

Suppose witness-free classical setup computes

\[
(P,Z)\leftarrow Setup(x;r)
\]

and masks the final key as `C = K xor KDF(Z)`. If there were an efficient extractor

\[
E(x,P,Z)\to w,\qquad R(x,w)=1,
\]

then witness search is solved by running `Setup` and then `E`. If `E` is QPT, their composition is QPT. Therefore, for a QPT-hard witness-search relation,

\[
\boxed{\text{setup-known }Z + \text{ value-only }E(P,Z)\to w\text{ is impossible}.}
\]

This corrects Run 111's phrase "extractable invariant adaptor" if read as extraction from the recovered value alone. The required reduction must instead use the **recovery process**—adversary code, predictor/oracle behavior, supplied representation, circuit plus adjoint, etc.—or end in an independently justified QPT-hardness break. This matches the process-oriented nature of Run 102.

### Result B — the 2024 generic NP adaptor exposes shared-prefix invariants

Primary source: Liu–Tzannetos–Zikas, *Adaptor Signatures: New Security Definition and A Generic Construction for NP Relations*, IACR ePrint 2024/1051, current PDF `https://eprint.iacr.org/2024/1051.pdf`.

Figure 7 gives, schematically,

\[
\widetilde\sigma=(\bar\sigma,Y,c,d_0),\qquad
\sigma=(\bar\sigma,Y,c,d),
\]

where `bar_sigma = SIG.Sign(sk,(m,Y,c))`; a source witness is the trapdoor that changes the commitment opening from dummy message `m0` to target message `m`. The extractor checks that `bar_sigma`, `Y`, and `c` agree and extracts from the two openings. These algorithms are explicit at indexed PDF lines 853–876.

Hence the direct Run-111 composition

\[
Z=I(\bar\sigma,Y,c)
\]

fails unconditionally for any public `I`: the complete input to `I` is already inside the pre-signature. With `C=K xor KDF(Z)`, anyone recovers `K` before adaptation.

This is only a no-go for invariants of this unchanged shared prefix, not every conceivable completion invariant. The paper quantifies security over PPT adversaries, not QPT adversaries.

### Result C — a VRF has the right common-value shape, but not witness gating

A VRF separates one deterministic value `v` from its proof `pi`. Thus the same value can coexist with randomized/non-unique proof encodings. This avoids conflating "same KEM value" with "unique full signature", so the Erwig unique-signature obstruction from Run 111 does not by itself forbid a VRF-like invariant.

If every valid source witness could obtain the same hidden `v`, then

\[
C=K\oplus KDF(v)
\]

would give exact all-witness same-key correctness. But a normal VRF lets the **VRF secret-key holder**, not an arbitrary NP witness holder, compute `v`. Publishing `(v,pi)` leaks it; publishing only `pk` gives the witness no evaluation power. A public offline token that transfers exactly `v` to valid NP witnesses is still the missing release compiler. Naming it an "adaptor VRF" would be circular unless independently constructed.

## Exact lattice-VRF security audit

Primary source: Esgin–Kuchta–Sakzad–Steinfeld–Zhang–Sun–Chu, *Practical Post-Quantum Few-Time Verifiable Random Function with Applications to Algorand*, IACR ePrint 2020/1222 / PQCrypto 2021, current PDF `https://eprint.iacr.org/2020/1222.pdf`.

The honest algorithms are classical. With short module-lattice secret `s` and public `t=As`, evaluation computes

\[
b=G(A,t,\mu),\qquad v=\langle b,s\rangle,
\]

then samples masking randomness and outputs a proof `pi=(z,c)`. The first reported concrete set has an 84-byte VRF value and about 4.94 KB proof.

The important model boundary is explicit:

* Definition 2.5 defines computational full uniqueness against a **polynomial-time adversary**.
* Theorem 3.1 assumes a Module-SIS instance and proves uniqueness **in the random-oracle model**. Its proof starts with a `PPT adversary` and explicitly performs `Rewind 1` and `Rewind 2` using standard forking (indexed PDF lines 479–544).
* Appendix B Theorem B.1 assumes the paper's MLWE distribution and states pseudorandomness against **PPT** adversaries with at most `k-1` evaluation queries, again in ROM (lines 1089–1133).

Under this project's required classification:

1. honest algorithm model: classical PPT;
2. theorem adversary: classical PPT as written;
3. hardness: the paper's explicit Module-SIS/Module-LWE distributions and parameters;
4. reduction: classical ROM; uniqueness uses classical rewinding/forking;
5. QPT/QROM status: **UNPROVED here**. Assuming a lattice problem is QPT-hard does not automatically quantum-lift the forking/reprogramming proof. The exact QPT hardness of the paper-specific small-secret/error distributions was also not independently established in this run.

So LB-VRF is useful evidence for a compact **canonical value + randomized proof** interface, not an acceptable QPT endpoint.

## 2026 Online/Offline-NIZK adaptor status

The indexed current record for Abe–Bui–Cong–Ohkubo–Shang–Takahashi–Tibouchi, ePrint 2026/2155 (minor revision 22 September 2026, ASIACRYPT 2026), still advertises arbitrary-NP witness completion and extraction via Online/Offline NIZK, with an AES-128 VOLE-in-the-Head/FAEST instantiation.

The full current primary PDF was not retrievable in this run. Therefore no claim is made about whether its pre-signature exposes/hides a common invariant, and its abstract is not promoted to a QPT theorem. The 2024 prefix-leak result must not be projected onto this distinct 2026 construction without its actual algorithms.

## Executed checker

`setup_known_invariant_adaptor_vrf_run112_check.py` is deterministic and standard-library-only. Two executions were byte-identical. It records **17,997 assertions** covering:

* 197 finite setup-known-value/value-only-extractor composition cases;
* 2,016 generic-adaptor shared-prefix fixtures, each with four adapted openings, including immediate one-mask early-key recovery from the pre-signature;
* 189 fixtures where one deterministic value has six distinct proof encodings;
* 96 conditional all-witness same-key fixtures once one common value is supplied;
* 32 process-vs-value separation controls.

## Updated ledger

| Component | Honest model | Adversary/reduction model | Exact conclusion | Target status |
|---|---|---|---|---|
| setup-known-value lemma | classical PPT setup | QPT extractor allowed | rules out value-only source extraction for QPT-hard witness search | unconditional correction |
| Liu–Tzannetos–Zikas generic AS | classical PPT | PPT in paper | generic witness-hiding adaptor; shared prefix unchanged | shared-prefix invariant composition refuted; QPT unproved |
| Esgin et al. LB-VRF | classical PPT | PPT, ROM; two rewinds for uniqueness | compact canonical value + randomized proof, few-time | useful shape only; QPT/QROM unproved |
| Run 102 | classical honest use; QPT extractor | process/circuit access | conditional recovery-behavior extraction | reusable only after suitable encoding |
| needed release | classical public/offline | arbitrary QPT | every valid source witness gets same hidden value; unauthorized recovery process source-extracts or breaks QPT-hardness | **missing** |

## Next handoff

The sharper target is now a **process-extractable hidden canonical value**:

1. one setup-known value independent of which valid source witness is used;
2. a public/offline witness-gated mechanism that lets every valid source witness obtain it without exposing a universal evaluator;
3. an arbitrary-QPT recovery **algorithm** can be used to extract an ORIGINAL source witness or break an independently justified QPT-hard assumption.

Next work should audit the full 2026/2155 algorithms when available, search specifically for a VRF/VUF with an explicit QPT/QROM or standard-model quantum theorem rather than a "post-quantum" label, and connect any surviving canonical-value predictor to Run 102 without reintroducing Run 110's noisy complete-gadget leak or Runs 104/106/107's searchable-completion failures.

The practical generic-NP public/offline PQ WKEM remains open. The stopping condition is not met.
