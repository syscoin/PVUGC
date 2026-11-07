# Run 572 — exact short-output injectivization of cyclic three-view seams

Date: 2026-10-16. Research only. Live starting branch \`research/pq-wkem-validation-20260918\`, SHA \`1855cc3cbec7180689676db1f4cd74e1b24cb8cc\`; draft/unmerged \`syscoin/PVUGC#1\`. Dependencies at that exact SHA: Run 571 note blob \`30d5b3cc8997f085e9590d20e0e4b09f72e0dc25\`, Run 259 blob \`c7f3b77f0273ca1cbe6f0b31c1a086b8eb3acbf2\`, CLZ assessment blob \`c19d9d9cd515140e3ce62eac960cd548c0add622\`. Latest substantive ordinary PR comment: 6067040320.

## Precise result and proof

Run 571's injective-reference dihedral reduction left short-output cyclic reference functions unresolved. Let \`N=2^n\`, \`1<=k<=N/2\`, \`T={0,...,k-1}\`, and let \`B: Z_N -> {0,1}^b\` be uniformly random. Define \`V_T(x)=(B(x+t))_{t in T}\`. For **every distinct** \`x,y\`, the **exact** pair-collision probability is

\`Pr_B[V_T(x)=V_T(y)] = 2^(-b*k)\`.

Proof: write \`d=y-x !=0\`. Make an undirected graph with edges \`{t,t+d}\` for each \`t in T\`. Translation by nonzero d partitions \`Z_(2^n)\` into cycles of even, power-of-two length. Every such cycle contains an antipodal pair \`u,u+N/2\`. The consecutive half-interval T contains no such pair, so it cannot contain a whole translation orbit. The selected edges therefore contain no cycle; length-two edge duplication would likewise require both antipodes in T. The graph is a forest of k distinct edges. Independent uniformly random b-bit colors on its vertices satisfy all edge equalities with probability exactly \`2^(-b*k)\`. QED.

For arbitrary offset subsets, the correct exponent is the graphical rank \`|V|-components\`, which may be smaller than k. Negative control: \`N=8,T={0,4},d=4\` has two written equalities but only one independent edge. The consecutive-interval restriction matters.

By a union bound,

\`Pr_B[V_T not injective] <= C(2^n,2)*2^(-b*k) < 2^(2*n-1-b*k)\`.

With \`k=ceil((2n+kappa)/b)<=2^(n-1)\`, failure is \`<2^(-kappa-1)\`. Illustrative probability parameters: \`n=128,b=1,kappa=128,k=384\`, failure \`<2^-129\`. These are **injectivization distribution parameters**, NOT 128-bit quantum work-factor estimates. The proof also applies to a 2k-wise independent classically samplable function family, since any collision graph uses at most 2k vertices. Exposing such a family's algebraic coefficients may make the shift easier to recover; no secure concrete seam is thereby constructed.

## Dihedral consequence

If a public candidate exposes **three separately coherently evaluable functions** \`A(x)\`, \`B(x)\`, and \`F_delta(x)=A(x) XOR B(x+delta mod N)\`, cancel A to obtain \`G_delta(x)=B(x+delta)\`. Evaluate grouped oracles \`B_T(x)=V_T(x)\` and \`G_T(x)=V_T(x+delta)\`. Conditioned on V_T being injective, \`O(x,0)=B_T(x)\`, \`O(x,1)=G_T(x)\` is an exact right-coset oracle for the reflection \`(-delta,1)\` in \`D_N=Z_N semidirect Z_2\`. An arbitrary QPT attacker with coherent access can generate this HSP oracle at cost k component queries per grouped query. Known dihedral algorithms are **subexponential** \`2^O(sqrt(n))\`, not known polynomial QPT from this argument. No concrete Kuperberg resource estimate, universal quantum break, or FINAL key recovery is shown unless the protected key is explicitly derived only from delta.

## Attack surface and limits

Seam cancellation and joint-view/gauge correlation are exact under the specified three-oracle interface. A single capsule suffices; biased/malicious setup is unnecessary. Short one-bit outputs and standalone statistical tests do not block grouped injectivization. Reuse across UTXOs or related claims compounds exposure, but neither multi-capsule security nor cross-context key recovery is analyzed completely. Public checking keys may be included in the adversary view and are not used by this reduction. Coherent chosen-input evaluation of all three correlated public functions is essential; no claim is made against CLZ/CCMR actual protected public interfaces. A transparent invertible B has a previously known classical inverse attack, separate from this result.

Honest finite checks are classical. The theorem treats a public ideal random function or a 2k-wise independent family; no honest classical-PPT obfuscated F_delta construction with hidden delta is supplied. The adversary model is arbitrary QPT with coherent access to the entire stipulated public interface and arbitrary auxiliary public information. No QROM programming, extractor, rewinding, practical instantiation, or complete 128-bit parameters are claimed. The new step is **sharper cyclic consecutive-offset forest collision counting**, not a new quantum algorithm. M. Gharibi's 2012 general injectivization theorem for arbitrary groups has a weaker \`|G|^2/|S|^ceil(k/2)\` bound for arbitrary distinct offsets; the actual Theorem 1 and proof were inspected at https://arxiv.org/pdf/1207.4537 (PDF pages 3–4). The Run 571 note preserves Kuperberg/Regev dihedral references; their full proofs and constants were not re-audited here.

## Validation and WKEM handoff

The adjacent exact Python checker was executed twice byte-identically, passed \`py_compile\` and 34,392 assertions: 13,089 finite forest cases, 248 exhaustive tiny random-function probability cases, 155 dihedral-oracle instances, 4,960 fiber checks, a nonconsecutive-offset counterexample, and bound arithmetic. It executes no quantum algorithm and establishes no QPT cryptographic security.

Run 259 retains only its exact supplied-complete-representation -> ORIGINAL source implication, conditional on its actual statistical or QPT-SIS assumptions. This oracle attack produces no accepted representation or ORIGINAL witness; avoiding it does not construct the missing late-witness \`Join_w\` or prove unauthorized FINAL-key recovery/signature forgery -> ORIGINAL source. False-instance full-public-output QPT hiding, all-witness SAME capability, malicious one-honest-party N-of-N setup/abort/erasure, multiple-capsule composition, practical resources and the conditional Bitcoin P2MR/native-SLH challenge graph are **UNPROVED**. Research-only, no production modifications. **Stopping condition unmet.**
