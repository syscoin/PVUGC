# Full-coin adaptive survivor hybrid for restricted LWE SOURCE

**Constructive result (restricted):** The predecessor shared-LWE-key/XOR-share proof permitted adaptive opening of plaintext shares only. This continuation permits the adversary to reveal each opened share's **entire encryption randomness** along with its plaintext, with a fully instantiated QPT decisional-LWE and native-signature simulator. The proof replaces **only one randomly selected, unopened share** by uniform ciphertexts; every opened capsule remains genuine and exactly re-evaluable. It incurs a factor \(t\) for guessing a survivor. This is a concrete improvement in a restricted composition interface, **not a generic-NP witness-KEM or a 128-bit QPT hardness certification**.

Record: full-coin-adaptive-survivor-hybrid-20261028-automation-turn11. Starting syscoin/PVUGC open/draft/unmerged PR #1 at 8a1b891249a7c7e5b2aaf2fec5d34ab84a6bcd2d, branch research/pq-wkem-validation-20260918; latest substantive comment at start 6484925563. Exact predecessors read: two_tier_public_proxy_20261028/RESEARCH.md blob 6fca0ecbb6aa733039be88fda3ab315d69fb956a and shared_lwe_selective_opening_20261028/RESEARCH.md blob 8d7c996046bed561c3f95f022412e15f5ae7935b. No external literature research.

## Algorithms and distributions

Fix odd prime \(q\), \(m>n\), \(h\) with \(2h<q\), native seed length \(\kappa\), and polynomial \(t\ge 1\). Let \(g=2h+1\), \(B=\lfloor q/g\rfloor\ge2\), and \(\ell=\lceil\kappa/\log_2B\rceil\). Define the signed integer L1 sphere

\[
S(m,h)=\{r\in\mathbb Z^m:\sum_i|r_i|=h\},\quad
N(m,h)=\sum_{k=1}^{\min(m,h)}2^k{m\choose k}{h-1\choose k-1}.
\]

The exact classical PPT sampler first chooses \(k\) with weight equal to its summand in \(N\), uniformly chooses the \(k\)-element support, a uniform ordered positive composition of \(h\), then independent fair signs. The QPT decisional-LWE **true source** is \(A\leftarrow U(\mathbb F_q^{m\times n})\), \(s\leftarrow U(\mathbb F_q^n)\), \(e\leftarrow U(\{-1,0,1\}^m)\), and \(b=As+e\pmod q\). Its challenge-secret-free **uniform branch** samples \(A,b\) independently uniformly. The independent QPT hardness assumption is for exactly these distributions, including its advice model; a concrete 128-bit security estimate has not been supplied.

The ORIGINAL statement is a **restricted LWE bounded-error relation**, augmented with typed public identity/claim/UTXO/branch/anchors/window/context and checking-key bindings. Its valid ORIGINAL witness is \((s,e)\) with \(b=As+e\pmod q\), each \(e_i\in\{-1,0,1\}\), and the specified context valid. This does NOT instantiate the full SYS/BTC predicate.

Classical Build given only \(A,b,C\) generates a *genuine* independent native signing seed \(K\in\{0,1\}^\kappa\) and \(pk(K)\); samples independent uniform \(U,Z_1,\ldots,Z_t\in\{0,1\}^\kappa\); and publishes \(D=U\oplus\bigoplus_iZ_i\), \(V=K\oplus U\). Encode each share \(Z_i\) as fixed-length \(\ell\) base-\(B\) digits \(a_{ij}\). For every \(i,j\), independently sample \(r_{ij}\leftarrow U(S(m,h))\), publish the entire source ciphertext

\[
(c_{ij},d_{ij})=(A^\top r_{ij},\ b^\top r_{ij}+g a_{ij})\pmod q .
\]

ALL \(t\) related share capsules use the SAME \(A,b\) but independent randomness. The complete public view includes source/relation/statement, every ciphertext, genuine \(pk(K)\), \(D,V\), typed claim/path/context, permitted public auxiliary inputs and all modeled related capsules. The auxiliary-input generator must be efficiently simulatable from public data, challenge-independent advice and opened allowed shares/coins; it must not leak native \(K\), the hidden share, \(U\), a SOURCE witness \((s,e)\), or hidden coins through separate channels. The stronger keyless builder model is not established.

Public OFF-CHAIN Release validates an **ACTUAL ORIGINAL** \((s,e)\) before decoding. For each digit,

\[
d_{ij}-s^\top c_{ij}=g a_{ij}+e^\top r_{ij}\pmod q,\qquad |e^\top r_{ij}|\le h<g/2.
\]

The cyclic center gaps are at least \(g\), so EVERY valid ORIGINAL witness uniquely recovers every digit and returns the SAME precommitted \(K=V\oplus D\oplus\bigoplus_i Z_i\), without a canonical witness or common intermediate states. Nothing is verified by Bitcoin or by an inner proof here.

## Stronger selective-opening game and exact QPT hybrid

The arbitrary QPT adversary receives the full public view, may obtain classical native signing-oracle answers except for a designated fresh challenge-path message, and may adaptively call Open(i) on at most \(t-1\) **whole distinct** shares. Open(i) reveals **both** \(Z_i\) and *every* encryption coin \(r_{ij}\); the adversary can reproduce \(c_{ij},d_{ij}\) and all associated plaintexts exactly. A real ORIGINAL witness \((s,e)\), unrevealed global Build coins, and a signing seed are NOT disclosed. Opening ALL t shares, arbitrary partial coin openings spread across all t shares, and extra same-key bypass capsules are outside the security claim. Open is an experiment, not an online authority or mandatory protocol participant. Signing and opening interfaces are classical; adversaries may use arbitrary coherent QPT state and challenge-independent efficiently preparable quantum advice. No quantum superposition oracle queries, quantum rewinding, random-oracle extraction or adversary-volunteered representation are used.

Let \(E\) mean successful output of a usable final native capability or accepted *fresh* intended-path native signature; \(O\) be the set of opened indices. Independently choose \(J\leftarrow\{1,\ldots,t\}\) uniformly, and put \(E_J=E\wedge(J\notin O)\). Exact counting gives

\[
\Pr_T[E_J]=\mathbb E_T[1_E(t-|O|)/t]\ge\Pr_T[E]/t.
\]

**True-to-uniform:** One ordinary QPT decisional-LWE reduction gets challenge \(H=[A\ b]\), generates the REAL native K/pk, every mask, share and independent encryption coin, and can answer all full-coin Open queries without knowing \(s,e\) or a SourceOpen oracle. It measures \(E_J\). Its two branches are EXACTLY the actual true and uniform public/output/opening distributions. The gap costs \(\operatorname{Adv}^{QPT}_{DecLWE}\), not an additional assumption for opening correlations.

**Uniform-to-one-hidden-capsule:** For uniform \(H\in\mathbb F_q^{m\times(n+1)}\), if \(r\ne r'\in S(m,h)\), \(r-r'\not\equiv0\pmod q\), since \(2h<q\). Therefore

\[
\mathbb E_H[\operatorname{Coll}(H^\top r\mid H)]
=1/N+(1-1/N)/q^{n+1},\quad
\mathbb E_H[\operatorname{TV}(H^\top r\mid H,U(\mathbb F_q^{n+1}))]
\le\delta_h=\tfrac12\sqrt{(q^{n+1}-1)/N}.
\]

Condition on genuine \(K\), checking key, shares, XOR pads, public typed context, common \(H\), and all OTHER capsules and their coins. The selected share \(J\)'s \(\ell\) sphere samplers remain independent. A **conditional product hybrid** plus last-coordinate shift invariance gives expected whole-ciphertext distance at most \(\ell\delta_h\) when replacing ONLY the \(J\) ciphertexts with independent uniform \((n+1)\)-vectors. All other ciphertexts stay genuine and consistent with their full disclosed coins. Abort with a failure bit if Open(J) is requested: it cannot affect the event \(E_J\). The averaging over uniform H is done **before** any adversarially chosen adaptive conditioning; data processing and trace-distance contraction handle arbitrary QPT postprocessing. This is a **joint full-public** statement, not marginal pad hiding.

**Native-signature reduction:** Given a genuine native checking key \(pk(K)\) without K, sample uniform H, real shares and coins for every \(i\ne J\), genuine corresponding ciphertexts, independent uniform \(D,V\), and independent uniform ciphertexts for J. Return correct opened shares/coins for \(i\ne J\); abort for J. For fixed \(K,Z_{i\ne J}\), the map \((U,Z_J)\mapsto(V,D)\) is a bijection on two \(\kappa\)-bit strings, so \(D,V\) are jointly uniform independently of K even conditioned on \(pk(K)\). The J ciphertexts have no connection to \(Z_J\). Thus the simulator matches the ideal event \(E_J\) exactly; classical native signing queries are forwarded. A recovered usable K produces a fresh native signature, or an output fresh signature is forwarded. This uses independently assumed QPT native EUF-CMA, with a signing seed that is sufficient to derive a valid native secret key.

Combining gives, for the EXACT restricted TRUE LWE source and this opening/auxiliary game,

\[
\boxed{\Pr_T[E]\le t\bigl(\operatorname{Adv}^{QPT}_{DecLWE}+
\ell\delta_h+\operatorname{Adv}^{QPT}_{native\ EUF-CMA}\bigr).}
\]

When only share plaintexts are opened, the predecessor has a better no-\(t\)-loss hybrid. The new factor t buys genuine source-encryption-coin disclosures. No classical-to-QPT lifting is assumed.

**Random false distribution only:** For uniform H, the same proof begins after the decisional-LWE step and gives \(\Pr_U[E]\le t(\ell\delta_h+\operatorname{Adv}_{native})\). By a union bound a uniform \((A,b)\) possesses any ternary-error opening with probability at most \(\rho=q^{n-m}3^m\). Conditioning on a FALSE sampled H changes the distribution by at most \(\rho\), so \(\Pr_{U\mid FALSE}[E]\le t(\ell\delta_h+\operatorname{Adv}_{native})+\rho\). **This does NOT establish security for every fixed false ORIGINAL NP statement.**

## Exact verification, resources and limitations

The committed finite-algebra verifier 'verify_published.py' was executed twice with **2,730 assertions** and identical captured 'published_output.json': every proper t=3 XOR opening subset, 4 complete 256-bit same-K releases under two distinct ORIGINAL valid witnesses, replay of opened encryption coins, and an exact large-parameter integer inequality. Separate **LOCAL-ONLY** offline Python and JavaScript checkers passed **248,140** and **15,282** assertions, respectively, in two byte-identical runs each. The extended checker exhaustively tested 15,625 small-field full hashing matrices, 15 sphere-vector pairs, adaptive-share transcript laws, eight more 256-bit same-K trials and an independent recurrence for sphere cardinality. Their exact code/output is retained in the local research archive, not represented as committed unless separately published. None of these finite algebraic checks demonstrates QPT hardness, generic-NP security or native SLH security.

Illustrative arithmetic only: q=65537, n=128, m=1600, h=696, kappa=256, t=3; g=1393, B=47, ell=47; 141 ciphertexts, 18,189 field elements (excluding shared A,b, pk and metadata); \(\log_2N=2545.046872210\), \(\log_2\delta_h=-241.522016227\), \(\log_2(t\ell\delta_h)=-234.382464875\). Uniform-H ternary-opening probability upper bound is below \(2^{-21016}\). These are **statistical/resource bounds, not actual 128-bit QPT-LWE parameter certification**.

**Exact next missing construction:** a classical PPT witness-FREE compiler \(\mathrm{Comp}(R,x,C)\) for arbitrary ORIGINAL NP, where EVERY valid ORIGINAL witness opens one same precommitted native capability, every fixed false instance has full-public QPT security, and arbitrary unauthorized hard-true native recovery/forgery reduces to ACTUAL ORIGINAL W or an INDEPENDENT QPT break—without an adversary-supplied representation. The previously tested 3CNF and two-tier linear SOURCE compilers remain BROKEN by public pseudo-moment proxies. More padding, local mixers, basis rotation, an unrelated LWE wrapper, or merely requiring supplied opening acceptance are not fixes. Malicious N-of-N preauthorization, honest-erasure/abort/no-bypass graph, evidence availability before funding, authentic SYS/BTC AuxPoW/header/tag/ancestor/window relation, and hypothetical no-EC native PQ-only Bitcoin endpoint are separate unresolved requirements. The full completion condition is NOT met; do not disable the existing automation.