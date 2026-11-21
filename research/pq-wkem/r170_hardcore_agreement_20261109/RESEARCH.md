# R170 — Generic hard-TRUE native capability release implies passive one-bit key agreement

**Status:** Verified self-contained implication and Fourier extraction lemma; NOT a practical witness-KEM, a hash-only generic-NP compiler, or a QPT security proof for any candidate. This is a necessary *security* consequence of the user's ORIGINAL requirements. No lattice, discrete-log/group, online release issuer, web search or outside paper was used. No routine user notification or ordinary top-level PR comment solely for this result.

## 1. Provenance and continuity

Repository syscoin/PVUGC, PR #1, branch research/pq-wkem-validation-20260918. Observed initial head ee4c9998952e618ba67ac3348a26976ee41c4648, open/draft/unmerged. Read that head's rank_dichotomy_20261109/RESEARCH_AND_CHECKER.md exact blob 9b7c63a946062fd4de0a0bae7cb127f6da2e8cd4, as well as the exact-version R168 source-disclosure and MDS same-witness notes. A recent issue-comment read returned no comments in the requested recent window. A real intermediate checkpoint was published under this directory at commit 95edd896cd68f1bdf02732e545d8eef60f9196cd and parent ee4c9998952e618ba67ac3348a26976ee41c4648. That note preceded the tests and expressly did not claim they ran.

The R166 predecessor proved a generic hard-TRUE WKEM would yield one-way public-key transport if it supported a uniform random K, or native-signature transport with a freshly created signing key. One-way transport itself is not bitwise secrecy or key agreement. The result below strengthens this to a *hard-core shared bit* even when the frozen capability is a nonuniform native signature with correlated public verification key. It does not use any post-hoc issuer or source oracle.

## 2. Exact hypothetical property

Fix a security parameter λ and an ORIGINAL relation family with classical-PPT verification. Hypothesize a **classical-PPT** pre-funding Build(R,x,σ) producing public capsule c that includes native VK, intended message M, CK/auxiliary data and all bound context. Build needs only x (no satisfying witness). For **every** w with R(x,w)=1, the public off-chain Open(c,w) outputs the SAME frozen σ. The honest Builder may emulate a multi-party N-of-N ceremony with one honest protected/erased participant. Multi-party malicious security is not derived here.

Assume the hard-TRUE full-public QPT security actually demanded: for any efficient attacker obtaining the *exact* frozen σ (or a different native-accepted signature on the intended challenge path) with nonnegligible probability without a qualified w, there is a QPT reduction extracting an ACTUAL ORIGINAL witness or breaking a separately justified PQ native/hash security assumption. This is stronger than the usual false-instance-only WE definition and is NOT proved by an independently implemented candidate. The threat view includes R,x,c,VK,M,CK,source commitments,Aux and any relevant compatible related capsules. Independent run advice and setup/cross-capsule correlations must be simulated consistently.

## 3. Classical hash-preimage ORIGINAL family and sender/receiver

Choose a domain-separated target hash H_pre and n large enough to make random-preimage inversion quantum-infeasible at the target λ. The receiver samples sk <- {0,1}^n and publishes pk=H_pre(sk). Define the ORIGINAL relation R_pk(pk,w)=1 exactly when |w|=n and H_pre(w)=pk.

The sender generates fresh native signing material (or emulates the permitted honest N-of-N signing procedure), produces the intended frozen native σ on M and VK, and runs c=Build(R_pk,pk,σ). It then samples an independently uniform public r <- {0,1}^{|σ|} **AFTER** Build and publishes (c,r) along with its public context. The sender's one-bit secret is b=<r,σ> modulo 2. The receiver runs σ'=Open(c,sk) and computes b'=<r,σ'>.

For every valid preimage, σ'=σ, hence b'=b. No canonical witness or common source preimage is needed. Notice that this uses the *native-signature-only* interface: σ can have any distribution conditional on VK and c. The predicate's witness exists when Build runs, but it is unknown to the sender, exactly as a generic hard-TRUE experiment permits. A source-only scheme requiring actual future Bitcoin history instead of arbitrary NP applicability falls outside this reduction, and cannot be promoted to the requested generic result.

## 4. Exact bit prediction -> full frozen capability recovery

Suppose arbitrary QPT Eve A receives the full public transcript T=(R,pk,c,VK,M,CK,Aux,related public data) and independent r, and predicts <r,σ> with probability at least 1/2+ε(λ) where ε is nonnegligible.

For fixed (T,σ) set
    f_T(r) = E_{A fresh coins/advice}[ (-1)^{A(T,r)} ].
Define Fourier characters χ_s(r)=(-1)^{<s,r>} on the |σ|-bit Boolean cube and coefficients
    fhat_T(s) = E_r f_T(r) χ_s(r).

By definition, averaging over honestly sampled (T,σ), the bit predictor's advantage yields
    E_{T,σ} fhat_T(σ) >= 2ε.
Since every fhat lies in [-1,1], the probability of a transcript/σ with fhat_T(σ) >= ε is at least ε/(1-ε). The bound follows from E[X] <= ε+(1-ε)Pr[X>=ε] for X<=1. For such an instance σ is a heavy Fourier coefficient of f_T, **regardless of the distribution of σ**, native VK correlations, or other public checking fields. Choosing r only after c is essential so that f_T is a fixed function of r for each instance.

The next subsection supplies an explicit polynomial Fourier list extractor, rather than asking A to volunteer σ, a witness, its representation or its quantum query log. This uses fresh *complete runs* of A with selected r, not rewinding a quantum state. Repeated independent advice copies are an explicit requirement; this is valid for ordinary polynomial-advice model families supplied in polynomial copies but **not** for arbitrary one-shot quantum advice correlated with this run's σ/sk.

## 5. Paired-query heavy-Fourier reconstruction

Let m=|σ|. For a prefix u of length t, split any random r into (a,b) of t and m-t bits. Parseval implies total energy Σ_s fhat(s)^2=E_r f(r)^2<=1. Define the prefix energy

    E_t(u) = Σ_{v∈{0,1}^{m-t}} fhat_T(u||v)^2
           = E_{a,a',b} [ f_T(a,b) f_T(a',b) (-1)^{<u,a xor a'>} ],

where a,a' are independent uniform t-bit strings and b is a SHARED uniform (m-t)-bit suffix. The second identity follows from Walsh orthogonality in b. Evaluate an unbiased estimator by invoking A twice independently on public (a,b) and (a',b) and multiplying the corresponding ±1 outputs with the character. This works for randomized QPT A because the *outer* calls are fresh classical input/output invocations.

Start from empty prefix; at depth t extend retained prefixes by each possible bit. Retain only those whose estimated E_t(u) exceeds ε²/2, using additive accuracy <= ε²/4 and appropriate logarithmic amplification for a polynomial failure bound. If |fhat_T(σ)|>=ε, every true prefix of σ has E_t>=ε² and survives. Since total exact prefix energy <=1, at most O(1/ε²) prefixes have energy >=ε²/4 at any depth. Hoeffding sampling with O(ε^-4 log(m/ε)) paired oracle calls per candidate produces a polynomial m,1/ε candidate list. At the final depth this list contains the EXACT frozen σ on a nonnegligible fraction of transcript/σ instances. Selecting a random candidate suffices for nonnegligible recovery; native verification can optionally filter accepted candidates but does not prove exact σ identity if more than one valid signature is possible.

Consequently, an efficient nonnegligible bit predictor implies an efficient full native-capability recovery algorithm. The stipulated ORIGINAL hard-TRUE security then transforms it into a full preimage w' with H_pre(w')=pk or an independently justified PQ primitive break. **This is a conditional reduction on the existence/security of the desired WKEM, not that construction.**

## 6. Why this matters for SHA/PoW direction

A generic statement-only hash-based ORIGINAL WKEM with the requested hard-TRUE extraction would be powerful enough to implement passive one-bit public-key agreement from hash-preimage public keys, not merely a vague ability to detect satisfiability. Black-box random-oracle-only key agreement is subject to strong classical oracle-query obstacles. However this pass does NOT independently establish a PPT-vs-QPT impossibility for all black-box QROM constructions; a polynomial *query* eavesdropper that uses superpolynomial computation would not suffice for a QPT impossibility. Do not turn the remembered separation folklore into a proved no-go without the exact theorem/model. Also, this implication does NOT rule out non-black-box assumptions about a fixed SHA circuit, a cryptographically effective additional setup resource, or genuine new source-dependent correlation; those are the unresolved constructive directions.

Public ordinary PoW and source-root commitments alone do not secretly correlate a sender's frozen σ with the hard preimage witness. If a candidate uses authenticated Syscoin/AuxPoW data as an additional resource, its source-to-capability release must still be genuine and it must state whether it continues to satisfy generic-NP applicability. Synthetic PoW / a public hash of a fabricated parent header never stands in for authenticated Bitcoin best-chain membership. Distinct valid parent-work certificates for one Syscoin child outcome need not be incompatible forks.

## 7. Executed tests and exact provenance

Actually executed Python 3 standard-library checker.py twice with byte-identical outputs. It includes exact Fraction arithmetic comparing the Fourier-prefix square-energy identity with its paired-query identity on 31 arbitrary t,u combinations for an independent, non-character f; five deterministic noisy hidden-parity predictors on 14-bit frozen capability fixtures (per-call flip probability 0.14, correlation 0.72 in expectation), and an independent random-bit negative control. The polynomial-in-m,1/epsilon list extractor retained the true 14-bit secret in all five fixtures, with 1-2 terminal candidates, and returned zero candidates for the independent predictor. Total 48 actual assert checks; test numbers demonstrate only bounded finite arithmetic/implementation. The source outputs are deterministic from test seeds and are NOT a hardness evaluation, no QPT attack/extractor test, no original-PoW authentication and no real native signature.

    checker.py SHA256: c3aae5d43927c597263c0260329d0b7e46ea56c32fc6a8dd3d305b32a82242ee
    captured.json SHA256: 7a407b42c7215f8d980d5f19cabe70c29cc8d39c8099b6b24ecfdf274f236b2b
    expected Git blobs: checker.py a8dd5142c4f7fe13ef0563dc3bd86228b9147adb ; captured.json 79c5e6c5313cbb02547ae5b77092425d7d12b812

No independent agent used. The code and captured output, NOT just counts, belong with this note. A real hash-only Build_hash/Open_hash meeting every ORIGINAL witness and arbitrary-QPT recovery remains absent.

## 8. Next fundamental experiment, not an efficiency exercise

Take the hash-preimage hard-TRUE ORIGINAL relation itself and attempt to instantiate the public frozen-native release interface without witness enumeration or public test-only token oracles. Model the full source of *sender/receiver secret correlation*, identify whether a proposed SHA/PoW construction can establish a single unpredictable shared parity bit in the black-box oracle query model, and then either supply a polynomial QPT-secure mechanism or a rigorously scoped lower bound explaining which additional source-specific/cryptographic assumption is indispensable. In parallel preserve the actual Syscoin source relation identity/claim/UTXO/slot, full parent AuxPoW/coinbase/ancestor/lag/height/Merkle proofs, canonical-chain observation/window and native VK/path; these are not cryptographic secret-correlations by themselves.

This pass has NOT found a practical WKEM or a quantum-secure hash-only ORIGINAL source compiler. Do not disable the standing research task or claim a breakthrough.
