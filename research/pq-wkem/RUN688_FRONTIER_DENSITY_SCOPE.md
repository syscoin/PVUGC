# Run 688 — Public release-frontier quantum density bound

**Research only; not a practical PQ WKEM.** Exact live start: 'syscoin/PVUGC#1', 'research/pq-wkem-validation-20260918', 'd6bf7fe50e7b0d8b23c7d7e60e0bc17d8a81cea4', PR open/draft/unmerged (2026-10-21). The extended proof and more extensive checker are preserved separately.

## New scoped criterion

Let an honestly generated *true-instance* public release program take freely variable frontier input 's in {0,1}^b' and independent evaluator coins 'r'. Suppose 'M' **distinct** states 's' arise from valid ORIGINAL witnesses and, for this same fixed setup, each recovers a credential that signs the intended, previously unsigned native branch message with probability at least '1-epsilon' over 'r'. The public predicate 'Good(s,r) := Verify(pk, Sign(Release(P,s;r), m_x))' is polynomial-time and its known classical public circuit is coherently evaluable. This includes the actual native public checking key and context; it requires no recovered gates or reverse-engineering of an obfuscator.

The marked input fraction satisfies 'a >= M*(1-epsilon)/2^b'. Quantum amplitude amplification (with unknown a if needed) therefore finds some credential-producing pair and a fresh accepted native signature after 'O(sqrt(2^b/(M*(1-epsilon))))' coherent public circuit evaluations. It does **not** need to know any valid witness beforehand. If its measured state embeds a SOURCE representation, Run 259 may subsequently extract a witness; that does not increase the cost of the attack. Count distinct frontier states **M**, not the number of witnesses when the prefix is many-to-one. Include every freely variable authentication/token bit in b, not only the final mixing-gadget wires. Evaluation coins do not repair the bound.

For approximately perfect correctness the attack's query exponent is '(b-log2 M)/2'. A necessary **query-cost** condition for a nominal 128-bit-PQ target is roughly 'b >= 256+log2 M', with implementation margins. 'b=256,M=2^32' gives approximately '2^112' oracle calls; 'b=288,M=2^32' gives approximately '2^128'. This is a **concrete search-resource diagnostic**, not a QPT impossibility theorem when that work is exponential, nor a claim about quantum hardware cost. Asymptotic QPT insecurity follows only when the bound is polynomial.

## Exact scope

The argument is a coherent Grover-type public-evaluation search, not a new Simon/hidden-subgroup attack or an independent cryptographic hardness assumption. It does not break the actual RIO/CLZ construction, prove how many distinct valid states the Syscoin relation yields, or prove any construction's false-instance hiding. Malicious setup, replay, source extraction and multi-capsule correlations remain separate. The conditional Run 687 false-instance simulator theorem only addresses **false x**, whereas this bound addresses **true x**. Run 259 (exact blob 'c7f3b77f0273ca1cbe6f0b31c1a086b8eb3acbf2') remains 'accepted complete SOURCE representation -> ORIGINAL witness', not 'signature -> SOURCE representation'.

## Reproducibility / literature

The standard-library checker implements actual finite state-vector phase/reflection Grover iterations over 15 marked sets, checks analytic 'sin^2((2t+1)asin(sqrt(M/2^b)))' and normalization, randomized evaluator density, 40-witness-to-4-state collision, and two resource exponents. Compilation and two byte-identical executions passed; **63 counted assertions**. It is a toy query model, not a PQ WKEM prototype.

Primary quantum-search basis: Brassard–Hoyer–Mosca–Tapp, *Quantum Amplitude Amplification and Estimation*, arXiv:quant-ph/0005055. Local-mixing background: Canetti–Chamon–Mucciolo–Ruckenstein (TCC 2024), Canetti–Luo–Zhang (CRYPTO 2026); no new full-proof or QPT-assumption audit of either. Prior exact files consulted at live head: 'RUN687_PUBLISHED_SCOPE.md', 'CLZ_APPLICABILITY_20261008.md', Run 259 source binding.

**Unmet:** concrete post-quantum locally mixed release, every-ORIGINAL-witness common capability, full-public false-instance QPT hiding, unauthorized true-instance recovery/native forgery to ORIGINAL or independent QPT break, malicious/abort-secure N-of-N, adaptive multiple capsules, practical 128-bit parameters, conditional native-PQ Bitcoin graph. No production changes; PR stays draft.
