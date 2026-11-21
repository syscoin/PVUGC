# R185 — Source-dependent constraint mask, intermediate checkpoint

Status: active mathematical attempt, not a solved hash-only release scheme, security proof, or deployable bridge. Existing PR #1 branch research/pq-wkem-validation-20260918, observed start 0d56b39cbe2f643c67082b9f1ddc8ac97a1d2fbb, open/draft/unmerged.

Read exact R184 source-graph-gate checkpoint, R183 OR-key QROM conditional combiner, R182 activated-annex binding, R181 source-slot limitation and recent relevant PR comments. No web/literature, no other repository write.

Candidate: derive one native cancellation capability from actual ORIGINAL authenticated work/PoB/AuxPoW constraints without enumerating future evidence. Over a Boolean quotient represent local SHA/source constraints by c_i(z) that ALL valid ORIGINAL witness traces satisfy. Setup chooses a frozen K and random masks a_i, publishes F(z)=K + sum_i c_i(z)*a_i(z). Every valid trace w yields F(w)=K, including across the three challenge families if the combined OR relation is encoded correctly. This is a concrete same-key identity but DOES NOT supply secrecy.

Exact adversarial experiment: for public polynomial coefficient encoding bounded to degree D, calculate the span W of all allowed constraint multiples c_i*m and attempt Gaussian elimination for K from public F. If an actual witness exists, its evaluation functional annihilates W and maps 1 to 1, so 1 not in W; a public quotient functional may recover K WITHOUT an ORIGINAL witness. This issue must be tested rather than hidden.

Repairs to investigate: nonlinear SHA masking of the fault syndrome; hash commitments to unknown mask coefficients; and whether either still permits a polynomial-time public Open for ALL accepted original source witnesses without private issuance, independent puzzles, unauthenticated source shortcuts or obfuscation assumptions.

Only actual executed work may be described later. No successful quantum game, source compiler or native-signature implementation is asserted in this checkpoint. Do not notify a negative result.