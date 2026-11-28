# R208 — source-constraint release with SECRET polynomial supports

Repo syscoin/PVUGC PR #1, open draft branch research/pq-wkem-validation-20260918. Observed start 206e7da77311a894d13aa368707c217468b2a44c. This is an intermediate research hypothesis checkpoint written locally before tests, not a cryptographic advance. No external literature/web or other repository writes.

Candidate: R207's public coefficient-span attack may depend on a publicly declared mask basis. Let public ORIGINAL constraints f_j(z)=0 encode actual BTC/SYS/AuxPoW challenge verification; sample private SHA-seeded sparse high-degree monomial supports for masks r_j. Publish expanded coefficients of P(z)=K+Σ f_j(z)r_j(z), not the mask supports. Public Open evaluates P on an original authenticated witness trace and, when valid, receives the SAME K for every valid witness.

Attack being checked: from the publicly visible monomials t of P and local-constraint monomials u, recover candidate hidden supports m=t-u whenever u divides t. The span of f_j(z)z^m may suffice to quotient-extract K by Gaussian elimination without knowing the SHA seeds, the supports, or any actual witness. Assess visibility/cancellation preconditions and try a nonlinear-residual/factored repair.

Boundaries: toy constraints are not actual source-verification; no native PQ signature, QPT simulation, source certificate, or working key-release mechanism is claimed. Save exact executed checker, results and derivation after this intermediate checkpoint. Routine negative results receive no PR progress comment.