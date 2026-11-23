# Praxis review — intermediate checkpoint

This is a bounded, adversarial review of the user-supplied ePrint 2026/2971, not a claim of a construction breakthrough or a discovered classical break.

## Observations at this checkpoint

- Initial invocation clock: 2026-11-23 14:16:17 UTC. No elapsed-time claim is inferred from this entry.
- Fresh PVUGC PR #1 head read: `67dea8d5cb19b083e4f29cfa86bf2a306359107a`, existing branch `research/pq-wkem-validation-20260918`. Its most recent note screens Merkle-preimage release as NONQUALIFYING. No GitHub writes have been attempted in this invocation.
- The supplied PDF was retrieved through the ePrint mirror landing page's PDF link: https://eprint.iacr.asia/2026/2971.pdf . Search-service extraction reports 66 pages and 5,565 lines. Main and mirror direct HTTP requests from the local runtime returned HTTP 403, so no local PDF bytes or SHA256 are claimed.
- Paper: *Praxis: Practical Witness Encryption for NP*, David Tse, Nikhil Vanjani, Psi Vesely; retrieved version dated 2026-11-21 by the landing metadata. The underlying proof is classical bilinear GGM + ROM with a reduction alternative to Module-SIS. It is not hash-only or QPT secure.
- Actual root reads include Definitions 3.1–3.6, Theorem 5.9, Section 6.2, Section 6.4, Lemma B.9, Figure 9 and parts of Appendix B.6. Three agents are independently reviewing construction algebra, security scope and parameters/formalization. Their work is not represented as an independent cryptographic certification.

## Exact live questions

1. Can an in-model adversary bypass the low-rank stack/tie classification without a BQS witness or the stated short-kernel/MSIS alternative? Earlier attacks on exposed scalar factors do not automatically apply to encoded factors.
2. Is the lifting algorithm of Lemma B.9 justified by `24 beta^4 < q^3`, including containment and polynomial representation size? Lean uses a different exhaustive lifting reduction; a successful Lean build alone would not settle this question.
3. What does extraction to a Groth16 proof imply for the original source witness under correlated public CRS, advice, native context and multiple capsules? Its extra knowledge-soundness and runtime costs cannot be omitted.
4. Does fixed-witness correctness (failure iff xi_key(w)=0) meet the stricter adaptive/every-witness bridge requirement? No efficient malicious-witness counterexample has been established.

## Candidate-independent explicit recovery equation

Figure 9 includes S_leg=[s_leg]_2, its alpha copy [alpha*s_leg]_2, and K_alpha=[alpha*kappa]_T, with nonzero s_leg,alpha. Given a discrete-log algorithm, recover alpha as the relative logarithm of the first two values, then compute alpha^{-1} K_alpha=[kappa]_T and unmask. This is an algebraic, witness-free quantum route via ordinary quantum DLP, outside the paper's classical claim. It is not yet locally checked here and is not a claimed classical break.

## Reporting boundary

No Core tests, real source witnesses, end-to-end Praxis encryption/decryption, Lean build, quantum execution, funded endpoint or deployment have been run. No blanket security claim follows from failure to find an attack. No automation setting has been changed.
