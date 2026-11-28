# R208 — Secret sparse mask support does not repair public constraint release

**Classification: negative ORIGINAL-release construction/repair attempt, not a secure hash-only WKEM, practical bridge result or QPT proof. No ordinary PR progress comment.**

## Continuity and actions

Repo `syscoin/PVUGC`, existing open/draft PR #1, branch `research/pq-wkem-validation-20260918`. Start HEAD `206e7da77311a894d13aa368707c217468b2a44c`. Read exact latest `r207_constraint_ideal_20261110/RESEARCH.md`, plus narrowly relevant R205 public garbling inputs and R206 point lock. Read recent issue comments since 2026-11-10T14:00Z, none. No web/external literature, agent delegation, source-core write, native BTC/PQ operation, or mining. Intermediate hypothesis checkpoint was written locally before testing, then published as `9d8cc91efefa619b6044bfb13238b02c0e64a9da`. 

Local full checker: `checker.py`, SHA256 `80209abffa6780f25bade7c5eefa323793b0323881fbc577e856b41e0900a46c`; `captured.json`, SHA256 `547b365930ac09727eeb87a29feaad8ee4c89b2bd7a2a4d4245e80baa8011304`. Executed twice locally, output byte-identical; 20 seeds, 260 functional assertions. This complete local checker/output pair is **local only** and not claimed to have been published in the PR. Smaller independently executed and published `repro.py` blob `9248766debb96f0254d6cbd30617911fcf25d21f`, SHA256 `e581a0d172307a05c21731fe8c3dbb063b4ab7e2ba7b4e0a0fb430d6bb5e4128`; `repro_output.json` blob `4251b1cd357703c0e270a354f0421f24fc07d30a`, SHA256 `bf57f9cfc632194de5faf4d4c21c6e37d8984298a25582a9ca69d5957e9f7200`; executed twice byte-identically, 12 seeds and 84 assertions. Tests are synthetic algebra, not quantum security analysis or an actual original-source verifier.

## ORIGINAL target and new repair hypothesis

Actual ORIGINAL x_W binds claim/UTXO, N-of-N-preauthorized graph, exact cancel message/native VK, baseline and BTC/SYS anchors, windows and relevant source roots. One notary can initiate the withdrawal. A permissionless watcher with any genuine R1 stronger contradictory BTC history, R2 absent/invalid authorized PoB, or R3 qualified claim-prefix Syscoin fork/tag fault must recover the **same precommitted** path-scoped native cancellation capability off chain. Original SHA/AuxPoW/coinbase and history authentication belongs inside cryptographic release; Bitcoin sees a native signature only. Neither the toy polynomial nor SHA-sampled mask coefficients authenticate this original evidence.

R207 attempted `P(z)=K+Σ_j f_j(z)r_j(z)`: every accepting ORIGINAL constraint trace `z` satisfies every `f_j(z)=0`, so `P(z)=K` independently of which original witness applies. Its quotient attack uses a publicly specified finite mask span. The R208 repair makes the masks' **monomial supports secret**, random SHA256-seeded, high-degree and sparse, and publishes only the expanded polynomial coefficients. The toy field is F_257, with `f0=a+b-2ab-1`, `f1=c-ab`, `f2=a²-a`, `f3=b²-b`, `f4=c²-c`. Both (0,1,0) and (1,0,0) satisfy the circuit. A random nonzero constant mask term is deliberately included in f0 so the published constant coefficient is **not K**. A real Build would also seal a fixed native signature with `D=sigma_cancel XOR H_pad(x_W,K)` and publish appropriate checking data; this native component was not implemented.

## New exact attack lemma (expanded sparse carrier only)

Let `supp(f_j)` and `T=supp(P)` be the public nonzero monomial exponent sets. Construct

```
S_hat = {t-u : t in T, u in supp(f_j) for some j, u<=t componentwise}
V_hat = span_F {f_j(z) z^m : j any, m in S_hat}
```

Assume each private mask monomial `m` making a nonzero contribution has at least one term `z^(m+u)` that survives into the expanded public `P`, for some `u in supp(f_j)`. Then `m∈S_hat` despite being privately sampled, so `P-K·1∈V_hat`. Importantly `V_hat` is a publicly reconstructible subspace of the ORIGINAL constraint ideal. If there is a valid witness `z*`, every member of `V_hat` vanishes at `z*` while the constant 1 evaluates to 1; therefore `1∉V_hat`. One can perform sparse Gaussian elimination on public coefficients to obtain

```
rem_Vhat(P) = K * rem_Vhat(1), with rem_Vhat(1) != 0.
```

A nonzero residual coordinate recovers `K` without the secret SHA seed, mask support, valid witness, supplied representation or attack trace. Candidate size is bounded by `|T| Σ_j |supp(f_j)|`; matrix computation is polynomial in the **expanded-sparse** public encoding size. This is a straight-line classical attack and thus also within arbitrary QPT. It is independent of hash-collision or preimage hardness. It is NOT a proof against arbitrary hidden-cancellation algebraic certificates, factored circuits with exponentially many expanded monomials, or any particular SHA circuit obfuscation.

The full executed checker tested exact SHA256-derived secret monomial supports at exponents 3–24, secret coefficients, 20 independent capsules and 39–40 expanded monomials each. Every hidden support was reconstructed from public terms, the coefficient residual for the whole polynomial equalled K times the quotient unit, both witnesses yielded K, all four listed invalid assignments failed the source toy constraints, and the public constant coefficient differed from K in all tested cases. The published smaller reproduction independently recovered the private K for 12 seeds from only expanded coefficients and constraints, with no seed/witness argument. These assertions verify the algorithm on finite synthetic fixtures, not security of untested variants.

## Separate nonlinear-residual repair and its exact limitation

A proposed public gate might use a nonlinear SHA circuit `E_C(r_1,...,r_m)` where Open computes the residuals `r_j=f_j(trace(w))` and returns `E_C(r)`. If every accepting ORIGINAL witness produces the all-zero residual vector, **the public caller directly evaluates E_C(0,...,0) and obtains the same output without original evidence**. This applies even to SHA-nonlinear masks and opaque evaluator internals; it assumes the all-zero residual input is substitutable at a public interface. It does NOT automatically break a fully witness-entangled circuit that never exposes residual ports or an arbitrary obfuscated SHA gate. A separate post-hoc validity check in honest Open does not protect a callable public E. This is a deterministic functional argument, not a QROM reduction.

Moving to a high-depth, succinct, witness-entangled hash evaluator that cannot be expanded economically is an uninstantiated **new algorithm**. A transparent factored circuit exposing the secret K as a literal or as readable additive shares still leaks. The required compiler must couple actual source SHA/AuxPoW authentication to hidden key evaluation across ALL qualifying R1/R2/R3 witnesses, rather than isolating public zero-residual slots. No such Build/Open or full-joint QPT simulator/extractor is provided by this run.

## Exact handoff

Do not restart openly expanded sparse `K+constraint-ideal` masking merely by hiding SHA-seeded exponents: reconstruct hidden supports and try public quotient projection first. Do not substitute a public nonlinear zero-residual function for authentication. Pursue a genuine source-entangled SHA evaluation encoding, specifying actual classical-PPT `Build_inc(x_W,sigma_cancel)` and `Open_inc(C,w)` with every-witness same frozen output and arbitrary full-public QPT recovery/native forgery to an ORIGINAL certificate or independently justified PQ break; include malicious setup, N-of-N honest-erasure, auxiliary/sibling capsules and source adversaries. This remains **unsolved**. No source/production change or progress comment is warranted solely from this negative regression.
