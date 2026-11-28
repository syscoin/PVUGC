# R219 — HASH-EVAL-ENCODING: attempt to hide R218 coefficients behind public evaluation

**Disposition: unsuccessful restricted construction. Not a secure hash-only ORIGINAL witness-KEM and not a QPT theorem.** The actual release algorithm remains missing.

## Continuity

syscoin/PVUGC PR #1, draft/open, branch research/pq-wkem-validation-20260918. Observed starting SHA c5ddeb956e3804f0fe9a25fe3f76f3f4258ed3aa (R218), after exact-version reading of research/pq-wkem/r218_circuit_ideal_pad_20261111/RESEARCH.md. Latest ordinary PR comments since 2026-11-10 returned none. Local checkpoint recorded before implementation; the intermediate PR checkpoint is 9a3054f55335f940a6f29a99bf67eebe1f3a709b, with source parent c5ddeb9. No web/external sources, third-party agents, production files, native BTC signatures, actual SHA/AuxPoW/PoB verifier, mining, or QPT experiment were used.

## Exact candidate and general scoped theorem

Consider the actual original source SHA/AuxPoW/PoB verifier represented by public Boolean constraints C_i(z)=0. The prior functional candidate chose K and randomized low-degree masks Q_i and published a coefficient representation P(z)=K+sum Q_i(z) C_i(z), yielding the SAME K at every actual satisfying original witness but leaking K through a public constraint-span projector (R218). New repair attempt: hide the coefficient vector, and expose only a hypothetical publicly callable evaluator E(z)=P(z). This evaluator was intentionally modeled, NOT instantiated as hash-based cryptography.

For n Boolean inputs and multilinear total degree <=D, assume M=sum_{k=0}^D binom(n,k) is polynomial. If E is callable on every Boolean input 1_T of weight <=D, M NONWITNESS queries suffice to recover all coefficients via Mobius inversion:

    coeff_P(S) = sum_{T subseteq S} (-1)^(|S|-|T|) E(1_T).

Let S_public be the publicly known span of the reduced multiplier-constraint polynomials m(z)C_i(z). Assuming at least one satisfying Boolean witness w exists, evaluation at w annihilates S_public but not the constant polynomial 1, so e_const is not in S_public. Public Gaussian elimination finds L with L(e_const)=1 and L(S_public)=0. Therefore L(coeff_P)=K without finding w and without a valid witness query. This classical attack also belongs to QPT. It is restricted to the polynomial-dimensional raw evaluation family, NOT an impossibility theorem for hash-only WE or SHA.

## Executed experiments

A synthetic five-variable AND-chain circuit uses u=a*b, v=u*c and v=1 over F257; the only satisfying Boolean assignment is 11111. Random multiplier polynomials Q_i of degree <=1 yield total Boolean degree <=3. All 26 Boolean assignments of Hamming weight <=3 are nonsatisfying. An independently executable small checker (published_repro.py) used only those invalid raw evaluations to recover 32/32 random K values. It recorded 66 counted assertions, no security claim. Its exact tested SHA256 is 7334c8edb31111f7dc1e1bc0e798ae4fd628f5f55ed562bf9570b07f7237f19c; captured-output SHA256 b8fb87bd54854b35daf9dd81ae09ab53a1cdd341bcdfbd7b5e637342a5b9b826. Both executions matched.

A separate larger local-only repro.py checked Boolean coefficient interpolation, annihilating projection, witness-free K recovery and synthetic capability unsealing (404 functional assertions, 64 seeds). Local source SHA256 c8af0b0b9c669468fdc25d59299b2b4e50e11fc8f32b7aeb51cfb23f9de2fe2f, output SHA256 2ace4d9a499317e26249526bbbd84b0ffa782f2a72c200da5749e1b2aa627cc9; two byte-identical runs. This is not deployed Bitcoin/Syscoin.

## Attempted domain restriction and exact remaining obligation

For an IDEAL evaluator restricted to authenticated observation set Z, take independent uniform mask B in the public span S and a fixed key K. Exposed values are Y_K=K*ones_Z+E_Z(B). The conditional distributions over Y for any two fixed K are identical iff ones_Z lies in the linear image E_Z(S); otherwise distinct K occupy disjoint affine cosets and a linear functional recovers K. Executed local ideal_domain.py (SHA256 2d4569f8f216ceda001731b77600454eacdd52ecaf4d97af45eadff334e6dd60) checked five selected invalid observations (perfect uniform masking in this IDEAL model), all 26 invalid probes (K leaks), and the first five plus a satisfying observation (K leaks). Output SHA256 659e429ede896b4afe7fa0a679bf2f851868937007ccfab0b9571fdce0502de4. This statement is linear algebra, NOT quantum or public-key security.

An honest-verifier condition, an inspectable program with a hidden constant, source-held secret labels, an online evaluator, SHA commitments to unusably hidden coefficients, or an independent PoW puzzle cannot instantiate a public source-authenticated evaluator. If source validation is merely applied before a publicly reconstructible key, a malicious attacker bypasses it.

**Missing constructive step:** a concrete hash/SHA-based, classical-PPT public Build_hash(x_W,sigma_cancel) and Open_hash(C,w) that cryptographically couples all ACTUAL authenticated challenge evidence (R1 BTC, R2 admitted PoB, R3 SYS/AuxPoW) to one precommitted claim-specific native cancellation capability, and a full-joint arbitrary-QPT recovery/native-forgery-to-ORIGINAL-evidence or independent PQ break reduction. No generic arbitrary-NP assumption is imposed. No ordinary PR comment or notification warranted; keep research automation enabled.