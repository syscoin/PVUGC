# QGL — quadratic global-constraint lock (negative offline result)

**Status: no positive secure witness-KEM advance.** Bounded offline continuation of NGCE, actual prior head bd2c5d9de34ef4d1fd10b01a963cb8ff821b60fb, ordinary comment 6550493876. The goal was to repair public-affine interpolation using nonlinear ORIGINAL Boolean/NAND circuit equations, without a SOURCE-opening oracle.

## Constructed candidate and exact public distribution

For an ORIGINAL Boolean-circuit statement x, let a classical-PPT compiler form explicit polynomial constraints f_1(v),...,f_m(v), including Booleanity, NAND gates, and accepted output. Every valid ORIGINAL witness v has f(v)=0. Define F(v) as either the vector of these constraints (QGL-1) or that vector together with every pairwise product f_i(v)f_j(v) (QGL-2). These are globally defined nonlinear constraints, not independent local witness labels.

Sample the same precommitted capability K before any ORIGINAL witness is known. The attempted public raw release, for each symbol j and capsule c, has the form

    E_{c,j}(v) = g K_j + eta_{c,j} + sum_i a_{c,j,i} F_i(v) (mod q).

Coefficients a may be arbitrary correlated source-dependent masks, and eta is the fixed small decoding error for this symbol; raw evaluation must be computable by the public from capsule and v. For every valid ORIGINAL v, all F_i(v)=0, so E_{c,j}(v)=gK_j+eta and centered rounding recovers the same K in all related capsules.

This defines a **public affine-in-feature release family**, not a complete LWE ciphertext distribution. It tests whether nonlinear polynomial constraints and a quadratic repair alone enforce ORIGINAL-source soundness. A public precheck that refuses to return a key on invalid v is not a cryptographic restriction: attackers may recombine the exposed raw field expressions.

## Exact unauthorized hard-TRUE recovery

Define B(v)=(1,F(v)). If a valid witness exists, the target e=(1,0,...,0)=B(v_valid) lies in the linear span of all public B(v). Sample public invalid field points v_h, accumulate their B(v_h), and solve

    sum_h lambda_h = 1,
    sum_h lambda_h F_i(v_h) = 0 for all i.

Any such coefficients yield the identity, for **every** capsule and symbol simultaneously,

    sum_h lambda_h E_{c,j}(v_h) = gK_j+eta_{c,j} (mod q).

The masks and feature-aligned noise cancel algebraically *before* rounding, regardless of coefficient magnitudes. Neither an ORIGINAL witness, SOURCE-opening oracle, knowledge of a_{c,j,i}, nor an adversary-supplied representation is needed. Correlated checking keys, preauthorization signatures, and auxiliary outputs cannot erase a key already available from this public projection.

### Rank-sampling lemma and proof

Let F:F_q^n -> F_q^M comprise degree-at-most-D polynomials, D<q; r=dim span{(1,F(v))}, r<=M+1. If the current span is proper, a nonzero linear functional annihilating it but not the full span yields a nonzero polynomial l(1,F(v)) of degree at most D. Elementary polynomial root counting gives Pr[the next uniform v fails to increase rank]<=D/q. Expected samples to full rank are at most r/(1-D/q). Stopping after h consecutive failures per rank phase prematurely stops with probability at most r(D/q)^h. When the span is full it contains e=(1,0,...,0) from any unknown valid witness. For a Boolean circuit with at most 2^n valid assignments among q^n field points, the chance that N independently sampled field points inadvertently include a valid Boolean witness is at most N 2^n/q^n; the executed checker additionally asserts every chosen point is invalid.

This is a **precisely restricted no-go for polynomially many publicly evaluable, low-degree, fixed-feature affine masks**. It does not rule out general hidden-state nonlinear release, source-dependent honest noise outside that affine feature span, or raw evaluations unavailable to adversaries. It does not supply an LWE challenge simulator, a QPT-hardness assumption, or a global witness encryption construction.

## Exact executable regression

Field q=65537. ORIGINAL Boolean NAND trace v=(x,y,u,v,z): u=1-xy, v=1-ux, z=1-vy, required z=0. Nine polynomials: five Booleanity relations w(w-1), three NAND equations, and z. Exactly two valid ORIGINAL traces: (0,1,1,1,0) and (1,1,0,1,0). QGL-2 adds 45 quadratic products of the nine constraints, making 54 mask coordinates (maximum total degree 4).

The exact checked Python 3 standard-library script, published as checker.py, deterministically samples 180 invalid points from random.Random(0x51474C20261031), a mock 32-byte secret, two independently masked related capsules, coefficient masks uniform modulo q, errors eta in [-10,10], and spacing g=100. Because 100*255+10<q/2, the final centered byte decoding is unambiguous. The checking hash of the mock secret is only an integrity test; it is **not** a native PQ signature.

The compact checker was run offline and produced the exact captured output.json. QGL-1 recovered 64/64 mock key bytes across two capsules using 10 invalid evaluation coefficients; QGL-2 recovered 64/64 with 54 invalid coefficients. Neither attack queried an ORIGINAL witness. A longer independent local checker passed **784 assertions twice with byte-identical output** (SHA-256 43ef412d093442c4a782e096b2b48689744e2001a167b9edf23b889ff591c2fb), preserving additional exact raw-residual and false-instance tests. The false contradiction f(x)=(x,1-x) has no such affine interpolation (as f_1+f_2=1); this does **not** establish general FALSE-source security.

## Security status and next exact equation

**No positive advance.** QGL has witness-free classical-polynomial setup and every-valid-ORIGINAL-witness SAME-capability correctness but fails unauthorized hard-TRUE recovery against a classical adversary, hence also against arbitrary QPT. False-instance full-public-output security is unproved, and native EUF-CMA, quantum coherent attacks, malicious setup, correlated auxiliary inputs, selective openings and cross-capsule composition have no established reductions here. The earlier ordinary-QPT-LWE theorems for uniform binary-ISIS sources do not transfer to the structured NAND matrix.

The next construction needs a real, independently justified LWE/hash-based cryptographic nonlinear public release that prevents the **entire public recombination** of invalid source observations, with an actually joint challenge simulator. Required target: classical-PPT witness-free Comp(R_original,x,context,vk), public Lift with Lift(Comp(...),W)=K for **every** valid ORIGINAL W, and unauthorized QPT final-key recovery or fresh native forgery on adversarial FALSE/hard TRUE sources -> an actual ORIGINAL witness OR an independently justified QPT break. Never assume the adversary volunteers an internal representation. N-of-N one-honest funding/abort, SYS/BTC evidence qualification, DA and the conditional native Bitcoin PQ endpoint remain unresolved.

No external web/literature research or subagents were used. There is no deployment or completed practical witness-KEM claim.
