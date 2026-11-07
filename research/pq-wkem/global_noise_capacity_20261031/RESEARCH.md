# NGCE — public affine interpolation defeats a proposed noise-capacity gate
2026-10-31. **NEGATIVE SOURCE-release repair checkpoint, not positive PQ WKEM progress.**
Repository syscoin/PVUGC PR #1, draft branch research/pq-wkem-validation-20260918, preceding head d92b4968be6e6f044dfc6117fd9c726abf07a364, ordinary comment 6550396385. No external research.

## Exact proposed repair and public release distribution
NOGC established that any integer affine opener of L1 norm at most L yields an ORIGINAL circuit witness; it also exhibited a fake opener with norm L+2. We tested replacing large-spacing bit rounding with a noise-tolerant code at a rate chosen to discriminate honest one-hot squared norm L from integer fake squared norm greater than L.

For each symbol m, take q=2147483647, independent s uniform in Z_q^10, errors e_1...e_14 and e* independently uniform over integers [-B,B], B=20, and g=100. Publish beta=A^T s+e (mod q), tau=t^T s+e*+gm (mod q), together with the ORIGINAL statement, checking key, context, and any related capsules. The attacker needs only (A,t,beta,tau), a projection of the full public view. If a native checking key or authentic preauthorization transcript is added, it cannot hide information already available from this projection. This is not a QPT simulator or native-signature model.

## Exact unsatisfiable instance
The ORIGINAL relation is NAND(x,x)=0 AND NAND(x,x)=1, which has no Boolean witness. Add one unconstrained four-choice one-hot auxiliary block; it can be included in the ORIGINAL witness and contributes one one-hot block. Coordinate order is
  (x0,x1; p00,p01,p10,p11; n00,n01,n10,n11; d00,d01,d10,d11).
The ten public affine equations A z=t are:
  x0+x1=1;
  sum(p)=1, p10+p11=x1, p01+p11=x1, p00+p01+p10=0;
  sum(n)=1, n10+n11=x1, n01+n11=x1, n00+n01+n10=1;
  sum(d)=1.

For d=0,1,2,3, define public integer affine solutions
  z_(0,d)=(1,0;2,-1,-1,1;1,0,0,0;onehot(d)), ||z||_2^2=10;
  z_(1,d)=(0,1;0,0,0,1;-1,1,1,0;onehot(d)), ||z||_2^2=6.
All eight satisfy A z=t exactly despite the ORIGINAL statement being FALSE. Every legitimate four-one-hot representation would have squared norm L=4. Thus each displayed integer fake opener is worse than honest in squared norm.

However zbar=(5/14)*mean_d(z_(0,d))+(9/14)*mean_d(z_(1,d)) is a RATIONAL affine combination satisfying A zbar=t, and **||zbar||_2^2=97/28 <4**. The attacker never needs to submit zbar as an accepted integer representation.

## Explicit joint-public interpolation attack and proof
For each of the eight PUBLIC integer fake solutions z compute r_z=center_q(tau-z^T beta). Since A z=t, if the centered residue does not wrap,
  r_z=g*m+e* - z^T e.
All displayed z have L1 norm at most 8. Since |gm|+B(1+8) <=280<q/2, this identity is **deterministically exact for every supported error coin**. Publicly compute
  r_mix=(5/14)*mean_d(r_z(0,d)) + (9/14)*mean_d(r_z(1,d)).
It equals g*m+e* - zbar^T e without knowing m, s, the errors or an ORIGINAL witness. In particular, the real interpolation is performed on centered public numbers; it does not require modular division of an integer SOURCE opener.

For independent centered bounded errors, variance of one error variable is B(B+1)/3=140. Exact noise variances:
  best displayed fake integer opener z_(1,0): 140*(1+6)=980;
  hypothetical legitimate one-hot four-block opener: 140*(1+4)=700;
  PUBLIC interpolated fake observations: 140*(1+97/28)=625.
Thus integer short-opener soundness does not bound the attacker's actual joint-public noise channel. The public interpolation has *lower* noise variance than honest one-hot evaluation in this explicitly specified system. This is NOT a universal impossibility for every code/noise choice, nor a QPT security result; it refutes the proposed linear-noise variance-gap proof strategy.

## Executed checks and provenance
The exact published self-contained checker.js was executed in the V8 tool and produced 27021 assertions on 3000 deterministic samples, all passing. It checks all eight public A z=t identities, squared norms, exact public residuals, affine mixture identities, and quantization MSE/error ordering. Captured output is output.json.

An additional **LOCAL-ONLY** standard-library Python checker was executed twice, with byte-identical final outputs. It checked 12,000 symbols / 96,000 public residual identities and recovered the SAME precommitted 256-bit mock capability in both related repetition-coded capsules with no ORIGINAL witness; the mock checking digest matched. Python source SHA-256 f1971e969dc51fa18462fc02829a344abb3106864a6b3a7df610bffcda995162; final output SHA-256 bb510b3e5aec48d778c0e8638def82c91e8e2c6c29876f96152b0a489cdfc6ed. Complete local archive SHA-256 f0ecf079c31dc8e6f98fb114715770c9005afe7bf092eeabfec2eb55c828a280. The Python fixture and mock key are NOT native PQ signatures or QPT experiments.

## Unproved next equation
There is no secure ORIGINAL-dependent witness-KEM here. A repaired scheme must provide witness-free classical-PPT Comp(R,x,context,vk) and public source-dependent Lift with Lift(Comp(...),W)=K for **every** ORIGINAL valid W, without public invalid-opening interpolation. For adversarial FALSE or hard TRUE x and arbitrary coherent QPT attackers in the complete joint relation/capsule/checking-key/context/auxiliary/related-capsule view, unauthorized final-key recovery or accepted native fresh forgery must yield an actual ORIGINAL witness or an independently justified QPT break. An optional hash, norm or proof precheck does not cryptographically gate an already public raw residual. Ordinary uniform-matrix QPT-LWE assumptions cannot simply be applied to this structured A. No SOURCE-opening oracle, arbitrary-key-recovery extraction, malicious-setup proof, or native Bitcoin PQ deployment is claimed.
