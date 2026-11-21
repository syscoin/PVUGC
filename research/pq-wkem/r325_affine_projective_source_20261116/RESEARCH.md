# R325 — projective-key release and the SHA Ch nonlinear consistency gap (NONQUALIFYING)

A bounded offline iteration continuing the missing R324 source-dependent public release. It constructs a **real polynomial-time full-public release and exact FALSE simulator for a restricted affine relation**, then checks why that release does not extend to the ORIGINAL authenticated SHA/AuxPoW witness relation. No ORIGINAL hash-only witness-KEM or independent QPT native recovery theorem is claimed.

## Read-only continuity

At start, syscoin/PVUGC PR #1 was open/draft, branch `research/pq-wkem-validation-20260918`, head `b6da8f956051bc08ded48997d449222310b50996`. Read R324 exact note blob `ddbc20c409bd01cf3166b4cfd448af73ba15e5e6` and R323 blob `75bb84de7dc1df0d977c5fc5157efbd0d337d3be`. Read-only Core #609 PR metadata showed head `c91539de3c34937e57d7f5fda47c7b0502ff33f6`, with release-disabled/sentinel public PQ activation. No Core tests run.

The target ORIGINAL relation is still the **independent OR** of relevant greater exact Bitcoin cumulative work on the same anchor, authenticated finite burn/withdrawal-authorization fault, and qualified semantic Syscoin ancestor inconsistency or independently outer-authenticated relevant tag fault with explicit maturity qualification. Retain exact claim/UTXO/burn/amount/recipient, baseline, relevant source height h_rel, BTC anchor/window, LC depth, deadline/reset, capsule ID, fixed safe native cancellation message/VK, modern contextual AuxPoW chain ID, exact canonical 41-byte parent SYS tag distinct from child commitment, all interval links, and R225 native activation/slot-global policy. This fixture does **not** model or authenticate those ORIGINAL conditions.

## Fully specified restricted Build/Open

For an affine statement x=(A,b) over F_2, with A an m-by-n matrix, use relation V_A(x,w) = [A w=b]. Honest builder freezes an arbitrary lambda-bit S representing synthetic cancellation bytes. Draw **independent** R uniformly in F_2^(m-by-lambda). Publish:

```
P = A^T R
K = b^T R
D = S XOR K
C = (A,b,P,D,context,VK)
```

`Build_A` and `Open_A` are classical polynomial time. `Open_A(C,w)` checks A w=b, then computes `S' = D XOR w^T P`. All valid witnesses, not necessarily the same witness, return identical frozen S because `w^T P = w^T A^T R = b^T R = K`.

**Complete-public FALSE security is exact** for b outside image(A): take v in kernel(A^T) with b^T v=1. For each uniformly random column of R, adding v preserves the public projection P while flipping its secret K bit. Therefore K is uniform even conditioned on the complete P. For independent uniformly drawn columns, D is a uniform one-time pad, independent of S and its public native verification key/context **conditioned on auxiliary data independent of R**. The simulator samples real P and independent uniform D. Identical full-public classical distributions remain identical under arbitrary coherent/joint QPT processing and independent access to other oracles. This statement does not protect a secret separately revealed by auxiliary data or native VK, and retained/correlated source/setup coins invalidate its independence premise. No QROM reprogramming is invoked.

**The restricted TRUE relation is easy**: a classical attacker can solve A w=b using Gaussian elimination and recover S. There is no hard-TRUE ORIGINAL source security. The example is an algebraic control, not a new deployed cryptosystem.

## Attempted SHA256 Ch repair fails source-authenticated release

The SHA bit operation `Ch(x,y,z)=z XOR (x AND y) XOR (x AND z)`. Introduce independent lift coordinates `t_xy,t_xz` and encode its check as the *linear* equation `c+z+t_xy+t_xz=0`. The deliberately FALSE unlifted source `x=y=z=0,c=1` violates Ch, but the vector `m=(x,y,z,c,t_xy,t_xz)=(0,0,0,1,1,0)` solves all the lifted affine equations: its synthetic t_xy is not x*y. The public affine projector now lets an adversary calculate `D XOR m^T P = S` without an ORIGINAL valid SHA trace. Checking actual source admission *after* extraction cannot retract native bearer cancellation.

The exact next cryptographic condition is to enforce `t_xy=x*y` and `t_xz=x*z` **inside source-dependent secret release**, for all SHA/AuxPoW/contextual source gates together, while keeping polynomial Build, public Open, every ORIGINAL-witness same S, and a complete-public QPT simulator/extractor. More independently valued monomial coordinates do not accomplish this. This is not a generic impossibility theorem for nonlinear hash-only WE.

## Multi-capsule public law

Reusing R is unsafe even for an affine FALSE target. Let target A0=[0],b0=[1]: P0=0,K0=r. A TRUE sibling A1=[1],b1=[1] built with *the same* r reveals P1=r, thus K0 publicly, and S0=D0 XOR P1 without target witness. With fresh independent R0,R1, each sibling P1 leaves K0 uniform. This repairs only the stated independent-randomness control; it says nothing about malicious N-of-N setup, selected disclosures, source producer retained coins, overlapping honest secrets, or arbitrary sibling schemes.

## Executed evidence

Python3 standard-library checker executed twice locally with byte-identical output; **30,666 assertions** each. Exhaustive census covered every F2 matrix up to 3-by-3 and every right-hand side: 3,131 TRUE and 1,905 FALSE systems, checking TRUE projection identity and per-projection FALSE conditional K uniformity. Also tested two distinct TRUE witnesses of a 256-bit synthetic S, all eight Ch truth rows, explicit false-source linear-lift public extraction, same-R sibling leakage, independent-R no-leak law, and 200 random bounded matrices. No Bitcoin/Core source admission, valid native SLH signature, QPT experiment or network claim.

Complete local derivation, executed `checker.py`, paired JSON outputs and captured hashes are in the R325 **local-only** reproducibility archive, not claimed as source published in GitHub. Local checker SHA256: `323ad8c304b99905e0bdced14bb4a7dfacc1bbf4f910d836d1ed1c6436da5d2b`. Both JSON output SHA256: `d2fa96b06985e18c3f343a4dd411834162d137bde12d2604312f62315d6813f3`. Archive SHA256: `7b5eb6a74b85e0ba55472bb2800ac8707bccb6b395f4030f814371bd0cfe751b`.

**Unsolved:** noninteractive genuine SHA/AuxPoW/canonical contextual source-dependent hash-only Build/Open yielding one fixed safe native capability for EVERY qualifying ORIGINAL witness; FALSE/hard-TRUE QPT recovery or accepted native forgery to an actual ORIGINAL certificate or independent PQ hash/native break; malicious N-of-N ceremony/abort, useful completeness/DA, inclusion and R225 binding. No progress comment, production change, deployment or automation change.
