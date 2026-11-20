# R397 — Noncommutative global branch masking: source-release preflight (NONQUALIFYING)

## Provenance and aim
This bounded iteration began at live open draft syscoin/PVUGC#1 head `102e6beb5b76db5fa93bb1cfc5300dd4c8e12cb4`, branch `research/pq-wkem-validation-20260918`. Inspected latest R396 and exact R395 research notes, and ordinary top-level comments since 2026-11-18T19:24:41Z (none). No Core files/tests, network certificate, real BTC signature, FE, or deployed program were evaluated.

The unfinished R396 object is a polynomial-size *universal accepting sink* for all qualifying ORIGINAL future certificate paths. Here the candidate changes the algebra of earlier commutative local-mask/tensor proposals (R366): use order-sensitive noncommuting matrix products with **independent random gauge per layer**, rather than multiplying local scalars. We construct its fully public encoding and analyze the *joint* view including the encrypted frozen message. The family is rejected by an actual full-public extraction on a FALSE predicate.

## A synthetic public compiler, not an ORIGINAL release construction
Work only in mathematical `GL_2(F_101)` with invertible matrices, NOT a group-based cryptographic fallback. Put `I` for identity,
`U=[[1,1],[0,1]]`, `V=[[1,0],[1,1]]`, and `[U,V]=UVU^-1V^-1`. Construct four layers for the Boolean predicate `R(b)=b AND NOT(b)`:

```
          b=0        b=1
M_1       I          U
M_2       V          I
M_3       I          U^-1
M_4       V^-1       I
```

For either consistent full input `b=0` or `b=1`, `M_1(b) M_2(b) M_3(b) M_4(b)=I`: the full predicate is FALSE. Independently sample `G_0,G_1,G_2,G_3` uniformly among invertible 2x2 matrices, set `G_4=G_0`, and publish BOTH alternatives

```
B_(j,b) = G_(j-1)^-1 M_j(b) G_j .
```

Define the concealed hypothetical accepting group element `K=G_0^-1[U,V]G_0`. To carry a fixed synthetic 256-bit secret `S`, publish `D=S XOR SHA256("noncommutative-mask" || encode(K))`. A prescribed public evaluator multiplying a consistent full input obtains `I` and therefore has no accepted witness for this FALSE relation. The setup nevertheless leaks S.

## Complete-public extraction, with no satisfying input
From the *published* matrices alone form

```
A   = B_(1,1) B_(1,0)^-1        = G_0^-1 U G_0
Z   = B_(2,0) B_(2,1)^-1        = G_1^-1 V G_1
P01 = B_(1,0)                   = G_0^-1 G_1
Z0  = P01 Z P01^-1              = G_0^-1 V G_0
K'  = A Z0 A^-1 Z0^-1           = G_0^-1[U,V]G_0 = K
S'  = D XOR SHA256("noncommutative-mask" || encode(K')) = S .
```

The public extraction uses the *inconsistent* local choices `b=1` at layer 1 and `b=0` at layer 2, without knowing private gauges or any satisfying whole assignment. Noncommutativity and independent layer gauges were genuinely present: the attack is gauge transport and branch-ratio algebra, not R366's commutative balanced-cover multiplication. The entire FALSE public transcript determines S, ruling out a FALSE secret-hiding simulation for this precise scheme even against classical PPT (hence QPT). This says nothing about the general impossibility of source-specific SHA-only release.

## Repair attempted: forward-only state labels
To forbid public inverses, replace group matrices with hidden hash encodings `L_j(s)=H("state"||j||s)`. But a common-state public transition would have to satisfy the exact equation

```
T_(j,b)(L_(j-1)(s)) = L_j(s * M_j(b))      (E1)
```

for all relevant future states s, while neither publishing s nor enumerating the exponential set. The arbitrary SHA hash of s has no known public, compact, homomorphic state action giving (E1). Publishing explicit edges for finitely many states repeats R395/R396's exhaustive-state/future-certificate barrier. Setting `T(L)=H(L||j||b)` gives easy public transitions but loses group-state equivalence and the *same* accepting sink for distinct future paths. A hidden terminal oracle is not public Build/Open. **No cryptographic hash-native action or independent security reduction is instantiated here.** This is an exact unfinished interface, not a black-box ROM impossibility theorem.

## Executed checker and reproducibility
A Python 3 standard-library local checker was actually executed twice, with successful exits and byte-identical JSON. It built eight deterministic randomly gauged FALSE instances, checked both consistent complete inputs yield I, then recovered the 256-bit frozen S from public B and D for all eight instances. It is a mathematical toy check, not source PoW admission, native ECDSA, FE or quantum testing.

Local-only checker `/mnt/data/r397_noncommuting_mask_20261119/check.py`: SHA256 `826a7602f50c3409956ce1df6062a63c12ed88cb656e005c9bb882e793cdf84d`.
Two local-only JSON outputs have identical SHA256 `b08f650f7bfdbecb07c88b5a4864789d2ac8c0914fbf39ae156c6c5a5a508fc3`. These files were NOT published with this note; do not infer durable sandbox persistence from their paths.

## ORIGINAL handoff
**NONQUALIFYING**. The actual missing primitive remains public classical PPT
`Build_orig(x_W,sigma_cancel)->C` and `Open_orig(C,w)=sigma_cancel` for **every** qualifying ORIGINAL witness, with full-public FALSE/hard-TRUE QPT recovery/native-forgery -> an ACTUAL ORIGINAL source certificate or independently justified break. Future proposals must avoid both published matrix branch-ratio algebra and scalar finite covers, and instantiate a practical cryptographically protected universal sink rather than name one. Preserve the original BTC-greater, finite authenticated burn fault, and contextually authenticated Syscoin inconsistency/tag-fault OR; exact claim/UTXO/amount/recipient/native-message/LC-depth/anchor/deadline/reset binding; activated canonical AuxPoW; one-honest N-of-N setup; R225 endpoint portability; malicious source coins and sibling capsules. First-release native BTC ECDSA does not repair the source-dependent public gate.

No breakthrough notification, PR progress comment, other repository/production write, deployment or automation change.
