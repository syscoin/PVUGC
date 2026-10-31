# Paired-binary witness-free SOURCE: bounded-noise repair test and uniform-source density obstruction

**STATUS: NO positive secure witness-KEM construction advance.** This is one offline, resource-bounded continuation of the exact paired-binary 3CNF compiler, not a claim that the full-public SOURCE is secure. It establishes (i) a general error-scaling failure for that release family and (ii) an unconditional statistical incompatibility between *exact false-source soundness* and the prior densely populated uniform-SOURCE statistical hybrid. Both are supporting diagnostics for the unresolved arbitrary-ORIGINAL-NP release compiler, not a new cryptographic primitive or proof of its security.

## Exact version/provenance

2026-10-29, existing scheduled research task (automation turn 11; no separate execution UUID supplied); repository `syscoin/PVUGC`, open/draft/unmerged PR #1, branch `research/pq-wkem-validation-20260918`, starting observed head `02708af2b75e38c18fa97f26ff965a085774c3f3` (before publication). Last ordinary substantive comment `6492985342`. Exact prior input `research/pq-wkem/paired_binary_np_source_20261028/RESEARCH.md` at commit `760dc50adaafa4fe7fc591dee9dff0e4f81b0945` (blob `edfa385fcec0bfaf915f309d41c349cd3c355a40`); `research/pq-wkem/preA_classical_leakage_20261029/RESEARCH.md` at starting head (blob `435c927931148a02f44667a2e35ab98fc3fdc81a`). No outside web, literature, or unrelated repository browsing. No new literature assumption.

## Named candidate: independently amplitude-scaled bounded-error dual-LWE release

Recall the *public, witness-free* 3CNF paired-binary source. For a formula with v variables and c clauses define `N=v+2c`, `m=2N`, `n=N+c`. For every one of N pairs of source coordinates, require `w_{k,0}+w_{k,1}=1 mod q`. For each clause count its three satisfied literal occurrences and include slack pair coordinates `u+2z`, equating the sum to 4 modulo q. Fix `q>4N+7` so each accepted L1-`<=N` opening is genuinely 0/1 one-hot, hence projects to an ORIGINAL satisfying assignment. Conversely every ORIGINAL satisfying assignment gives an accepted source opening. The SOURCE is `(A_x,U_x)` computed from `(R,x)` **without** any planted witness.

The previous ciphertext used bounded errors in `{-1,0,1}`. Test its most direct noise repair: choose any public integer amplitude `B>=1`, independent errors `e_i, epsilon` uniformly in `{-B,...,B}`, fresh `s` uniformly over `F_q^n`, and set

```
  g = 2 B (N+1) + 1;  T = floor(q/g) >= 2
  c = A_x^T s + e              (mod q)
  d = U_x^T s + epsilon + g a (mod q)
```

Every accepted short opening w deterministically decodes digit a, since

```
  d - w^T c = g a + epsilon - w^T e  (mod q),
  |epsilon - w^T e| <= B(N+1) < g/2.
```

The centers `g a`, for `0<=a<T`, have cyclic modular separation at least g; off-chain nearest-center decoding is exact. All accepted ORIGINAL witnesses (not a canonical witness) therefore still release **one identical precommitted K**. The full public view would still contain statement/relation, claim/UTXO/path/window/context, all ciphertexts, actual independent native checking key, XOR masks, auxiliary information and related capsules. The repair is tested *against that whole-key condition*; the native key used in checker is only a mock uniformly sampled 256-bit capability, not an implemented SLH-like signature.

## Why amplitude scaling cannot repair this specific compiler

Take the fixed FALSE 3CNF containing for each of v variables both clauses `(x_i OR x_i OR x_i)` and `(NOT x_i OR NOT x_i OR NOT x_i)`; c=2v. Every ORIGINAL assignment fails exactly f=v clauses, so no accepted L1-`<=N` SOURCE opening exists. Nevertheless a public algorithm chooses ANY assignment and uses valid one-hot slack values on satisfied clauses and malformed `u=(-1,2), z=(0,1)` on each failed clause. Its unaccepted pseudo-opening w* obeys **exact integer** equations, not just modular ones:

```
  A_x w* = U_x,
  ||w*||_1 = N + 2f,       ||w*||_2^2 = N + 4f.
```

Consequently the attacker computes on the published ciphertext directly:

```
  d - (w*)^T c = g a + epsilon - (w*)^T e (mod q)
```

without volunteering a short representation, running Release, finding an ORIGINAL witness, breaking DecLWE or forging a signature. For centered independent bounded errors, Hoeffding gives per-column attack-decoding failure at most

```
  2 exp[ -(g/2)^2 / (2 B^2 (1 + N + 4f)) ].
```

For L ciphertext columns (fixed radix length per 256-bit XOR share, three shares) the complete-secret attack fails with probability at most

```
  2 L exp[ -(g/2)^2 / (2 B^2 (1 + N + 4f)) ].
```

Because `g/2>B(N+1)`, this exponent is *strictly larger* than `(N+1)^2 / (2(1+N+4f))`, **independently of B**. Increasing bounded-noise amplitude while retaining worst-case every-witness correctness cannot remove the public pseudo-decryptor. At `v=32`, `N=160`, `f=32`, `||w*||_1=224`, `||w*||_2^2=288`, `q=1000003` prime, B of 1,8,128,1024 gives theoretical log2 upper bounds on WHOLE-KEY ATTACK FAILURE of -57.9931,-57.2575,-56.3100,-54.7747. All four actual whole-key mock recoveries succeed from both tested public pseudo-openings. These are attack success bounds, never legitimate scheme security levels.

Naive repeated contradictory clauses cannot repair this pair encoding. If each contradictory pair is repeated r times, c=2vr, N=v(1+4r), f=vr, `||w*||_2^2=v(1+8r)`, while the above Hoeffding exponent grows asymptotically as `v*r`: the public attack becomes **more** reliable. The executed checker verifies the finite identities r=1,2,4,8; it does not claim that arbitrary PCP amplification or nonlinear globally bound constructions are impossible.

## Joint public source-density lemma (separate, exact proof obligation)

A distinct obstacle affects attempts to reuse the *statistical* honest-planted SOURCE hybrid on EVERY fixed FALSE arbitrary-NP statement. Let S be any set of N distinct `w` modulo prime q in `F_q^m`. Sample `A <- F_q^(n x m)` and independent `U <- F_q^n` both uniformly, and count

```
  X(A,U) = #{w in S : A w = U}.
```

For each w, `Pr[A w=U]=q^-n`. For each distinct w,w', `Pr[A w=U and A w'=U]=q^-2n`: condition on `A(w-w')=0`, probability `q^-n`, then choose U matching Aw, probability `q^-n`. Thus

```
  E[X]   = N/q^n,
  E[X^2] = N/q^n + N(N-1)/q^(2n).
```

The second moment inequality gives

```
  Pr_uniform[there exists a short w: Aw=U] >= N/(N+q^n-1).
```

For a fixed FALSE ORIGINAL x, any exact sound compiler whose published (A_x,U_x) has **no** accepted short preimage lies entirely outside this event. Thus its SOURCE distribution must have statistical distance from uniform `(A,U)` at least `N/(N+q^n-1)`. In the previous illustrative planted regime (`q=65537,n=128,m=1600,h=800`, `log2 N=2770.7394`, `log2 q^n=2048.0028`), that bound is greater than approximately `1-2^-722.7366`. The honest-planted statistical closeness to uniform is therefore **not transferable** to a SOURCE compiler that is both fixed-false sound and witness-free. This does NOT rule out computational indistinguishability of planted and no-short-opening outputs, nor prove computational hardness of the support predicate; it rules out *that particular statistical LWE-hybrid shortcut*.

Independent exact enumeration for `q=7,n=1,m=3,h=2` has |S|=18 and 2,143 of 2,401 uniform (A,U) pairs with a short opening (0.8925), exceeding the theoretical lower bound 18/24=0.75. First and second moments were checked exactly as rational identities.

## Executed checkers, scope and next handoff

The committed self-contained `check.js` is the exact file executed twice with byte-identical `check-output.json`: PASS 16 mathematical assertions. A larger **LOCAL-ONLY** standard-library Python `check.py` was executed twice with byte-identical `output1.json`/`output2.json`: PASS 2,350 assertions. That checker constructs the actual sparse A,U and valid/invalid source vectors, synthesizes fresh uniform s and independent bounded e, encrypts fixed-length radix digits of three XOR shares of 256-bit mock K, and verifies full K recovery by two DIFFERENT public FALSE pseudo-openings for B=1,8,128,1024, plus two distinct accepted valid witness openings in a TRUE multi-witness fixture for B=1,128. It checks exhaustive three-variable FALSE assignments, replicated-clause parameter identities and exact finite-source moments. Initial local Python harness accumulated recovered share integers instead of XORing them and failed a whole-key test; corrected before the two final identical runs. No actual QPT experiment, certified concrete 128-bit parameters, native SLH signature implementation, BTC covenant emulation, SYS/BTC evidence, setup graph or malicious ceremony was tested. No arbitrary-QPT proof is claimed for the failed compiler.

**No security repair and no arbitrary-NP WKEM advance.** Next exact requirement remains a classical PPT witness-free `Comp(R,x,claim,path,window,context,pk)->(SOURCE,capsule)` and `Phi(R,x,W)` such that every valid ORIGINAL W is accepted and releases SAME precommitted K; every fixed FALSE x hides K in the COMPLETE jointly correlated public view against arbitrary QPT; and arbitrary unauthorized hard-TRUE K recovery/fresh intended-native forgery yields an **ACTUAL ORIGINAL witness** or independent QPT break, without assuming an adversary-supplied internal representation. Any proof using uniform `(A,U)` for a false-source hybrid must address the statistical-density obstruction *and* pseudo-decryptors, not merely increase LWE error. The restricted planted dual-LWE and pre-A leakage lemmas remain usable only in their documented models; they do not instantiate the missing compiler. One-honest N-of-N preauthorization/abort/erasure/DA, authenticated SYS/BTC PoW evidence and the hypothetical native no-EC-key-path PQ Bitcoin endpoint remain unresolved. **Do not disable the automation.**
