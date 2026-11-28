# R288 — Global witness-tagged SHA labels: one-gate completeness gate (NONQUALIFYING)

## Continuation and claim

Continues the exact unfinished repair in `research/pq-wkem/composition_correction_garble_20261114/RESEARCH.md` at blob `72d36b9c2d8c1e3b82200e162e6b63e03ebe2732`. Starting PVUGC PR #1 head `c338d9a3595272ed5cb9389f142edc6cdfae004a`, open draft, branch `research/pq-wkem-validation-20260918`; Core #609 metadata `c91539de3c34937e57d7f5fda47c7b0502ff33f6`. Most recent substantive ordinary issue comment remains R225 #6796383617. No production changes, Core test run or QPT experiment.

The preceding composition failed by combining internally consistent subcircuit labels from different hypothetical source witnesses. This iteration attempted to *eliminate the reusable cut* by tying each wire label to one common digest `t=SHA256(domain||x_W||canon(w))` of the **complete authenticated** ORIGINAL certificate. The canonicalization must preserve actual ancestor-hash comparison at `h_rel`, distinguish same-child alternative Bitcoin parent carriers from forks, and separately bind the faulty claimed wrapper; exact modern contextual AuxPoW admission, source windows/depth, and claim/vault/native message cannot be dropped. A hash of raw user-selected bytes is not a source credential.

## Concrete attempted repair

Sample independent hidden gate/wire seeds `s_v` and define for a binary gate g with input wires u,v and output o:

```
L[v,b,t]   = Trunc_lambda SHA256("L" || v || b || s_v || t)
R[g,a,b,t] = L[o,g(a,b),t]
             XOR Trunc_lambda SHA256("PAD" || g || L[u,a,t] || L[v,b,t])
```

With correct active input labels **and a tag-specific row**, an honest gate evaluation returns the label of the same tag `t`. Labels at unequal tags do not splice in the naive fixed-label way. This is the limited constructive property being tested, **not** secret release, not every-witness completeness, and not a SHA QPT theorem.

### Exact fixed-row feasibility lemma

Condition on noncolliding domains and independent random-function outputs. If `R[g,a,b,t0]` is the single row published at setup and `t1 != t0` is independently sampled, the fresh output label is uniform independent of the fresh pad and static row, hence

```
Pr[R[g,a,b,t1] = R[g,a,b,t0]] = 2^(-lambda).
```

Therefore one fixed row ordinarily fails to decrypt a future source-tagged label correctly. The argument is *only* for this SHA-label/two-input-gate construction in an ideal-independent-hash experiment. It is not an impossibility theorem for SHA-WE, programmable RO/QROM, arbitrary obfuscation, or original-source KEM.

### Joint-public repair attempts

* **Make all seed/row derivation public:** anyone derives BOTH logical input and accepting-output labels at any fabricated tag. A later `CheckSource(w)` does not retract the already extracted authorization.
* **Make labels publicly tag-convertible:** when `L[v,b,t]=B[v,b] XOR Delta(t)` and `Delta` is public, a recovered label at `t0` converts to `t1` using `Delta(t0) XOR Delta(t1)`. This restores cross-witness splicing. Public nonlinear `Delta` has the same problem.
* **Keep a secret dynamic row generator:** future arbitrary authentic source tags cannot evaluate it without an additional noninteractive source-dependent release mechanism; postulating that generator is the original missing primitive, not a hash-only instantiation.

The specific outstanding question is whether the *actual authenticated SHA/AuxPoW history* can provide a cryptographically useful, nonforgeable public source credential with which a frozen, polynomial-size hidden-key evaluator can operate at every qualifying future witness while not operating at invented witness transcripts. None of these formulas construct such a credential or an independent QPT extraction.

## Executed evidence, deliberately limited

Two independent executions of a Python 3 standard-library SHA256 checker on 128 synthetic 16-byte tags produced byte-identical output, 1,116 assertions each: 4 correct baseline rows, 508 mismatching static future rows, 508 functioning **private** future row computations, 64 public-seed accepting token recoveries without source, and 32 public-delta transfers. SHA256 checker `f7786d883492b7fc3e18e93bdf4e74217f912ac9ea01c17f60a30c0ccc6dedcd`; output for both runs `fcadf6f531e17f92cd913f24b1ba6a6aee4573b65f44d486d7c53a30ad363984`. A complete local archive (source, two outputs, derivation, provenance) is `R288_global_witness_tweak_20261114.tar.gz`, SHA256 `800b22ca33c29322efcf0628700ee4fe6e019c321f9d402a1c140ed1c6b2549d`; this archive is a local conversation artifact, **not** committed to this repository. The recorded tests do not implement authenticated Bitcoin/Syscoin headers, live consensus, native SLH signatures, or quantum algorithms.

## Exact original unresolved obligation

Construct actual classical-PPT `Build_inc(x_W,sigma_cancel)` and public `Open_inc(C,w)` for ALL qualified ORIGINAL challenge witnesses (qualified higher-work BTC history, authenticated particular burn defect, or relevant qualified Syscoin inconsistency/tag fault), yielding the SAME frozen safe cancellation capability. Full-public FALSE and unauthorized hard-TRUE QPT recovery or accepted native forgery must straight-line imply an ACTUAL ORIGINAL qualifying source certificate or an independent PQ hash/native break, with full auxiliary and sibling-capsule information and malicious setup. Do not assume a source signer, online authority, exposed PRF secret, NP proof on Bitcoin, enumerated future history, or generic assumed WE/iO. This iteration does not reduce that foundation gap.

No ordinary PR comment or completion notification is warranted. Research automation remains enabled.