# R309 — SHA-source degree-bounded projection and fixed-cut repair (NONQUALIFYING)

This is a bounded offline continuation of R308's unfinished source-conditioned `Extend`, starting from PVUGC PR #1 head `61e94fdbfc36ebb8253901ce0321ce4fa93f0519` on `research/pq-wkem-validation-20260918`. R308 blob `94ed2a7fb10962ed501ec0c583613ddfde464cfb`; R307 blob `82973b1a11326bd82e93b8ac2221a46338013f77`; ordinary comment R225 `6796383617`. Core #609 current read-only metadata head `c91539de3c34937e57d7f5fda47c7b0502ff33f6`. No Core test/deployment claim.

The ORIGINAL three-branch OR and complete claim/UTXO/burn/recipient/amount/BTC anchor, contextually admitted modern AuxPoW/exact canonical tag, actual semantic ancestor at h_rel, LC depth, source window/deadline/reset, exact faulty wrapper and native message/VK bindings remain required. One notary initiates; anyone with authentic original evidence challenges. N-of-N is only setup. This fixture DOES NOT implement any of that verifier. R225 native activation portability remains independent.

## Attempted implicit projection instead of an exponential frontier

Try a publicly evaluable **direct** release function `F_C:{0,1}^n -> {0,1}^lambda` in algebraic-normal form, degree <=D per output bit, with `F_C(w)=S` for **every** accepted source string w, where S is a frozen cancellation surrogate. If the accepted-set monomial evaluation matrix `E_A` has full column rank `M=sum_{k=0}^D binom(n,k)`, then every degree-D polynomial vanishing on A is the zero polynomial: writing `F_C(w)=S+Q(w)`, correctness gives `E_A coeff(Q)=0` and full rank forces `Q=0` everywhere. Thus **any raw input, even an invalid source string, retrieves S from a publicly evaluable scalar F**. This attack does not need public coefficients or extraction of a program representation. Its premise excludes systems that do not expose this scalar on invalid inputs; those need a separate full-public analysis.

For an *independently idealized* random accept set of probability p=2^-d, any nonzero degree-D GF(2) polynomial has Boolean support >=2^(n-D). Union bound:
```
Pr[rank(E_A)<M] <= (2^M-1)(1-p)^(2^(n-D))
                <= exp(M ln 2 - 2^(n-D-d)).
```
This ideal-random statement is not a concrete-SHA or ORIGINAL-source theorem.

The executed Python 3 SHA256d checker exhaustively enumerated three **synthetic** 80-byte header families with 14 free nonce bits and a 4-zero-leading-bit toy target. For D=3, M=470. Accepted counts: 1039, 1025, 1021. All three exact GF(2) ranks were **470**. Therefore cubic all-accepted direct response functions are constants on all 14-bit inputs in each tested slice. This is a finite SHA computation only, not Bitcoin best-chain membership or contextual Syscoin consensus.

## High-degree repair and joint-public failure

A proposed SHA target circuit conceals S behind fixed opaque labels `L[i,0]` for each target bit, with
```
C = S XOR SHA256("PAD" || capsuleID || L[0,0] || ... || L[d-1,0]).
```
Correct accepted headers obtain the same target-bit labels and open the same S. But with a publicly reusable evaluator and identifiable cut, an attacker can obtain **each** zero label from a different invalid SHA header where only that particular bit is zero. The executed d=4 regression used patterns `0101`, `0101`, `1110`, `1001`: every source sample failed the complete `0000` target, yet the mixed cut labels recovered the exact 256-bit surrogate. Eight different valid toy headers opened S honestly. The checker simulates the opaque-label cut oracle; it does NOT implement a public garbler or claim actual source labels exist.

Repairing cuts by whole-hash tag `t=SHA256d(w)` and labels `L[i,b,t]` makes separately valid witnesses have different pads: four tested accepted headers had four distinct pads, and one frozen ciphertext opened only the selected one. A future source-dependent correction generator is still missing; a public tag converter revives splicing. This is the same global consistency problem as R288, now checked against actual SHA256d output-bit behavior.

## Unfinished ORIGINAL equation

```
Build_inc(x_W,sigma_cancel)->C  [classical PPT; one frozen safe capability]
Extend(C, authenticated ORIGINAL transition, hidden parent label)
      -> hidden child label
Open_inc(C,w_original)->same sigma_cancel for ALL R(x_W,w_original)=1
```

No classical-PPT source-earned label generator was constructed. No full-public FALSE/hard-TRUE QPT recovery/native-forgery reduction, malicious setup, auxiliary/sibling composition, real consensus admission or native PQ endpoint was established. Neither checking authenticity after secret recovery nor a hash root that authenticates bytes solves this. The next requirement is an actually instantiated compact, nonspliceable source-dependent hidden transition, not another efficient representation of an unrelated hash puzzle.

## Executed provenance

Two final checker runs produced identical SHA256 `1d48d18e46d8944aef5836f003d3962eb4385cf27f1d097dbfe178d26fdb0dfd`. Checker SHA256 `27f7206c4e0cf366ab61895a22c982bfc6dbcb3ff46130b2691fcfa4088b74e6`. At least 49,281 synthetic SHA256d evaluations were observed. Full derivation/checker/output/provenance are archived **locally** as `R309_source_degree_join_20261115.tar.gz`, SHA256 `458a58446b41c61633ee716ff81f9eda372806f5b3b8c6e809242760c6fa9dd7`, and are not claimed committed here. No external web, delegated agent, real consensus test or quantum experiment.

**NONQUALIFYING**. No ORIGINAL hash-only release advance, notification, PR comment, production change or automation stop.
