# Run 486 — false-instance key-recovery hardness implies one-bit witness encryption (known-key setup)

Date: 2026-10-13. Exact live starting head: `7e61b96ffe2d0c10f021a672080ea9188abc63c5`, draft branch `research/pq-wkem-validation-20260918`. Latest ordinary substantive PR comment: 6067040320.

## New scoped implication

This is a Goldreich–Levin **reduction applying an established theorem to the release interface**, not an independent local mixer or a WE construction from LWE. Suppose a classical-PPT honest Build(x) transiently knows a classical n-bit K and outputs its complete public capsule view P. P includes the native public checking key vk(K), all context (relation, claim/UTXO, branch, anchors, window, sighash), public programs, presignatures and classically samplable auxiliary material. Every ORIGINAL-valid w opens the SAME K, even if other intermediate states differ. For an ORIGINAL-false x, assume any QPT attacker given P recovers exact K only with negligible probability. This must be a full-view assumption; merely assuming security with vk or setup auxiliaries omitted is insufficient.

Define for arbitrary message bit b:

```
WE.Enc(x,b): (P,K) <- Build(x); s <- uniform {0,1}^n;
             return (P,s,b XOR parity(K & s)).
WE.Dec((P,s,c),w): K' <- Open(P,w);
                  return c XOR parity(K' & s).
```

Every valid ORIGINAL witness decrypts correctly. If a false-instance QPT distinguisher separates encryptions of 0 and 1, sample uniform c and use its response to predict parity(K&s) given (P,s). The advantage is half the distinguisher's probability gap (with the appropriate response orientation). Apply classical Goldreich–Levin/Hadamard list decoding to this QPT predictor on multiple fresh classical masks s, keeping the *same* P. A nonnegligible advantage yields a polynomial-size candidate list containing K with nonnegligible probability, so choosing a random list element recovers exact K with nonnegligible probability. This contradicts the assumed QPT recovery hardness. No quantum rewinding or QROM programming is required: each measured oracle response comes from a fresh QPT invocation.

If false-instance *native-signature* security prevents fresh accepted signatures on a bound, unpresigned transaction message, then exact K-recovery implies such a forgery (recover K, sign the message), hence it implies the key-recovery premise. This is conditional on the ordinary native verification/signing interface genuinely accepting signatures computed from K.

Therefore a **generic-NP known-key** all-witness SAME-capability release primitive that is QPT-hard to forge on false instances is already strong enough to obtain **one-bit witness encryption**, whether or not its protected release region is small. The statement is **WE-hardness in functionality**, not an impossibility theorem, a concrete resource bound, a proof requiring iO/RIO, or a cryptographic assumption for the proposed mixer.

### Important limits

* A strong public **keyless Build** that cannot compute K even with retained construction coins cannot form the mask bit. This reduction does not establish that such a builder exists or is safe. Original honest N-of-N known-key setup may be simulated centrally for this theorem; actual abort/erasure/graph security remains unproved.
* Correlated vk does NOT make raw K real-vs-random; the reduction needs only **key recovery hardness**, which GL converts to hardness of the parity bit. The public checking key is retained throughout.
* Uniform QPT and polynomially repeatable/independently preparable nonuniform quantum advice are covered. A unique non-clonable **setup-correlated quantum auxiliary state** is not automatically covered by the repeated-invocation decoder, and requires an additional theorem. Coherent evaluation of published classical programs by attackers is permitted.
* Independent per-bit capsules give longer messages by polynomial hybrid loss only if all joint auxiliary views are simulatable. Related-key/multi-branch capsules, malicious setup, one-time honest erasure and retained secrets are NOT established.
* True-instance key/signature -> accepted COMPLETE representation -> ORIGINAL witness is NOT derived here. Run 259 remains downstream and requires its exact source representation interface.
* No claim of 128-bit concrete security or a working local mixer, PQ native signature, CLZ/RIO instantiation, or completed WKEM. Bitcoin remains ordinary native signature/graph only.

## Falsification / attack scope

Chosen-input and coherent public evaluation are allowed in the full-view QPT recovery game. If a seam, statistical fingerprint, frame/gauge synchronization or chosen-input attack recovers K, that candidate fails the **premise**; GL does not defend it. Malicious setup revealing K, reuse of K across true/false capsules, or auxiliary copies containing source witnesses also invalidate the premise. Cross-UTXO binding is necessary but not proved by this theorem. The quantum aspect is reduction to a QPT parity distinguisher with fresh measured calls; this is not a newly discovered coherent quantum attack on local mixing.

## Executed finite diagnostic

`run486_compact_check.js` passed 15 assertions and two byte-identical Node executions. An independently executed extended Python checker passed 2,581 assertions and complete joint-distribution census. Both use an insecure 8-bit toy secret with a public view revealing its upper bits. For h unknown low bits, exact key-guess success is 2^-h, GL parity prediction advantage is 2^(-h-1), and encryption-bit total variation is 2^-h. These finite distribution identities are NOT evidence for cryptographic one-wayness, QPT security or an actual release protocol.

Exact dependencies read at starting head: Run 485 `f06dff5e11359bd3817fb90125f4d817435f72b7`, Run 483 `0933013687e3f39d7a6c4dc9e733d5b203d03f72`, Run 482 `20349ba98e4d598a4adb5e18fda9736d7e9f1f90`, Run 259 `c7f3b77f0273ca1cbe6f0b31c1a086b8eb3acbf2`, and CLZ assessment `c19d9d9cd515140e3ce62eac960cd548c0add622`.

Literature: Goldreich–Levin (STOC 1989) hard-core predicate and Hadamard decoding; Adcock–Cleve, *A Quantum Goldreich-Levin Theorem* (arXiv:quant-ph/0108095); the original GG-S-W witness encryption definition (STOC 2013); Canetti–Chamon–Mucciolo–Ruckenstein TCC 2024 local mixing (architectural context only).

**Handoff:** The genuinely protected relation-dependent release primitive is still missing. A claimed weakening from message hiding to native-key non-recovery does not escape one-bit WE under known-key setup. Future constructive focus: independently justified source-aligned local release with arbitrary-QPT false hiding and native authorization -> complete ORIGINAL representation or an independent QPT break. No practical WKEM; draft/unmerged; production unchanged.
