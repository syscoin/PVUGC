# R207 — Constraint-ideal all-witness release: full-public extraction

**Classification: genuine concrete hash-only Build/Open-shaped attempt and attempted SHA-based repair, but NO ORIGINAL bridge release, no new secure primitive and no QPT proof.** This is an adversarial regression of the previously recorded affine/low-degree closure weakness, not a breakthrough.

## Provenance and continuity

Repo syscoin/PVUGC, existing draft/open PR #1, branch `research/pq-wkem-validation-20260918`. Observed start `8dce731601be2a19d36b57158721ab771a9f7150`, source tree `17aca8a999d0e037a7637096a1a936076b59d3f5`. Exact R206 RESEARCH.md and CHECKPOINT_01.md read at that head; ordinary PR comments since 2026-11-10T17:00Z were empty. Local genuine intermediate checkpoint was written before checker execution. Intermediate published commit `cfa57b33383c8166731bd12e3b020524bc0149de`, direct parent of this final research commit. No web/external literature, independent subagents, source-code changes or production implementation. No native PQ signature, QPT simulator, mining run or Bitcoin/Syscoin full verifier was executed.

Local full generic-coefficient checker `checker.py` was executed twice with byte-identical output, 724 functional checks; SHA256 source `faacfa6ba3bce8ba82f6cbdb7d3aa9e7d1237b7a3ccc2b6dc1948c0fb335bb00`, output `ad06d7816f3581b9e4725bf6822053f8ebbda2879ba4504aa2afb2df6fd66d9b`. It is retained locally, NOT claimed uploaded in this GitHub commit. The compact `repro.py` and `repro_output.json` attached to this commit WERE independently executed twice locally with byte-identical output, 512 assertions. Source SHA256 `86bbac93d46920f318c6c9f742aed4e1f6a05a6051b4628dd924c2b641ed5399`; output SHA256 `b9da6fdd0d1f04c308df40c7bb2e140072dfe53c65b896458f1947742d67422f`. Their exact bytes must be read back before claiming successful publication. Synthetic SHA-like Boolean gate only, not a production verifier.

## Chosen ORIGINAL-dependent candidate

For each exact withdrawal x_W, the intended ORIGINAL relation is a selected OR of (1) authenticated more-work BTC rival, (2) the exact invalid/missing claim-bound PoB, or (3) a qualified authenticated claim-prefix SYS fork/AuxPoW tag fault. The full real witness circuit must bind actual BTC/SYS SHA headers, parent coinbase/Merkle links, parsed tags, ancestry, work/height windows, relevant source state, claim/UTXO, cancellation path/message and native VK. The toy experiment substitutes only small Boolean/SHA-like constraints; nothing about it authenticates actual original evidence.

Write the real relation as field polynomial equalities `f_j(z)=0` over the Boolean witness/trace variables z, including all source checks, disjunction selector and Booleanity equations. The candidate is:

```
Build(x_W,sigma):
    sample uniform secret field K, random polynomial masks r_j from
      a polynomial-dimension, publicly specified mask space M
    publish explicit coefficients of P(z)=K+sum_j r_j(z)*f_j(z)
    publish D=sigma XOR H_pad(x_W, encode(K)), checking key, native VK
Open(C,w):
    derive trace z from the ORIGINAL authenticated evidence w
    k=P(z)
    return D XOR H_pad(x_W,encode(k)), accepting only native VK/message match
```

**Exact all-witness correctness:** for ANY qualifying original z, every constraint vanishes so P(z)=K, irrespective of fork header, proof randomness, SHA hash outputs or which R1/R2/R3 branch is satisfied. Distinct valid witnesses therefore yield the SAME frozen key. This is the one property R206's future point-lock lacked, but it does NOT make the candidate safe.

## Deterministic full-public quotient attack

Let `V=span_F{f_j*m : m in public mask coefficient basis}`. The published coefficient vector p is `p=K·1+v` for some `v∈V`. For every satisfying assignment z*, evaluation E_z* satisfies E_z*(1)=1 and E_z*(V)=0. Therefore 1 is NOT in V if a true witness exists. The full-public adversary computes by Gaussian elimination a *different*, explicit linear functional ℓ on coefficient vectors with ℓ(V)=0 and ℓ(1)=1. It then obtains ℓ(p)=K and unmasks the native capability WITHOUT original witness, submitted representation, oracle trace or hash break. This works in time polynomial in the publicly encoded coefficient space size. The extraction is classical, hence an arbitrary QPT adversary can use it too. It applies to the proposed openly spanned mask family, NOT all possible SHA circuit encodings.

For the synthetic SHA-like AND/conflict constraints over F_257:

```
a²-a=b²-b=c²-c=0, c-ab=0, a+b-2ab-1=0
P=K+r0*(a+b-2ab-1)+r1*(c-ab)
   +r2*(a²-a)+r3*(b²-b)+r4*(c²-c)
```

Both (a,b,c)=(0,1,0) and (1,0,0) are valid, and P evaluated at each equals K. Yet any public viewer extracts `K=(C_const+C_a+C_a²) mod 257` from its coefficients; the 128-seed compact checker verifies both same-key openings and unauthorized extraction of a synthetic sealed 32-byte cancellation capability.

For the FALSE relation `a=0 AND a=1`, 1 is in the mask span and uniformly distributed masks can statistically hide K. FALSE hiding does not imply secure hard-TRUE recovery. No claim of statistical security as a prerequisite for general WKEM is made.

## Repair 1: nonlinear SHA-seeded mask sampling (tested, fails)

Pick r_j mask coefficients using secret `SHA256(seed||j)`. The public P still lies in the SAME affine coefficient coset K·1+V. The public ℓ kills V regardless of how unpredictably its coefficients were sampled. The local full generic checker exercised 80 independent SHA-seeded capsules and recovered K and the frozen synthetic capability without any witness. The compact published checker also uses SHA256 to derive mask coefficients, so its extraction is not an attack on a toy RNG. This precise family fails even with an ideal secure hash and perfectly hidden mask seed.

## Repair 2: nonlinear hash-valued masks / hidden evaluation (uninstantiated)

Try `P(z)=K+sum_j f_j(z) SHA256(seed,j,z)` or `P(z)=K+H(sum_j f_j(z)r_j(z))` to escape the public linear coefficient quotient. A transparent public computation exposing K or hidden seed trivially reveals them. Keeping them committed/secret prevents a permissionless watcher from evaluating P(z) using an arbitrary actual source witness. Publishing a polynomial number of explicit source-point evaluations does not ensure all future qualified headers open; publishing all 2^n witness-indexed evaluations is exponential in general. Merely promising an obfuscated evaluator, constrained public PRF, ideal release oracle, programmed QROM or separate label issuer is not a concrete hash-only compiler. The missing subalgorithm is a **succinct publicly evaluable yet nonlinearly protected all-witness encoding** together with the full-joint QPT simulator/extractor. No such construction was instantiated in this run.

## Required end-to-end properties remain missing

One notary activates a claim inside an N-of-N preauthorized covenant-emulation graph, ANY watcher with ONE authenticated ORIGINAL challenge must be able to obtain the SAME pre-signed, claim-scoped native cancellation authorization OFF CHAIN, without live quorum approval. Bitcoin sees only a native signature, not a ZK verifier or BitVM/PCP/VM dispute. Every relevant source interval tag and qualifying BTC/SYS history must be authenticated, including relative-work qualification for R1 and positive claim-prefix inconsistency for R3; distinct parent work for the SAME child is not a fork. N-of-N participants must not be able to bypass or publish unopenable capsules after funding. False-instance and hard-TRUE arbitrary QPT recovery/forgery must reduce to actual ORIGINAL evidence or independently justified PQ hash/native break, against correlated checking keys, malicious setup, auxiliary data and related capsules. These are NOT proven by the present algebraic tests.

**Conclusion:** R207's same-key source-constraint carrier has a reproducible, unconditional full-public extraction; SHA-PRG coefficients do not repair it. The exact next constructive obligation is a concrete *nonlinear public witness-evaluation encoding* that avoids the exposed polynomial quotient, while retaining authentic SHA/AuxPoW witness binding. No routine PR progress comment or user notification is warranted.
