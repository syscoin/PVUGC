# Quotient-normalized SOURCE with small quotient noise: rejected release repair

2026-10-31, scheduled research turn 11. This is a **negative supporting note**, not constructive PQ witness-KEM progress. Exact `syscoin/PVUGC` PR #1 head before this work: `fb8d26f6e2075266acba9899b7108b4c476c0452`, branch `research/pq-wkem-validation-20260918`, open/draft/unmerged. Latest ordinary substantive comment inspected: `6541909013`. No external literature or internet research; only authorized GitHub continuity reads.

## Attempted witness-free ORIGINAL-dependent compiler

Let F be a 3CNF and D∈F_q^(m×T) its public degree-d Boolean-violation matrix, e the constant-monomial vector. This modifies the previous `degree4_polymask_20261031` and `full_public_linear_leak_20261031` scheme at the *source-generation/noise* layer, rather than assuming a SourceOpen oracle. For e outside rowspan(D), choose a public full-row-rank basis Q of span(e,rowspan(D)), first row e. The compiler samples u,R,S,s uniformly and centered small xi,etaStar. Publish B=u e^T+RD, c=B^T s +g(ke+D^T S)+Q^T xi, t=u^T s+etaStar (mod q), plus the actual relation, statement, claim/UTXO, branch, anchors/window/context, native verifying key, allowed auxiliary information and related capsules. The hidden native master is 512 bits in the intended variant; the checker treats individual bits and does NOT execute native signatures.

Every true ORIGINAL Boolean witness W has D v(W)=0,e^T v(W)=1 and therefore Q v(W)=(1,0,...,0). The public offline Release applied to that witness yields v(W)^T c-t = gk+xi[0]-etaStar modulo q. Thus distinct legal witnesses recover the SAME K when the centered noise fits the decoding margin.

## Exact public extractor, destroying FALSE and hard-TRUE security

**Public Gaussian elimination**, without any ORIGINAL witness, finds v0 from D v0=0 and e^T v0=1 whenever e∉rowspan(D). No Booleanity, shortness, submitted representation, extraction oracle, or quantum computation is required. Because Q v0=(1,0,...,0), the actual complete joint source distribution satisfies

    v0^T c-t = (Bv0-u)^Ts + g(k e^T v0+S^TDv0) + v0^T Q^T xi-etaStar
             = gk+xi[0]-etaStar mod q.

With quotient-coordinate small noise, the public nonwitness decodes identically to every genuine witness. This refutes the contemplated uniform-quotient ordinary-QPT-LWE pad hybrid: an LWE challenge simulator cannot both preserve this full-public identity and hide its bit. The failure already works for ONE capsule; real checking-key correlations, auxiliary data, related capsules or quantum coherent attacks cannot repair it.

The already-certified FALSE subclass e∈rowspan(D) from the previous theorem is unaffected but does not cover arbitrary FALSE. The source matrix is still visibly structured. Replacing Q^T xi with original-coordinate small noise restores a possible *noise-norm distinction* between a true 0/1 v(W) and a dense v0; it does NOT establish security. In a separate n=6,d=4 12-clause TRUE toy we obtained 10 valid witnesses, each recovering the intended bit in 1,000/1,000 releases, while a public non-Boolean v0 (not one of the ten witness monomial vectors) also recovered 100/100 trial bits, with centered l1=7. Do not present that toy as a hard-TRUE QPT attack.

## Executed exact checker, QPT model, open obligations

`checker.js` is the executable source of the exact function executed before publication; `output.json` captures its deterministic result. It uses q=65537,g=4096,n=5,d=3,T=26,ell=7, 10-clause known FALSE F10 (zero satisfying ORIGINAL assignments), an independently sampled complete (u,R,S,s,B,c,t) per bit and quotient-aligned small noise. It checks public Gaussian-elimination extraction on 512 bits. The separate downloaded local research archive additionally contains three full Python checkers, two identical executions of each, an ambient-noise repair probe and extended provenance. These scripts are toy finite-field identity checks, not cryptographic hardness assessments. Source-only equality of the joint distribution does not imply genuine native signature security, and native EUF-CMA cannot save a capsule whose secret master is already public.

Target adversary: arbitrary nonuniform QPT, all public relation/claim/context/vk/aux/multiple-capsule outputs, optionally classical disclosures. Honest compilation/release remain classical PPT for fixed d. Since the attack is classical PPT and breaks the basic public output, no appeal to ordinary QPT-LWE, SIS, PRG, native signature EUF, rewinding or extraction can establish the required false/hard-true theorem for this attempted noise distribution.

**Next exact missing equation:** jointly instantiate an ORIGINAL-dependent source compiler and public Lift from EVERY true ORIGINAL witness to the SAME K, but with a full-public challenge simulator that cannot be inverted by arbitrary publicly computable non-Boolean states; then prove arbitrary unauthorized final-key recovery/native forgery yields an actual ORIGINAL witness or independent QPT break. Ambient monomial noise was tested, not proved as a fix. Malicious one-honest N-of-N setup/abort/DA, SYS/BTC qualification and hypothetical PQ-native Bitcoin endpoint remain unresolved. No complete WKEM and no deployment recommendation.

Continuity files read at exact version: `full_public_linear_leak_20261031/RESEARCH.md` blob `2f1b77e08dab630a1b2df349950185d02263e1f2`; `degree4_polymask_20261031/RESEARCH.md` blob `cede7a438ecea7d0705e264679ab8ba24796425f`; F10 from exact `degree4_polymask_20261031/checker.js` blob `ddfb2e39c53fe88fbdd607b108cf856c06d1ddd0`.
