# R339 — semantic source-credential labels: splice-to-certificate obligation (NONQUALIFYING)

## Execution/provenance
Read open draft syscoin/PVUGC PR #1 at branch `research/pq-wkem-validation-20260918`, head `79734d931f9f49f055b2215ddc58a1e6033d4656` (R338), with head tree `32828d95fdbab69c24f10fff7257dd8266de79a0`. Read exact R338, R337, R336 and R335 commit research notes and latest PR top-level comments; R225 is still the latest substantive ordinary comment. No Core source read or Core test invoked this execution, no external search, no native signing, no original live certificate, no QPT experiment. This is a paper-only candidate-selection iteration, not a release claim.

## Selection criterion and what is changed
R337's static SHA-garbled verifier leaks TRUE output on a FALSE instance if the attacker gets both fixed input labels for a single variable using fabricated source strings and locally splices gate paths. R338's transparent high-degree sparse polynomial evaluator leaks the secret from its published coefficients, without input labels. Do NOT optimize either representation.

The distinct possibility investigated here is to **make access to each semantic input label require a *separately authenticated and mature original source certificate***, so that some apparent splicing strategies are *themselves* qualifying source challenges rather than unauthorized uses. This is not a proposed private issuer or a relaxation of source evidence: the needed issuerless, serialized public access mechanism must be built, not postulated.

For a fixed claim-prefix instance x_W, let a qualified source observation R name a complete contextually checked source history, exact claim/window/anchors, claim-relevant child-ancestor height h_rel and hash a(R), and the actual LC maturity. A Bitcoin parent certificate identifying a child hash and another parent certificate identifying the SAME child hash are NOT conflicting semantic observations. Let H_Q(R,R') denote: both are authentically qualified and mutually relevant within the original branch-3 scope, and their actual semantic ancestor hashes at h_rel differ, with a checked predecessor path when reference heights differ.

**Limited semantic implication (not a WE theorem):** If a public label oracle could issue unforgeable, certificate-extractable labels tagged by complete `(claim,h_rel,a(R),maturity,source-anchor)` and an adversary obtained two labels from qualified R,R' for *incompatible actual ancestors* in the same allowed claim-prefix scope, then the attached records R,R' themselves are an ORIGINAL branch-3 challenge witness. This implication fails for:
- two different Bitcoin parent certificates of the SAME Syscoin child;
- two tag records which refer only to an older shared ancestor before the fork;
- an unmatured or contextually invalid wrapper;
- a post-claim divergence outside h_rel's restricted scope;
- different heights with no authenticated predecessor relation;
- fake records admitted because the label generator treats a plaintext verification check as security.
It does not select a winning Syscoin branch or require greater Syscoin work. This only characterizes a desirable shape for *extracted certificates*, not security of arbitrary label recovery.

## Attempted actual Build/Open and precise stop point
Try ordinary hash-garbled global source verifier gates. Builder samples secret wire labels k_(i,0), k_(i,1), a hidden TRUE output label u_1, and freezes the exact safe native cancellation capability S. It publishes garbled tables G and CT=S XOR SHA256("cancel"|x_W|u_1). To open on ANY approved original witness W, a public algorithm must recover the one required static label k_(i,b_i(W)) on every input from the source certificate while revealing no arbitrary invalid-wire combination that opens CT.

A natural source-dependent translator is:
  t(W)=SHA256("original-source"|x_W|encode(W)),
  e_i(W)=SHA256("ephemeral-input"|t(W)|i|b_i(W)),
  tau_i(W)=k_(i,b_i(W)) XOR e_i(W).
Public Open would compute k_(i,b_i(W))=tau_i(W) XOR e_i(W).
This is a NOT-YET-SERIALIZED interface. Builder cannot precompute tau_i(W) for all future unpredictably mined qualifying original W in polynomial bytes. Publishing a translation callable on arbitrary W (including unqualified fake W) reveals both static input labels from two chosen fake strings, and then the known R337 splice obtains u_1 without any original source challenge. Concealing the translation key in an ordinary inspectable public circuit is not a hash-only implementation. A plaintext `if VerifyOriginal(W) then return tau` includes the private translation key in public code. Deriving input labels only as SHA256(t(W)) without the translator changes them with every W and does not decrypt the builder's frozen garbled tables. The different semantic source-credential tag prevents *misclassifying* source evidence, but provides NO cryptographic protection of private labels.

The joint public simulation also fails to be instantiated: ideal independent hidden wire labels plus no accessible translation could have a restricted FALSE hiding argument, but the actual published translator is absent; adding its arbitrary-W evaluator already gives a classical FALSE attack. A simulator that hides this gap by taking a secret source-label oracle as input would simply assume the desired release mechanism. There is no QPT reduction from an arbitrary key-recovery adversary to ORIGINAL source certificates, nor a proof for native VK/signature correlations or opened sibling capsules.

## Endpoint / handoff
**No source-dependent classical-PPT public Build/Open, no ORIGINAL-source breakthrough, no demonstrated hard-TRUE/FALSE QPT security.** The candidate is stopped before synthetic test inflation; R337 already supplies a concrete FALSE splice test, and the semantic implication here does not require a synthetic Core fixture. In particular the old R316 equal-tag example is NOT evidence that the strict light client misses a mature fork; the actual semantic histories/coverage must be checked.

The next *unconstructed* equation is a setup-time polynomial-size inspectable hash-only capsule component `T_C(W,i)` for arbitrary FUTURE full original source witnesses, such that:
1. for every qualifying W, T_C supplies the builder's frozen correct label for each needed source bit, **for all three independent OR grounds** or for an actually composable branch-specific capsule;
2. arbitrary classical/QPT recovery of a forbidden combination of labels yields an ACTUAL original certificate (not merely a label, query log, offered representation or fake hash string), or an independently justified native/hash break;
3. the full serialized public program plus VK, native signature message, authorized setup context, malicious source side information and opened siblings has a jointly valid simulator.
No such component or independent assumption has been instantiated. This note is NOT a solution or an independent advance to announce.

The preauthorization trust model is unchanged (one honest N-of-N participant, no online response after setup), as are strict PQ contextual AuxPoW, all original claim/burn/amount/recipient/window/depth/reset bindings, Bitcoin-only native signature verification, and R225's slot-global veto versus activation-portable signature issue.

**NONQUALIFYING. No PR comment or user notification warranted.**
