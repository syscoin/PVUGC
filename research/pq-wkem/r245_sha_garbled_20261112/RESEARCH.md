# R245 — SHA-garbled source verification cannot release a secret from public input labels

**NONQUALIFYING research checkpoint.** This is a concrete hash-based Build/Open attempt, a joint full-public classical adversary, and two repairs checked at the exact missing boundary. It is not an ORIGINAL bridge WKEM, QPT security proof, or an implementation of real Bitcoin/Syscoin validation.

## Provenance and actual actions

Research branch syscoin/PVUGC PR #1: research/pq-wkem-validation-20260918. Starting head ba8b95d1f054fde470e470e74e9f06a1897c2cad (R244), parent 832e471d5837c807577c381dba7fb12f8c2f8ff0. Exact R244 RESEARCH blob 5f2ade097de8efffabccc32f5c6dd57ba42f8577 was read before this attempt. The last relevant top-level PR comment observed was R225 issue comment 6796383617. Core PR #609 metadata was read-only at head c91539de3c34937e57d7f5fda47c7b0502ff33f6. Its existing activated modern chain-ID, exact 41-byte SYS ancestor-tag output and unique-child commitment rules are treated as the SOURCE baseline, not rerun in this research pass.

One notary initiates a withdrawal; anyone may challenge under one of THREE independent ORIGINAL grounds: strictly more qualifying Bitcoin work, exact finite authenticated burn/authorization fault, or relevant mature authenticated Syscoin prefix/tag inconsistency or specifically allowed tag fault. N-of-N preauthorization belongs to the frozen Bitcoin spending graph, not the challenge quorum. The whole source relation must bind the actual claim/outpoint, assertion, burn/amount/recipient, context, Bitcoin anchor/work/window, Syscoin ancestor/height/LC depth, deadline/reset and cancellation native message, VK and capsule ID. The min checker below uses an intentionally FALSE 1-bit toy relation, not any of this authenticated source.

Local private working checkpoints existed BEFORE experimentation and BEFORE the proposed repair: CHECKPOINT_01 SHA256 14aabe2b968aab37eb78a5b16b8f63da61c9f91489a3cef431a2775bc35ddd13, CHECKPOINT_02 SHA256 de4e98fe6d8f1287b271ad0fea57cfdb5796640f3c8f41e12d2b2772694085a3. Post-test CHECKPOINT_03 SHA256 85e949c8fac6b3c5c3ab97c5b1cbfd72555551fd3e1bd59ed4354551a103b9ae. These expanded local files were not uploaded. Expanded local sha_garbled.py SHA256 05d262b3a3248ecfd6f24a9a5863890bbc7677f6b1fa5ddb4a3c011c9b58695c and captured.json SHA256 9f906136830c8f1f20bd7f9f1fb8e37ab68b849771b06b06b29a402042d3e957 were actually run and matched twice, but are local-only. The publication includes the separately executed shorter checker and its captured output.

## Candidate and exact equations

Let V_x(w) be a Boolean verifier for all ORIGINAL source conditions, rather than a separate post-hoc source if-check. In a classical polynomial-time Build, choose random 128-bit labels L[i,0],L[i,1] for each wire. For binary gate i with input labels a,b, the public row index is SHA256(serialize("row",i,a,b)), and ciphertext row is

    T[i,a,b] = L[out,f(bit(a),bit(b))] XOR trunc128(SHA256(serialize("pad",i,a,b))).

For unary gates use one input label. Build freezes the same sigma_cancel by

    E = sigma_cancel XOR trunc128(SHA256(serialize("release",L[out,1]))).

Open authenticates a genuine ORIGINAL w, maps its source bits to labels, evaluates V_x using SHA gate tables, and if output is accepting returns E XOR the output-label pad. Every qualifying witness would return the same sigma if it can obtain its correct input labels. Since Build happens BEFORE arbitrary future source histories, the first candidate publishes BOTH possible input labels for each future source bit. This makes honest functional evaluation possible, but exposes all rows' SHA pad inputs.

## Joint full-public adversary — FALSE instance, no witness

Test V(b) = b AND (NOT b), so NO b in {0,1} satisfies V. Honest Open cannot recover sigma for either input. But the full public adversary starts with the two labels for b, decrypts both unary NOT rows to get both NOT-b labels, and uses every combination of the public b labels and recovered NOT-b labels to decrypt each AND row. One pair corresponds locally to (b=1,NOT-b=1), although these assignments are globally inconsistent. This reveals accepting L[out,1]. The adversary immediately recovers sigma from E and checks a public hash of the result. It performs only forward SHA and XOR, never SHA inversion or collision search; it needs NO authenticated source witness. This breaks even FALSE hiding for the candidate and hence also hard-TRUE security. The attack is classical, therefore available to QPT adversaries. Including more real SHA verification gates inside V cannot repair gate-local closure when both labels can be publicly propagated.

The separately executed public/private-separated checker in this folder ran twice and produced identical printed JSON. It samples fresh private labels and sigma on each run, includes only source-bit label pairs, tables, E and SHA-check in the public view, and keeps private oracle labels/sigma separate for assertions. Observed FALSE witness count zero, both honest opens reject, both output labels publicly reached and frozen sigma recovered via checking hash. A larger local checker additionally ran a TRUE circuit b XOR 0 (honest b=1 opens but raw closure opens early) and two synthetic future SHA256d source hashes with different gate row keys. The tests are synthetic SHA gate algebra, not Bitcoin headers mined to a target, AuxPoW consensus validation, native PQ signing, QPT proof, or performance measurement.

## Concrete repairs evaluated and why neither instantiates original-source release

Repair A: publish only H(hidden-input-label) for the inactive bit. This defeats simple closure but an observer with an arbitrary future source witness cannot derive the unpublished label from an actual parent/coinbase/Syscoin history; ordinary hash commitments do not release preimages. Using baseline labels only excludes alternate valid histories.

Repair B: derive each input label from SHA256d of actual future parent history and a seed. Different independently admissible future parent certificates have different label/row keys, so a finite Build-produced gate table fixed before those sources are known cannot be keyed to BOTH without a further compiler. Withholding a builder seed prevents public Open; publishing it makes arbitrary fabricated source-derived labels computable. Treating a hypothetical protected SourceToLabel oracle as an assumption would merely restate the missing primitive. Requiring both live source witnesses to share an invented miner-held OTS key is not permitted by the canonical AuxPoW tags.

Repair C: append a public SHA-based global-consistency check to Open. The attacker simply does not invoke Open and uses the public rows; garbling that check with accessible input labels retains the same local label-closure attack. Protected, globally non-recombinable label selection must be IN the release computation, not a public policy check after raw evaluation.

## Scope and next exact obligation

This rejects only SHA-GARBLED-245 as specified, not all hash-based computational witness encryption. No security advance is claimed. Needed: actual classical-PPT Build_inc(x_W,sigma_cancel), public Open_inc(C,w) yielding the SAME claim/path-scoped native cancellation capability for EVERY qualifying ORIGINAL certificate, plus arbitrary QPT full-public unauthorized recovery or accepted native forgery -> genuine admissible ORIGINAL evidence or a separately justified PQ hash/native break. All native/VK/capsule/checking correlations, malicious setup and source retention, selective sibling openings, and fixed-outpoint activation portability (R225) remain. The input-label source compiler is NOT supplied by this note.

No ordinary PR progress comment warranted.