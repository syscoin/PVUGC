# R197 public source-circuit garbling: unfinished construction hypothesis

Run 2026-11-10; repository syscoin/PVUGC PR#1 on research/pq-wkem-validation-20260918, observed head 349fbdb646bd5ae3cdceaae56a76f32f7ee986b7 (R196 SHA ratchet). No external research. This is the first local checkpoint, written before checker execution.

Choose one new hash-only release candidate: garble a concrete Boolean checker for original authenticated SYS/BTC challenge relation, publish both labels for each externally supplied ORIGINAL witness bit so any challenger can evaluate offline, encrypt frozen claim-specific cancellation signature sigma under the output-true label. A valid witness recovers the same sigma because garbled circuit has one true output wire label. Build is classical polynomial, input labels are published and setup has no online issuer. All source-header SHA, PoB and tag-consistency checks can be represented as Boolean subcircuits but are not implemented in this bounded experiment. No Bitcoin verification is added.

Critical security test: source/witness bits with fanout enter two contradictory gate paths. Even though the false instance has no globally valid witness, an attacker holding both labels can evaluate the branches on different local input choices and combine their output labels to open the final AND's true key. Try domain-separated SHA garbled gate tables with point-and-permute rows and public checking key. Assess whether adding a common hash of the entire ORIGINAL witness as a gate tweak prevents label switching without requiring setup to know future witnesses or publishing a universal callable hidden-key compiler.

This proposed candidate is not a solved KEM. Do not claim a QPT reduction from the bounded classical test. Do not pursue size/performance.
