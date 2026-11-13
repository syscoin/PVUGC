# Working checkpoint: source-quotient key-release construction

Status: a concrete attempted hash-only release compiler, no security or practicality claim yet.

Starting authoritative syscoin/PVUGC PR #1 branch `research/pq-wkem-validation-20260918`, observed head ba6fcc87dafeef348f28b4fcca48f0224e68521b, open/draft/unmerged. Read actual latest dual-branch carrier research and exact Merkle-consistency-source lemma. No external search, LWE, groups, online releaser or native Bitcoin script changes.

Research direction: replace the exponential witness-indexed pads with a small number of cryptographic release states indexed by authenticated **source equivalence classes** rather than entire witnesses. The ORIGINAL source relation verifies claim/UTXO, child, AuxPoW/parent work, authenticated tags, anchored ancestor/slot and external canonical-state assumption. Distinguish OutcomeID (semantic child) from WorkID (complete evidence). Build fixes the native signature sigma before event.

Candidate public interface: Build samples fixed K, publishes CK=Hcheck(K) and D=sigma xor Hmask(K), and a finite release map E[u]=K xor Hpad(u) keyed on class u=g(w). Honest Open would check ORIGINAL w, derive u, decrypt K and native signature. Need every valid w, regardless of WorkID, to derive some precommitted u. To be secure raw D must be unavailable to an attacker holding invalid w or computable u without qualifying evidence; a post-hoc verifier is insufficient.

Tests to execute: (i) fixed genuine child with different parent-work certificates, (ii) invalid parent/source with same OutcomeID, (iii) independent work-identifier class, which preserves source specificity but requires per-work pre-enumeration, (iv) formal entropy lower bound for independent hash pads, (v) attempt to replace E[u] by an enumerable Merkle proof root with cryptographic source checking. Assess exact ORIGINAL completeness vs raw release and preserve the results. This checkpoint is not a result; no PR comment warranted.
