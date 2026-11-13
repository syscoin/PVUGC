# R187: Source-root keyed canonical absence witness as a hash-only release component

Status: intermediate hypothesis, deliberately before running checker. NOT a crypto release breakthrough or a working witness-KEM. This run focuses on the exact unfinished R2 source-to-secret interface, without optimizing old restricted constructs.

## Continuity
PVUGC PR #1, branch research/pq-wkem-validation-20260918; observed start ce1539be0b7e2cf930adc44b2fd58caab83bae34 (draft/open/unmerged), latest R186 `research/pq-wkem/r186_sha_midstate_work_20261109/RESEARCH.md`, exact blob 901376dbeefc83dac55bd0adc983fc4fda452189. R185 exact public coefficient-dual attack read to avoid repeating it. Recent ordinary PR comments through R177 contain no new request changing the authenticated-source target. No external web/literature.

## Candidate: R2-CAP, canonical absent burn path
For a *fixed authenticated* source state root rho and exact BurnID b, consider a domain-separated SHA Merkle registry whose leaf is either EMPTY or OCCUPIED(key,record). Let path p=(s_0,...,s_{d-1}) be sibling hashes under a fully specified, deterministic sparse-tree layout. VerifyAbs(rho,b,p) recomputes rho. Define canonical token T=H_tok(x_W,rho,b,p).

Crucial potential gain: every accepted path for the same (rho,b) and EMPTY leaf must be byte-identical unless two different inputs to some SHA node hash collide. Therefore distinct original witnesses for the *same fixed state root* (different external headers/proofs) normalize to the same unique R2 path. This is a property of the actual hash commitment, not a fake secret-label issuer.

Questions to test:
(1) Prove and check exact path uniqueness at fixed rho,b, accounting for variable encodings, substitute roots and indexed directions.
(2) Can classical-PPT Build BEFORE future source truth is known construct `E=K xor H_pad(T)` for that unique but unknown path without knowing the path or exposing a public pad? Attempt commitment-to-path, fake-path and root-based repairs.
(3) Does a path from different authenticated source state roots accidentally count as same claimed withdrawal? Check root binding and any challenged-root changes.
(4) Does the canonical normalization avoid the many-witness barrier for *R1 or R3*, or is this strictly one R2 source component?

Target full-public security for the 3-branch R_cancel remains unchanged; no online issuer or source secret retained by a malicious actor. This checkpoint is written prior to the experiment; no test result asserted.
