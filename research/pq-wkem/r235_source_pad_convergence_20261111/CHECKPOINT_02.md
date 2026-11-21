# R235 second checkpoint — telescoping SHA repair

Initial observed PR #1 branch head: 39455d84a3fe7bad1ad5b99e672c5387bcfb9580. This is a record of the hypothesis before the test, not a claimed security or construction advance. Read exact current-head R235 CHECKPOINT_01.md (blob b0a73185b87389c01327be5e145504b768a857e7) and R234 RESEARCH.md (blob 10f5765efa07f6e8c0a10d1586d1b96def97090a); no external research.

Candidate repair of certificate-specific SHA-pad: derive a path-invariant secret from a telescoping SHA hash accumulator. For authenticated source sequence z0,...,zm let F(z)=SHA256(domain||z) and D_i=F(z_i) XOR F(z_{i+1}). Then XOR D_i = F(z0) XOR F(zm). Test whether real source diversity permits a fixed pad while an unqualified public party cannot derive the pad from known endpoints. Also test two distinct SHA256d parent-work wrappers for one child and an alternative semantic child. Synthetic work tests do NOT validate deployed Bitcoin or Syscoin.

A source-dependent public Build/Open and full QPT simulator are the necessary output; a mere telescoping identity, SHA-prefix, public source-anchor or verifier-if-check is not enough.
