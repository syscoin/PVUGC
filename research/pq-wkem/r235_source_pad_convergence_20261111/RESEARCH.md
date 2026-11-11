# R235 — SHA source-certificate pad convergence and telescoping repair

Classification: NONQUALIFYING. No original witness-conditioned public Build/Open, no QPT proof, no source-certified hidden common secret.

Observed start SHA: 39455d84a3fe7bad1ad5b99e672c5387bcfb9580, syscoin/PVUGC PR #1, research/pq-wkem-validation-20260918. Read exact R235 preceding checkpoint (blob b0a73185b87389c01327be5e145504b768a857e7) and R234 (blob 10f5765efa07f6e8c0a10d1586d1b96def97090a); last relevant PR discussion was R225. Local intermediate checkpoint was written before checker execution. Hashes of exact locally executed files are below. No web, external literature, independent agent, native signing, actual AuxPoW consensus validation, original witness encryption, or quantum security execution.

## Candidate: SHA-pad from an actual original source certificate

Let sigma be the frozen claim/path-scoped native cancellation signature, x the full original withdrawal challenge statement, and w a fully qualified source-work/fork/burn evidence witness. A proposed static pad construction is:

    E = sigma XOR H_pad(x, Enc(w_star))
    Open(E,w) = E XOR H_pad(x, Enc(w)).

Even assuming the builder could know some selected qualifying w_star at setup (not assured for future source challenges), correctness on ALL qualifying original witnesses w0 and w1 requires:

    H_pad(x,Enc(w0)) = H_pad(x,Enc(w1)).                  (1)

This exact equality follows by XOR cancellation and is not a hardness assumption. Different valid Bitcoin parent-work certificates for the SAME pure Syscoin child can yield different Enc(w) even though they do not constitute a fork. Different legitimate source branches also generally differ. With SHA applied to injectively distinct full encodings, common correctness across those cases would require a SHA collision. A sampled inequality alone is not a SHA security theorem.

## Repair A: telescoping SHA source history

For a consecutive authenticated path P=(z0,...,zm), let F(z)=SHA256(domain||z), and public edge difference D_i=F(z_i) XOR F(z_(i+1)). Define Acc(P)=XOR_i D_i. Exact identity:

    Acc(P)=F(z0) XOR F(zm).                              (2)

Different valid paths between SAME endpoints now give the same pad. This is a functional improvement relative to full-transcript hashing, but a live fork generally gives DIFFERENT end-block identities. If both endpoints are fixed/public, anyone computes (2) without any authenticated source evidence; the pad is not hidden and the cancellation signature is publicly exposed. A common public predecessor/anchor is already known before the fault and has the same defect.

The additive field version with public potential phi and edge values phi(v)-phi(u) modulo p telescopes to phi(end)-phi(start). This observation rules out ONLY publicly computable potential-difference carriers with publicly constructible endpoints, not all hash-based WE or nonlinear source-dependent obfuscation.

## Repair B: common anchor plus a purported source gate

Use pad=F(public anchor), E=sigma XOR pad for all alternatives, with an honest evaluator checking source validity first. The pad is available immediately and raw release bypasses the verifier. Adding a public telescoping correction cannot make the pad secret. A secret label known to a setup party or source miner but not guaranteed to appear in every real, future authenticated source witness creates malicious-source-retention or completeness failure; an online authority/extra independent puzzle is excluded.

No common SHA pad for all three ORIGINAL challenge families was found; the same requirement must hold across heavier BTC competing history, bound PoB fault and qualified Syscoin fork/tag inconsistency. A source-borne hidden cross-witness correlation, together with a full-joint public simulator/extractor, remains missing.

## Actual bounded local execution

Python standard-library checker.py is exact source below, executed twice with identical captured.json. SHA256d toy parent target ~10 bits, full source fake header/coinbase linkage explicitly synthetic (NOT Bitcoin difficulty rules, AuxPoW Merkle branches, best-chain membership, tag parser or source authenticity). Two different work certificates were found for the same synthetic child, one for another child. A single fixed pad opened only for the calibration certificate. SHA telescoping equality held for multiple paths; equal endpoints allowed immediate public recomputation and different endpoints generated different pads; a prime-field additive potential confirmed the same identity. 27 deterministic functional assertions; no native SLH signing, QPT experiment or ORIGINAL release.

Exact local code SHA256: ac2eaef417be231343fea162fa5b80115bd4e30ae439ecac1a2646869a6249b8.
Exact local captured SHA256: 1216a7fe7fd0e288b16476fff572c811c2a4ab60d616b761ca68cf61011261ab.
Local pre-test checkpoint SHA256: 114aeec7495ee06a4155a6770ad414f0b587d4b1df0cde4882e2bfbe35ac3698.

## Next exact missing equation

Instantiate public classical-PPT Build_hash(R_original,x,sigma)->C and Open_hash(C,w)->same sigma for EVERY complete authenticated original BTC/SYS OR-challenge, and prove arbitrary full-public QPT recovery/native forgery extracts actual ORIGINAL evidence or independently justified hash/native break. Include source timing, malicious setup, aux input, related capsules and coherent quantum attacks. No online release service, fake source certificate, post-hoc verifier, independent mining puzzle, forced canonical witness or lattice fallback. Do NOT repeat R234 public-bit release or R235 certificate-hash/telescoping carriers without an explicit new source-dependent cryptographic correlation and full-public argument. No qualifying progress comment.
