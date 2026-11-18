# R355 — source-salted irreversible SHA release: a convergence obligation, not a KEM

**NONQUALIFYING; no user or PR progress comment.** At start, syscoin/PVUGC #1 was open/draft, branch \`research/pq-wkem-validation-20260918\`, head \`54ec90af5ab6acdd8c133fc93fd1df5a3ec4c568\` (R354); recent substantive PR discussion reviewed. This run did not inspect or execute Syscoin Core, actual original AuxPoW/BTC certificates, native signatures or QPT experiments. Prior strict-PQ consensus rules remain assumed, not newly reverified.

## Candidate and change from R354

R354's affine public edge transport leaked via an eight-row XOR-flow certificate, and its reversible public group action exposed a correction inverse. A different construction uses an **irreversible** SHA-state transition, with canonical source transcript w = (z_0,...,z_(m-1)), claim-bound fixed setup seed k_0:

\`k_(j+1) = SHA256("R355-HASH-PATH-V1" || encode(j) || encode(z_j) || k_j)\`.

Each z_j is meant to represent authentically bound parent/child/carrier facts, *not* merely a fabricated bit assignment. One frozen native message S could be encrypted as \`D=S XOR H("cancel"||K*)\` provided every qualified ORIGINAL w computes the same K*. Transitions and public witness opening take polynomial time and have no public group inverse or affine edge ciphertexts. This changes the algebra of R354's attack. However it fails its own **all-witness common-key correctness**.

## Exact restricted collision-convergence lemma

For equal-length canonical transcript paths w != w' with the same k_0, if \`T(w)=T(w')\` then the two public paths reveal a collision in SHA256. To extract: inspect the final SHA input pair u,v. If u != v, terminal equality gives H(u)=H(v). If u=v, canonical parsing implies equal preceding states and equal last-round observations; walk backwards until the latest unequal SHA input. Its two hashes are equal, yielding a collision. If no such round exists, w=w', contradiction. For different path lengths, append a length-domain-separated terminal SHA call so identical termini remain collision-producing unless lengths match.

Thus a raw irreversible hash path cannot implement SAME frozen terminal K* for two different valid future challenge certificates under SHA collision resistance, unless it adds an explicit convergence mechanism. This excludes only this direct SHA-chain family, not hash-only witness encryption generally. The two distinct certificates must be independently ORIGINAL-qualified; two parent work certificates supporting one child alone are not a fork. No global uniqueness of Bitcoin/Syscoin certificates is assumed.

## Joint-public compensation repair and exact failure

One can force correctness by publishing a witness-indexed correction \`E(w)=S XOR T(w)\`, then returning \`E(w) XOR T(w)=S\` from Open. But because T and E are public, any arbitrary *nonqualifying* z immediately recovers S. The joint public FALSE view consequently has no secret-hiding simulator. Changing E to an honest-code predicate-gated program \`if R_orig(x_W,w) then S XOR T(w) else bottom\` does not solve serialization: S remains in public code unless a separately instantiated cryptographic encoding hides it. A per-certificate table is exponential in unconstrained future nonce/history witnesses. Merkle-root authentication of E bytes cannot manufacture their hidden preimages. This is a rejected repair; it is not a claim of SOURCE-conditioned release.

The successor needs an actual polynomially serialized *nonlinear convergence* that avoids forcing SHA collisions, **and** a full-public source-authenticated simulator resisting public arbitrary-path evaluation and cross-witness mixing. An inaccessible source-label issuer or hidden-key API is not an instantiation. A high-degree formal mask without a publicly secure evaluator is not one either. R354's public-flow attack and the R355 SHA-collision lemma constrain distinct design families; neither proves general impossibility.

## Executed verification and provenance

Executed the attached Python standard-library checker **twice**. It constructs two *synthetic* inputs satisfying a 2-bit prefix toy qualifier, finds a deliberate truncated-8-bit SHA-path collision for inputs 29/101 with terminal byte 0x49, and walks backwards to a distinct-input same-output hash call at layer 6. For full SHA256, the same two paths yield different terminals (one observation, not cryptanalysis). A direct public compensation row recovers a synthetic 32-byte S even on nonqualifying strings 0 and 255. These are NOT original source certificates or full-source admission. The two captured output files are byte-identical.

Script SHA256: \`c3861a6e25558168aa661bc4b1c7ff7092eed87cf5e4b455451cf439b6cd8c35\`.
Output SHA256 for each run: \`ecf9093908c31d98cb942f8f74d6cfd818b07c64e920007c50a9decb06008b01\`.
Local source-and-results archive \`/mnt/data/R355_hash_path_convergence_20261118.tar.gz\` SHA256 \`56684f8fcd88bc38b6fe62efceb346ab678a16ca0f8230f5aef8fd6d1ed6ef72\` is **not** the GitHub publication and persistence in a later runtime is not assumed. This GitHub checkpoint additionally publishes this checker and one captured output. Local-only full expanded note is in the archive.

## Scope and handoff

**Still absent**: an honest classical-PPT public \`Build_inc(x_W,sigma_cancel)->C\` and \`Open_inc(C,w)=sigma_cancel\` for every qualified ORIGINAL witness, and an independently justified full-public FALSE/hard-TRUE QPT recovery/accepted-native-forgery reduction under nonuniform auxiliary input, malicious setup/source, retained source coins, sibling capsules and selective opening. The ORIGINAL relation preserves (1) qualified strictly greater same-anchor BTC work OR (2) finite authenticated claim-specific burn authorization fault OR (3) qualified claim-relevant Syscoin history inconsistency/independently authenticated tag fault at LC depth. Preserve all source/history/UTXO/claim/amount/recipient/window/reset/deadline/native VK/message/capsule binding, activated unique canonical modern AuxPoW, the R316 tag-lag correction, and R225 native same-outpoint activation portability. No source weakness or network activation is claimed. No progress notification, PR comment, production edit or automation modification.
