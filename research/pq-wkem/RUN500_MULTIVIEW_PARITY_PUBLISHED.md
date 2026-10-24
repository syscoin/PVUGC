# Run 500 — repeated same-key hardcore pads fail under multiview recovery

Starting PR head: 6c61ed65ac4f9b234c1d75550355d6aa51d86ff3. Branch research/pq-wkem-validation-20260918; PR #1 remains draft. This is a focused attack on a possible multiple-view extension of Run 499, **not** a break of its single-bit Goldreich–Levin lemma, a construction of local mixing, or a refutation of RIO.

Candidate: classical honest setup shares one hidden signing-key component S in GF(2)^h across m public releases. Each release uses an independent uniform public mask u_i in GF(2)^h and reveals c_i=b+<u_i,S>+<v_i,V>, where b is the SAME unknown bit, V is a known public-key component and v_i is a public mask. Complete capsule, VK, setup proof, all auxiliaries and public evaluations are visible. Arbitrary QPT attackers are allowed; a deterministic classical PPT attacker suffices.

Subtract known terms, forming z_i=c_i+<v_i,V>. Then z=[A|1_m](S,b), where A has rows u_i. If Q=[A|1_m] has rank h+1, public binary Gaussian elimination recovers the complete S and b without any ORIGINAL witness. For m=h+1+s, independently random A, the exact full-rank probability is

    product_{j=0}^{h-1} (1-2^(j-(m-1))) > 1-2^(-s).

Proof: project A's h independent uniform columns modulo span(1_m), obtaining h uniform vectors in GF(2)^(m-1). Full-rank probability is their independence product; union bound gives the strict stated lower bound. This holds for every fixed S,b and arbitrary public VK correlations. At h=256,m=273, success probability exceeds 1-2^-16. Bit b alone is recoverable whenever 1_m is outside col(A): find y such that A^T y=0 and <1_m,y>=1, then b=<y,z>.

The attack is unconditional against this **specific repeated parity-pad interface**, even when setup ZK certifies honest generation. If S is the secret native signing material, the attacker can issue a fresh native signature without an ORIGINAL source. Run 259 applies only after accepted COMPLETE-source representation, which this attacker never provides. No shared preimage, canonical witness or rank-of-lattice attack is involved.

Taxonomy: repeated local seam, public linear synchronization, multi-view correlated-mask/key attack, honest but key-reusing setup, native checking-key/public-field correlation, and fresh signature instead of cross-branch replay. Coherent quantum analysis is unnecessary because classical elimination succeeds. One securely distributed independent key per separately encapsulated bit prevents this exact combination; it does not produce a complete WKEM. SAME native key for all valid witnesses of a single claim remains mandatory.

Executed compact checker: node research/pq-wkem/run500_compact_multiview_check.js; 43,421 assertions, exhaustive h=1..3 and surplus s=0..1, exact product comparison and full-rank recovery, repeated byte-identical output. Independent extended local checker: 231,066 assertions at s=0..2; 32 illustrative real Ed25519 signatures after recovering 256-bit seeds with 273 public views. Neither checker implements a real PQ local mixer, SLH-DSA or on-chain Bitcoin endpoint.

Goldreich–Levin's **single-bit** hardcore result and Canetti–Chamon–Mucciolo–Ruckenstein TCC 2024 local reversible-circuit RIO remain unrefuted; no new full primary-literature proof audit. False-instance full-public-output QPT hiding, true-instance arbitrary-signature-to-ORIGINAL extraction, malicious N-of-N setup, concrete 128-bit costs and native-PQ Bitcoin integration are UNPROVED. No completed practical witness-KEM; production unchanged.
