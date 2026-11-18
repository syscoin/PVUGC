# R354 — hidden global checksum on a width-five Boolean program: exact public flow extraction

**NONQUALIFYING ORIGINAL witness-KEM research.** This is a new bounded construction and attempted repair of a compact implicit source-verification transport. No ORIGINAL-source conditioned public release or QPT security theorem is claimed; no user/PR progress comment is warranted.

## Continuity and scope

Read the open/draft syscoin/PVUGC PR #1 at head e086acd99d0bec51534468e3d5e79f213178b3a4, branch research/pq-wkem-validation-20260918. Its latest unnumbered source-Merkle note blob was e6929bbcf29e52a1d1830b78aabab08694da2e9d. Read R351 exact blob 48fc1a17abf0e6455434168aff4be521730a48ba and R350 exact blob bd1de20269249d79bb48481446b5932591fcdd2b; checked recent substantive PR issue comments (R225 same-outpoint activation-portability remains unresolved). No Core code, live Bitcoin/Syscoin certificate, production implementation or native signature tests were run.

R351's source-dependent missing operation is a polynomial-size serialized public transition for arbitrary future original SHA/AuxPoW evidence, with global repeated-variable consistency and one hidden frozen terminal release key. To change its explicit exponential frontier rather than repeat R327's low-degree mask, this pass constructs a **constant-width noncommutative Boolean-program state** and gives every occurrence of a repeated variable a hidden checksum contribution. A single inconsistent path cannot ordinarily reach the exact hidden terminal key if its checksum is nonzero. The decisive test is full-public multi-row recovery, not simply an honest Open validity check.

## Exact synthetic candidate

Let e=(0,1,2,3,4), a=(1,2,3,4,0), b=(1,3,0,4,2) be permutations of five elements, with composition p*q applying q first. gamma=a*b*a^-1*b^-1=(4,3,0,2,1). a, b and gamma are five-cycles, checked by the executable script.

For a FALSE statement F(x)=x AND NOT(x), a four-occurrence Boolean program uses:
- occurrence 0: p_0(0)=e, p_0(1)=a;
- occurrence 1: p_1(0)=b, p_1(1)=e;
- occurrence 2: p_2(0)=e, p_2(1)=a^-1;
- occurrence 3: p_3(0)=b^-1, p_3(1)=e.

For consistent x=0 or x=1 the full product is identity. An independently selected *inconsistent* occurrence sequence (1,0,1,0) has product gamma and would be a false accepted path without a consistency mechanism. This tiny Boolean example is not an original source certificate and the constant-width representation is not asserted for the full ORIGINAL verifier.

The attempted consistency repair selects independent hidden 256-bit t_0,t_1,t_2 and sets t_3=t_0 XOR t_1 XOR t_2. Thus the checksum of any four *consistent* choices is zero, whereas the mixed choice (1,0,1,0) has unknown checksum t_0 XOR t_2.

For every layer j and every group state g reachable through arbitrary occurrence choices, Build samples independent uniform 256-bit K_(j,g), publishes the starting K_(0,e), and publishes only the *reachable-state* rows

 E_(j,g,z) = K_(j,g) XOR K_(j+1,g*p_j(z)) XOR (z*t_j).

It masks one frozen synthetic capability S by D = S XOR SHAKE256(domain || K_(4,gamma), len(S)). Opening follows a chosen path, XORs its public rows with the published start key and applies SHAKE256 to the terminal result. For a TRUE companion F(x)=x AND x, consistent x=1 produces gamma and checksum zero, so public Open recovers precisely the same precommitted S. For the FALSE program no consistent x can open. The builder's construction is polynomial for this explicitly bounded reachable table. The joint-public security question gives the adversary *all* rows, not just the honest Open API.

## Decisive unconditional FALSE extraction

The hidden checksum does NOT repair public release. There is an exact eight-row identity, valid for every choice of independent vertex masks and checksum shares:

 K_(4,gamma) = K_(0,e)
   XOR E(0,e,0)
   XOR E(1,e,1)
   XOR E(1,a,0)
   XOR E(1,a,1)
   XOR E(2,e,0)
   XOR E(2,a,1)
   XOR E(2,a*b,1)
   XOR E(3,a*b*a^-1,0).

Every intermediate K variable occurs exactly twice and cancels. t_1 and t_2 each occur twice and cancel; no t_0 or t_3 term occurs. All eight rows are in the PUBLIC reachable-only table. An attacker computes K_(4,gamma), then S=D XOR SHAKE256(domain || K_(4,gamma),len(S)), without a consistent witness, without knowing the checksum shares, without SHA inversion, and without visiting any illegal graph state. This is a classical straight-line public edge-flow certificate, **not** a Bitcoin/Syscoin original challenge or an oracle-query extraction assumption.

It also defeats a fully coupled FALSE simulator: two possible frozen secrets S0 and S1 can be distinguished with certainty by calculating the exact plaintext from the complete public row table and D. Making SHAKE ideal, enlarging t_j, attaching a Merkle transcript root or adding a final honest-code witness test does not repair the displayed linear identity. The result is a restricted algebraic attack on this specific affine edge transport, not a general impossibility for hash-only witness encryption.

## Separate nonlinear group-action repair and exact limitation

Consider a *publicly executable* nonlinear checksum action U_phi on hidden terminal key K with group law U_phi(U_psi(K))=U_(phi+psi)(K) and U_0(K)=K. These equations guarantee correctness when repeated-variable contributions balance. But U_(-phi) is a PUBLIC inverse to U_phi. Hence, when the checksum phi of an accepting-group mixed path is computable, its key U_phi(K_target) immediately yields K_target by applying U_(-phi), regardless of nonlinear internal SHA gates. For XOR checksum groups -phi=phi.

The executed script constructs a nonlinear four-round SHA256-based public Feistel bijection F and sets U_phi(K)=F^-1(F(K) XOR phi). It checks U_phi(U_phi(K))=K for a nonzero phi. This is an exact group-action fact, not a proof of concrete SHA security. Hiding phi in affine row ciphertexts leaves the eight-row public-flow attack above; choosing hidden-key nonlinear transitions instead makes their required polynomial-size public serialization and joint QPT simulation **unimplemented**. Not all nonlinear/noninvertible programs are ruled out.

## Executed evidence

The CPython standard-library checker was invoked twice and both JSON result files are byte-identical. It enumerates all four-occurrence choices in the TRUE and FALSE fixtures, constructs only reachable group-state rows, performs formal GF(2) row-span extraction without using secret tape values, confirms exact key and 160-byte synthetic-capability recovery, and executes the nonlinear public Feistel inverse. It reports 28 public edge rows, reachable state counts 1/2/4/7/11, and the exact eight zero-based row indices 0,3,4,5,6,9,13,24 for the FALSE extractor, plus the publicly known initial key.

Checker SHA256: b0a5e6bc2ac7ec086e0a63ab12735c3562d8a0d7a77f1e2ab67311452b1b0c0b.
Each JSON SHA256: 3d0f185b33c7d8752445e384d69788249f13a4dc7aa5fb476672dc73fbd3626b.
Complete local derivation, actual checker, and captured paired outputs are archived LOCAL-ONLY at /mnt/data/R354_barrington_hidden_syndrome_20261118.tar.gz, SHA256 28b1ed86fcc309cbfa5b3bc40f1769c4254eb488c0c77a9e74b05ac965ee0ea7; this tarball is NOT a GitHub publication nor assumed persistent across runs. The repository note is this concise proof and provenance, not a claim that the full executable bytes are in GitHub.

## What remains

A valid positive successor must produce a **serialized classical-PPT, nonlinear, non-correctable** source-bound public transition, NOT another affine multi-row space or a reversible public group action. It must preserve one global actual authenticated ORIGINAL source assignment across repeated SHA/Bitcoin/Syscoin checks, return the SAME precommitted native safe cancellation capability for EVERY valid original challenge, and independently prove full-public FALSE/hard-TRUE QPT recovery/native-forgery security under malicious setup, retained source coins, auxiliary state and related capsules. A hidden-key transition API or ideal obfuscator is not the construction.

The ORIGINAL relation remains (1) strictly greater same-anchor BTC cumulative work OR (2) authenticated finite withdrawal-specific burn invalidity OR (3) qualified claim-relevant Syscoin inconsistency/tag fault at required LC depth. Apply active modern chain ID, exact unique canonical parent SYS tag, exact AuxPoW chain-root binding, actual ancestor comparisons and all source/UTXO/claim/amount/recipient/window/reset/deadline/VK/capsule conditions. Missing tag faults require independent outer-carrier authentication. R225 slot-global veto versus actual activation-bound native signatures remains separate. This run did not test those rules, nor prove original source-dependent release, native PQ signatures, Core consensus or QPT security.

**NONQUALIFYING: no user notification, PR progress comment, production edit, deployment or automation change.**
