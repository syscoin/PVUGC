# Prime-power torsion Macaulay rank-pad: exact repair of Pasch FALSE-source confidentiality

**Status:** New, positive, strictly restricted compiler/release/security advance. **NOT** a generic-NP witness-KEM; **NOT** a reduction from arbitrary unauthorized hard-TRUE key recovery/native forgery to ORIGINAL witness. This repairs the precise fixed-FALSE degree-3 Pasch 3-XOR example which defeated the preceding **odd-prime** Macaulay source, without adding a planted SOURCE witness, source-opening oracle, external hardness conjecture, or a larger polynomial degree.

## Concrete source and honest algorithms

Let the public ORIGINAL statement bind relation identity, claim/whole UTXO, branch, authenticated anchors/window/context, intended native verification key, and intended challenge-signing path. A classical polynomial-size deterministic gate reduction expresses the ORIGINAL NP relation as 3CNF F_x with an explicit extension map from each valid ORIGINAL W to a satisfying Boolean assignment v. This work does not implement the actual SYS/BTC authentication relation or native PQ Bitcoin opcode.

For fixed degree D>=3, make the public square-free monomial basis B_D of all Boolean monomials of degree at most D. Let m=|B_D|. For every 3CNF clause violation polynomial p_j (integer coefficients, Boolean multilinear quotient), include all coefficient rows of u*p_j with square-free multiplier u of degree at most D-deg(p_j). Append the coefficient row alpha of the constant monomial 1. The resulting integer A has n rows and m columns; U is zero except U_last=1. Reduce coefficients in Z_q for q=2^k. All this is witness-free and classical PPT for constant D.

For **every** valid ORIGINAL W, define Phi_D(W) to be the Boolean monomial-evaluation vector of its satisfying gate extension. Its entries are 0/1, ||Phi_D(W)||_1 <= h=m, and A*Phi_D(W)=U **over the integers**. Distinct valid W need not have equal Phi; there is no canonicalization or common intermediate.

Generate the **real** native signing key K and pk using native honest KeyGen, preserving the checking-key/secret correlation; K is a complete fixed-length secret capability with a native signing algorithm. Independently choose t>=2 uniformly random equal-length XOR share strings Z_j and publish M=K XOR Z_1 XOR ... XOR Z_t. For q=2^k set g=q/2. For each bit a of each share, independently sample s uniform Z_q^n, e uniform {-1,0,1}^m and eps uniform {-1,0,1}; publish the COMPLETE ciphertext

    c=A^T*s+e mod q,       d=U^T*s+eps+g*a mod q.

The public view is F_x, ORIGINAL binding fields, A,U, all (c,d), pk, M, auxiliary data and related capsules. The algebraic construction has no SourceOpen oracle and no undisclosed checking-key replacement. Honest randomness must be cryptographic; executable checkers use deterministic seeded test PRNGs **only for finite reproducible identities**, never as security samplers.

**Release:** On each genuine ORIGINAL W, calculate phi=Phi_D(W) off-chain and r=d-phi^T*c=g*a+eps-phi^T*e mod q, and output the nearest cyclic center 0 or g. Since |eps-phi^T*e|<=h+1, if g>2(h+1), every genuine ORIGINAL W decodes all protected bits and recovers exactly the SAME precommitted K by XOR with M. The final action is an ordinary native signature on the intended challenge path; Bitcoin performs no general NP verification, proof, trace dispute or VM execution. The native no-EC-key-path PQ endpoint is only a conditional assumption, not deployed functionality.

## Full-ciphertext torsion-equivocation theorem

Require a **publicly decidable mod-2 certificate** z_2 in {0,1}^n with

    A^T*z_2 = 0 (mod 2),       U^T*z_2 = 1 (mod 2).

It can be found and checked by ordinary F_2 Gaussian elimination. It **proves ORIGINAL FALSE**: any valid ORIGINAL phi would imply 0=z_2^T*A*phi=z_2^T*U=1 (mod 2). This is a subset of FALSE instances, not all of them.

Put q=2^k and g=2^(k-1). Because all coordinates of A^T*z_2 are even and U^T*z_2 is odd, the lifted vector g*z_2 obeys A^T*(g*z_2)=0 (mod q) and U^T*(g*z_2)=g (mod q). For **any two** plaintext bits a,a', transform only the encryption coins by

    Eq_(a->a'):(s,e,eps) -> (s+g*(a-a')*z_2 mod q, e,eps).

Both full ciphertext components are unchanged, **pointwise**:

    A^T*s'+e = c,
    U^T*s'+eps+g*a' = U^T*s+eps+g*a = d (mod q).

Uniform s is preserved bijectively even conditional on fixed ternary errors e,eps. Therefore the entire (c,d) distribution is exactly independent of each protected share bit, and the independently encrypted joint ciphertext distribution is exactly plaintext independent. This proof does NOT rely on odd-prime-field LWE or a marginal-only pad hybrid. Identical complete classical public records stay indistinguishable under arbitrary coherent QPT postprocessing.

**Prime-power extension:** For prime p, q=p^k, g=q/p and a mod-p certificate z_p with A^T*z_p=0, U^T*z_p=1 mod p, use digit alphabet 0,...,p-1 and the identical translation s'=s+g*(a-a')z_p mod q. Full ciphertext equality follows from g*p=q. All genuine phi decode by nearest cyclic radix-p center when g>2(h+1). This is an algebraic lemma, **not** a claim of ordinary QPT-LWE hardness on Z_(p^k). The checker tests p=3,q=81 as well as the primary p=2 case.

## The exact previously broken Pasch instance now protected

Use triples (0,1,2), (0,3,4), (1,3,5), (2,4,5) with 3-XOR parities (0,0,0,1). Every variable appears in two triples; the system is contradictory. Encode each parity as four forbidden-assignment 3CNF clauses (16 total). For D=3, the integer source is A of shape 17x42 (16 violation rows, one normalization), U=(0^16,1). Over the integers, the sum of **all 16 clause coefficient rows PLUS normalization** is a vector all of whose entries are even: parity cancellation leaves 2*(integer polynomial). Thus the explicit z_2=(1^16,1) is the required mod-2 certificate. An independent Gaussian solver produces a verified certificate.

At q=256 and g=128, all ciphertexts have the order-two coin symmetry above. At the earlier q=257 the same D=3 Pasch formula instead had a public unaccepted pseudo-opening and deterministic complete-key recovery. Choosing q=256 changes the **actual source arithmetic and bit encoding**; mere noise scaling in the old odd-q scheme does not. No lifted degree, canonical witness, assumption-based SOURCE release, fake pk or planted witness was introduced.

On an independent TRUE 6-variable source F=(x0 OR x1 OR x2), all **56 distinct** satisfying ORIGINAL assignments (other three variables free) each calculate Phi independently, obey A*Phi=U, and decode the identical native-secret 256-bit mock capability from all three 256-bit XOR shares with q=256, g=128, h=42 and |legitimate residual noise|<=43<64. The checker also confirms complete c,d equality under bit changes on Pasch, two independently randomized FALSE capsules using one protected K, and full encrypted-share/coin reconciliation after two whole shares were already disclosed. The mock key is an exact byte array, not an SLH implementation.

**Size:** 3 shares x 256 bits x (m+1)=**33,024** raw Z_256 ciphertext field elements = 33,024 bytes per 256-bit, 3-share capsule for this 6-variable source, not counting A,U, M, checking key, source, context, headers and framing. This is off-chain data and not a practical generic-NP or Bitcoin on-chain verifier measurement. No overall 128-bit QPT security level is certified.

## Genuine checking key, adaptive classical opening and multiple-capsule QPT proof

Fix polynomially many honestly built **mod-2-certified FALSE** capsules. Each may have distinct F_x,A,U, all may use the **same genuine native checking key pk(K)**, but their XOR shares and per-bit encryption coins must be independent, and each retains at least one unexposed whole share. The adversary may coherently process the entire classical public output and independent/nonuniform QPT advice not correlated with the hidden native secret. A classical authenticated Open oracle may adaptively disclose at most t_i-1 distinct WHOLE shares per capsule, including the complete plaintext and every s,e,eps coin; signing oracle queries, if present, are classical and forwarded to the genuine native challenger. Arbitrary owner-forged opening receipts, precommitted coin hashes, known/reused protected coins, malicious setup/retained signing seed, K-correlated hidden advice, full opening of one capsule, related TRUE capsules or coherent-superposition oracle queries are outside the theorem.

A straight-line QPT simulator given **only** the challenge native pk (and authorized classical signing oracle) can generate every public source, **honestly independently sample all shares with all coins**, and choose each public M_i independently uniform, answering any admissible adaptive Open with the genuine sampled share/coins. It never learns K, calls SourceOpen, guesses a protected index, or asks the adversary for a representation.

To prove the simulated and real transcript distributions coincide, fix real K and any permitted adaptive completed transcript, then pick any still-unopened index J_i in each capsule **after** the trace. Interpret the hidden share as Z'_(i,J_i)=K XOR M_i XOR XOR_(j!=J_i) Z_(i,j), and apply the explicit per-bit torsion Eq to that share's unpublished encryption coins. Each full public ciphertext and all opened plaintexts/coins, sources, masks and checking keys remain exactly unchanged, with an invertible measure-preserving change of uniform hidden coins. Partition by observed adaptive opening trace: the transformation preserves its partition, so the **entire** interactive classical transcript distributions agree. Arbitrary QPT postprocessing has no distinguishing information. The argument also composes across any polynomial number of separately randomized same-key certified-FALSE capsules without a guessing-factor loss. One full target K recovered or a fresh target-path native signature produces a fresh native EUF-CMA forgery. Thus, in precisely this restricted model,

    Pr[usable target-native-K recovery OR fresh native-path forgery]
      <= Adv_QPT-native-EUF-CMA(native, straight-line reduction).

The certified-FALSE information-theoretic secrecy has zero LWE term and zero statistical slack. Native QPT EUF-CMA is independent and must match the exact challenger key-generation/signing interface. This **does not** prove accepted owner receipt binding: public Eq deliberately permits any cipher bit to be equivocated using public z_2. An owner/ceremony authentication mechanism is still necessary.

## Execution, limits and exact next obligation

**Published standalone JS checker:** actual Code Mode V8 invocation passed 58,846 assertions before creating Git blobs; file content is its exact executed function source with a standalone console output wrapper. It compiles the exact 16-clause Pasch matrix, verifies all 64 FALSE assignments, finds the explicit mod-2 certificate, runs full ciphertext bit-equivocation, reconciles the last share in two separately randomized same-key mock capsules, and performs full 3-share 256-bit recovery on **all 56** valid TRUE witnesses. Its exact produced output is stored as OUTPUT.json.

**Extended LOCAL-ONLY Python checker and captured output:** Python standard library code executed twice with byte-identical output; **45,084 assertions per run**, including independent F_2 Gaussian certificate discovery, exact q=8 full-ciphertext distribution equality across all 27 fixed noise settings, 576 p=3 prime-power translation identities, two separately randomized false capsules, and full 256-bit capability correctness. Its initial incorrect fixture expectation of 3 instead of 5 source rows for a one-variable unit-clause Macaulay example was corrected before final runs. Python check.py SHA-256: 3390c444d7aea06d387c8bb5e070605d44a69d0e28885958ea2d21bde5e2c9e2. Python OUTPUT.json SHA-256: 48f4add88358e738256d2ddcd87571ac503b865c7ef9ad30c7d90328a632f5d1. Finite checks neither certify quantum hardness nor implement native PQ signing.

**Critical unresolved equation:** Need a classical-PPT, witness-free arbitrary-ORIGINAL-NP compiler Comp(R,x,claim,context,pk)->(A_x,U_x,capsule), public Phi(R,x,W) for every valid ORIGINAL W and one common precommitted K, security of the complete public view for **every** fixed FALSE instance including mod-p-rank-degenerate hard formulas, and arbitrary unauthorized hard-TRUE final-K recovery or native forgery -> actual ORIGINAL witness or an independently justified QPT break, without assuming an adversary-supplied representation or SOURCE oracle. Fixed-D mod-p refutability is efficiently recognizable, and therefore DOES NOT solve generic NP-WKEM or hard-TRUE knowledge extraction. The fatal odd-prime pseudo-opening results still apply to those old exact constructions. Malicious N-of-N preauthorization with honest erasure/no bypass, abort/pre-funding DA/graph, actual SYS/BTC AuxPoW/coinbase ancestor/interval/window/source qualification and Bitcoin censorship assumptions, and the hypothetical no-EC-key-path native PQ endpoint remain unresolved. Only after all those obligations are met may the research automation be disabled.

**Provenance:** Bounded offline 2026-10-29 continuation in authorized syscoin/PVUGC existing open/draft/unmerged PR #1, branch research/pq-wkem-validation-20260918, checked starting head c23ed198a17fdc65c16d97e863bf2d4127d79a1d and latest substantive ordinary comment 6498046651. Exact-version Macaulay predecessor, negative Pasch and adaptive opening research notes were read; no external literature, web research, unrelated repositories or independent agents. Authorized publication consists ONLY of three new files under research/pq-wkem/ and a separately verified ordinary top-level PR comment.
