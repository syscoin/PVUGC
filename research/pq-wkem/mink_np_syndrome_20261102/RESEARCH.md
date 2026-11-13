# MINK-NP-SYNDROME-20261102-R18

**STATUS: rejected SOURCE candidate, no positive secure generic PQ witness-KEM advance.** This iteration tests the exact missing generic-ORIGINAL Build/Lift rather than optimizing proof bytes. The compiler below gives honest classical-PPT correctness for every valid ORIGINAL witness, without the builder knowing a witness, but an explicit polynomial-time classical attacker decrypts on arbitrary FALSE and hard-TRUE statements. The full-public QPT security/recovery-to-ORIGINAL obligation is NOT satisfied.

## Continuity and scope

Started from draft/open/unmerged syscoin/PVUGC PR #1 at f59c1d022d95866ce08f086566a351293e6ad5e3, branch research/pq-wkem-validation-20260918, latest substantive ordinary comment 6581648937. Exact R17 RESEARCH.md blob 5c2c6e144e00d6b14ad0f33ac24aab521c191951 and R11 RESEARCH.md blob e2e47d88cc54f16478eaee8638df98c9ea4245bd were read. No external web, literature or other repos. Unlike R11, this candidate compiles an arbitrary NP original relation, but does **not** inherit R11's ordinary-QPT-LWE security theorem: its public key has an NP-dependent structured distribution.

Honest algorithms are classical PPT, messages classical, and adversaries may be arbitrary QPT with general independent/related quantum advice. Since the attack is already classical and uses only the capsule, it applies under **all** such access/advice models, including multiple related capsules and selective opening. No quantum rewinding, random oracle, extraction oracle, keyless Build, deployed Bitcoin functionality, or native PQ signature implementation is assumed.

## 1. Explicit generic SOURCE Build and Lift

Bind x to ORIGINAL relation identity, claim/UTXO, intended branch, source anchors/window, verification-key identity and context. Compile the polynomial-time ORIGINAL NP verifier into a standard 3CNF with n variables and c 3-literal clauses, preserving a polynomial-time witness extension and reverse witness recovery. Different valid witnesses need not share internal states.

Build an integer matrix A of d=n+3c rows, M=2n+4c columns and b=1^d. Each variable has a selector pair (t_i0,t_i1) summing to 1. Each clause has two slack pairs (a_j1,a'_j1),(a_j2,a'_j2), each summing to 1. The clause row reads:

    sum over its three TRUE-literal selector coordinates
        - a_j1 - a_j2 = 1.

There are B=n+2c pairs in total. A valid 3CNF assignment sets exactly one selector in each variable pair to 1. If a clause has k=1,2,3 satisfied occurrences, put its two slack bits (a_j1,a_j2)=(0,0),(1,0),(1,1) respectively and set complements. Thus for **every** valid ORIGINAL witness w there is an explicitly computable binary vector s_w with

    A s_w = b (over integers),    ||s_w||_1=B.

The builder does not need w to generate A,b. For each protected key-seed bit mu, fix prime q, bounded eta and Delta=floor(q/2), sample fresh independent r uniform in F_q^d and e uniform in [-eta,eta]^M, and publish

    u = A^T r + e (mod q),
    v = b^T r + Delta*mu (mod q).

Publish contextual manifest, genuine intended native vk, checking material and related capsules as required. Lift checks the ORIGINAL witness, computes s_w, uses the nearest circular center {0,Delta} of v-<s_w,u> and verifies reconstructed capability against the native vk/context. Large evidence and all operations remain off-chain. Native PQ signature/Bitcoin endpoint is explicitly conditional.

**Exact SAME-capability correctness:** for every valid w,

    v - <s_w,u> = Delta*mu - <s_w,e> (mod q).

If Delta/2>B*eta, the error has magnitude at most B*eta, so every valid w recovers the same exact precommitted mu, hence the same complete K, independently of witness representation. A short *integer* solution s with As=b and ||s||_1<=B must have each pair exactly (1,0) or (0,1), hence is a satisfying assignment and can map to an ORIGINAL witness. This supplied-representation fact does not extract a witness from arbitrary recovered K.

## 2. Fatal full-public classical key recovery

For **any assignment whatsoever**, construct a signed integer solution s_bad using the same variable selector pairs but, for a clause with k satisfied literal occurrences, choose its (a1,a'1,a2,a'2) as:

    k=0: (-1,2,0,1)
    k=1: ( 0,1,0,1)
    k=2: ( 1,0,0,1)
    k=3: ( 1,0,1,0).

Every pair row and clause row is still satisfied over integers. If u(a)<=c is the number of unsatisfied clauses of the chosen assignment, then exactly

    A s_bad = b,
    ||s_bad||_1 = B+2u(a),
    ||s_bad||_2^2 = B+4u(a) <= 3B.

The attacker can simply choose the all-zero assignment and calculate s_bad in polynomial time, without an ORIGINAL witness. Although s_bad is not a valid binary representation of an unsatisfied formula, **the capsule's linear decryption cannot enforce binary membership**:

    v-<s_bad,u_cipher> = Delta*mu - <s_bad,e> (mod q).

If Delta/2>(B+2c)*eta, this recovers the key *deterministically for every capsule* even for an ORIGINAL FALSE formula. More generally, independent symmetric error coordinates and Hoeffding's inequality imply, under the nominal honest worst-case completeness Delta/2>B*eta,

    Pr[bad decoder fails for a bit]
      <= 2 exp(-Delta^2/(8 eta^2 ||s_bad||_2^2))
      <= 2 exp(-B/6).

For B >= 6(lambda+1) ln 2 this is at most 2^(-lambda) *for the attacker*, with polynomial multiple-key-bit loss. This classical unauthorized recovered-key adversary neither breaks QPT-LWE nor native-signature security nor reveals an ORIGINAL witness. It breaks hard-TRUE final-key soundness as well as universal FALSE security.

The fatal witness-free attack uses only public relation/statement and capsule, so authentic checking key, genuine native vk, context, auxiliary data, audit openings, related capsules and selective openings do not rescue it. There is **no** full joint public-view simulator, no all-FALSE QPT security, and no valid arbitrary recovered-K -> ORIGINAL witness/independent PQ break theorem for this construction.

## 3. One concrete repair tried and rejected

Encrypt independent XOR capability shares per clause, each using a locally valid assignment, so a clause's slack pair is binary and the above signed solution for that clause is unavailable. This fails GLOBAL consistency: for the false formula (z OR z OR z) AND (NOT z OR NOT z OR NOT z), the adversary uses z=1 to open the first share and z=0 to open the second, then XORs them to recover the actual K. The executable checker reproduces 256/256 such recoveries. Hashing the local assignments does not provide a witnessed **common hidden-value binding** and would make different ORIGINAL witnesses yield different tags. A proposed repair must prevent local switching without reintroducing an independent WE/iO/WPRF assumption or a publicly evaluable affine invariant.

## 4. Exact executed checks / limitations

The published standalone checker.js is precisely the self-contained function executed twice in this run with byte-identical JSON results. It exhausts 4096 ordered 2-clause 3CNFs over two variables and all four assignments, tests two distinct valid ORIGINAL witness states with 256 dual-style ciphertexts, demonstrates 512/512 public false-source decryptions at prime q=41 and eta=1, enumerates all 3^10 error vectors at q=23 for both bits (116559 correct, 1539 failures for the **attacker**), and tests 256 clausewise-share switching recoveries. The separate longer **local-only** Python standard-library checker with seed 2026110218 passed 129296 assertions twice and had identical outputs; SHA256 of Python source a3bd32ed8e145043db44f8377faad21cbbe924a73856d4964c006ec4, output 02ba8b399f00ad2cf2588f14c636fb69fc65b9f5242250f196a5ffca2591bd8a. Neither tests quantum hardness or implements native PQ signatures or the entire setup graph.

## Exact next missing equation

Find a polynomial-time, globally nonlinear SOURCE compiler that prevents **any** efficiently computable non-ORIGINAL integer/fractional/locally switched representation from releasing K, while preserving Lift(R,x,C,w)=K for **every** ORIGINAL witness, with full checking-key/capsule/context/native-vk/auxiliary/related-capsule QPT challenge simulation and arbitrary recovered final K or accepted native signature -> ORIGINAL witness or independently justified PQ break. Malicious one-honest N-of-N ceremony/abort, DA/source-fork and conditional native Bitcoin endpoint remain open. **R18 is a rejected direction, not a construction success.**
