# Capacity-optimal bounded-noise radix for restricted target-only LWE SOURCE release

Research-only offline continuation, 2026-10-27. Repository syscoin/PVUGC, draft PR #1, branch research/pq-wkem-validation-20260918. **Starting verified head:** 2e4e3c9f1d7032268a9801e33607e6d488113035. **Exact preceding construction:** research/pq-wkem/target_only_lwe_selective_open_20261027/RESEARCH.md, blob c74c4b67b08f9a30369293babcde85c185c8f04b. No internet/literature research or independent agents.

**Scope:** This is an actual efficiency improvement to an independently described, restricted random-kernel release. It is NOT a generic-NP/BTC/SYS witness-KEM, an independently certified security level, or a completed hard-true ORIGINAL-witness extraction theorem.

## Previously unfinished practical release step and new algorithm

The predecessor uses one LWE ciphertext column per radix-128 digit of a 256-bit Z pad: with q=65537, g=512, weight h=2, error coordinates from {-1,0,1}, it takes 37 columns. But a valid binary weight-2 witness has projected absolute error at most E=2. A codepoint spacing of 512 wastes almost all of the bounded-error channel's capacity.

**Exact new release algorithm, classical PPT.** For any modulus q, binary kernel witness weight h, and supported integer error bound |eps_i|<=beta, let E=beta*h, g=2E+1, and radix m=floor(q/g), requiring m>=2. Convert the 256-bit Z to its canonical integer in [0,2^256), express it in base m (least significant digit first), and left-pad the digit vector to exactly ell=ceil(256/log2 m) entries. Generate independent (s_j,eps_j) for every digit, and publish:

    B <- uniform Z_q^(d x n), e=(1,0,...,0)
    p_j = B^T s_j + eps_j + g*t_j*e  (mod q)
    s_j <- uniform Z_q^d, eps_j <- chi^n on [-beta,beta]^n

Generate independent 256-bit K,U,Z, compute the *real* native (sk,pk)=SeedKeyGen(K), and publish D=U XOR Z and V=K XOR U, the actual pk and all public relation/claim/branch/UTXO/anchor/window/context labels. Source predicate for this **restricted** setting is R_B(B,w): w in {0,1}^n, w_0=1, sum(w)=h, Bw=0 (mod q). This SOURCE does not verify arbitrary ORIGINAL relation evidence.

Every accepted restricted witness w computes r_j=w^T p_j (mod q); its decoder selects the unique nearest cyclic center among {g*t:0<=t<m}, rejects if cyclic distance exceeds E, reconstructs Z and checks the 256-bit integer range. It then obtains K=V XOR D XOR Z, checks its derived native pk, and may produce an ordinary native signature on the intended claim-scoped challenge path. All valid w recover the **same precommitted K** although their w and error projections may differ.

## Proof 1: deterministic all-witness correctness and exact radix optimum

For any accepted w, Bw=0 and w^T e=1, so

    r_j = g*t_j + w^T eps_j  (mod q);
    |w^T eps_j| <= h*beta = E.

The minimum adjacent cyclic spacing is g, and the last-to-first gap is q-(m-1)*g >= g. Hence each radius-E error ball about a center has exactly 2E+1=g residues, and these balls are disjoint. The nearest center recovers t_j uniquely *for every permitted error draw* and for every accepted w, regardless of whether distinct w have distinct intermediate states.

For any **coordinatewise** one-scalar, exact-error decoding code in Z_q with alphabet size m', the m' balls of 2E+1 residues must be disjoint, implying m'(2E+1)<=q. Therefore m'<=floor(q/(2E+1)). Our equally spaced centers attain this bound exactly. This is capacity optimal only for this particular deterministic scalar/release interface, **not** arbitrary nonlinear/correlated codes, general witness encryption, or alternate error models. If chi has unbounded/subgaussian tails, use a chosen statistical/all-witness failure budget and a corresponding E; do not reuse the deterministic ternary guarantee.

At q=65537, beta=1, h=2: E=2, g=5, m=13107, log2(m)=13.67805..., ell=19. Since m^18<2^256<=m^19, this is the **minimum fixed-length column count** for the packed 256-bit pad under this alphabet. The predecessor with g=512,m=128 uses ell=37. The reduction is 18/37=48.648648...% in LWE ciphertext columns and their n-coordinate public field elements; the number of fresh LWE samples, matrix-vector multiplications, and target-only LWE hybrids also decreases from 37 to 19. The public matrix and key lengths are unchanged. No changes to the underlying q, d, n, h, chi, LWE hardness premise, native signer, or opening permissions are needed for this comparison. The finite q=65537,n=6,d=3 check is toy algebra, not a 128-bit parameter set.

## Proof 2: full-public coherent-QPT target-only LWE hybrid remains valid

The target **must** be generated with independent, *unconditioned uniform* B, with no planted source opening. Each target LWE challenge gives the same B and either y=B^T s+eps or a uniform y in Z_q^n. A classical straight-line distinguisher may know K,U,Z when embedding a column, generate digit t_j deterministically, and publish p_j=y+g*t_j*e. The addition is an efficiently computed group translation independent of the LWE challenge bit. Its size (g=5 rather than 512) plays no role in the ordinary decisional-LWE indistinguishability claim.

In the jth hybrid, leave all other target columns **honestly** generated from the same B with independent s,eps. Leave all sibling capsules, their checking keys, SOURCE openings, allowed native signatures and disclosed coins **real**, including adaptively disclosed true siblings. Crucially, DO NOT uniformize a legitimately opened sibling: its kernel witness distinguishes that operation. An adaptive selection of one target among T unopened claims may be handled by a fixed guessed target index, or a multi-target sum. Separately challengeable sibling scopes need independent B and native K; sharing B allows known sibling witnesses to decrypt a target even with distinct native keys.

Each switched target column costs at most Adv_QPT-DecLWE(d,n,q,chi) against arbitrary QPT with classical adaptive oracles and allowed efficiently generated quantum advice independent of hidden target coins. After ell switches, all p_j are jointly uniform and independent of Z, even when digits are highly correlated and nonuniform. For **each fixed real K**, conditioning on the actual native checking key pk(K), the map

    (U,Z) -> (D=U XOR Z, V=K XOR U)

is bijective on two independent uniform 256-bit strings. Thus (D,V) is jointly uniform and independent of K and pk, not merely marginally hidden. This is an exact complete-public-view simulator at the last hybrid, not a SourceOpen oracle. A simulator receiving only a real native EUF-CMA challenge pk can draw independent D,V and uniform p, generate siblings honestly, forward allowed target native signing queries, and turn a final recovered usable signing seed or fresh intended-path signature into a native EUF-CMA forgery. The bound is:

    Pr[target unauthorized usable seed or fresh native signature]
      <= ell*Adv_QPT-DecLWE(d,n,q,chi) + Adv_QPT-EUF-CMA(native).

Here ell=19 for the indicated bounded-error example, versus ell=37 previously. The native signature assumption concerns arbitrary QPT adversaries with classical adaptive signing queries. No classical rewinding, quantum random-oracle programming, generic-group security, or supplied internal representation is assumed for this restricted target.

**Exact joint-view restrictions:** The relation/statement, capsule, native checking key, context, auxiliary data and related capsules must be generated together. Target auxiliary information may depend on its public B, real checking key, permitted native signing responses and public claim/context, but must not secretly depend on K/U/Z or reveal a target valid opening. Related capsules may be adaptively opened only if generated with independent target secrets and classically simulatable without target K; authorized signature transcripts are preserved. Arbitrary target-key-dependent advice, quantum oracle access to hidden signing secrets, corrupt malicious setup coins, and shared SOURCE kernels are outside this bound. The same theorem does **not** cover an attacker-selected false ORIGINAL NP statement, a structurally compiled B_x, a target whose matrix is conditioned on a witness, or arbitrary unauthorized hard-true key recovery.

## Executed checker, exact recorded output and provenance

Files in this directory:
- check.py: **the exact executed** standard-library Python source (SHA-256 ffcccf23888ac9d92fdb939229f60869ff7cbee0378e6dcde47d6aef38c5b484; git blob c7ae60c3d0fe961597e8b43ddacacc0689030213).
- checks.jsonl: actual stdout of two successive completed executions, byte-identical JSON rows (SHA-256 e4296f31ff873ba9abd1a8ba981e6f2de7d56db4121bedde7268b15106f8f76b).
- Run locally: python check.py (Python standard library only). The deterministic seeded PRNG is for testing only and MUST NOT be used for actual key generation.

Each completed run passed **13,385 checks**: exact small-field q=31 decoding intervals and alphabet bound; all 3^6=729 independent ternary error vectors for two distinct true weight-h witnesses and six centers; 96 complete 256-bit K/U/Z releases under q=65537, both valid witness openings recovering the same K; an explicitly labeled SHA-256 checking-key *surrogate*; and exhaustive q=31 challenge-translation permutations. None tests native SLH, LWE/QPT hardness or 128-bit security.

Captured identical run output (each of the two rows):
{"baseline_columns": 37, "baseline_radix": 128, "checks": 13385, "column_reduction_pct": 48.648649, "columns": 19, "distinct_true_witnesses": 2, "error_abs": 1, "error_max": 2, "exhaustive_error_vectors": 729, "experimental_security_bits": "NOT ESTABLISHED", "full_key_trials": 96, "minimum_spacing": 5, "q": 65537, "radix": 13107, "small_capacity": 6, "small_q": 31, "status": "PASS", "weight": 2}

The checker creates an explicitly source-conditioned B with TWO valid witnesses only for completeness testing. That B is **not** substituted for the uniform target B in the security reduction, which would invalidate ordinary LWE challenge simulation. Previous misleading ghost-opening, row-shift, local-label switching, affine/low-degree closure and false-source extrapolation pitfalls are unchanged; this result does not bypass them.

## Exact handoff / ORIGINAL obligation (unproved)

We still need a classical polynomial-time compiler taking *every* ORIGINAL generic-NP or SYS/BTC (R,x) to a source-dependent B_x together with an opening map for **every** valid ORIGINAL witness W, such that B_x f_x(W)=0, anchor=1, and **every** W recovers the identical precommitted native capability. Its whole public relation/capsule/checking-key/auxiliary/related-capsule distribution must be generated in the same independently justified QPT simulator, without a SourceOpen oracle or a hidden common-preimage assumption. Arbitrary QPT hard-true final-key recovery or native forgery must imply an ORIGINAL witness or independent PQ break without the adversary volunteering a representation. Full false-instance security for all x, malicious N-of-N ceremony and erasure/abort, one-of-N watcher/ChainLock separation, PoW/source validation, DA/censorship/reorg limits, conditional P2MR-like/native SLH-like Bitcoin endpoint and graph composition remain unproved. This is only a meaningful restricted efficiency step; **do not claim a complete practical witness-KEM**.
