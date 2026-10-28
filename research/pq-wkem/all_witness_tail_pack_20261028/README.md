# All-witness tail packing: restricted unplanted LWE SOURCE
**Status:** restricted release resource improvement with negligible-error completeness; NOT a generic-NP or Bitcoin/Syscoin witness-KEM. Offline work dated 2026-10-28 UTC. No external research.

**Exact continuity:** syscoin/PVUGC draft PR #1, branch research/pq-wkem-validation-20260918, prepublication head d202c3d8f84a9b572704cffa170bff1169f43ac4. Latest substantive comment examined: 6460926444. Exact predecessor blobs: unplanted_hard_true_20261027/RESEARCH.md = df442f4bc3013d8cb62dddc0d6cc3d06140b8d35; capacity_optimal_radix_20261027/RESEARCH.md = 2904f9ab021bbbc270a7293063a4777bf8c537a0; stacked_source_lwe_gate_20261027/RESEARCH.md = 253bf988180b795b908a7b43b989b58a0ec99ed4.

## Release algorithm and exact distributions

Classically sample independent B uniform in F_q^(d x n), K,U,Z uniform independent 256-bit strings, an ACTUAL native native-checking key pk(K) from a deterministic seed-key generator, and per-column s_j uniform in F_q^d and epsilon_j independently uniform in {-1,0,1}^n. Parameters: q=65537 (prime), d=256, n=4240, h=2120, e0=(1,0,...,0), E=727, spacing g=1455, base m=floor(q/g)=45 and ell=47 columns. The ONLY SOURCE here is

    Rker(B,w)=[w binary, w[0]=1, HammingWeight(w)=2120, B*w=0 mod q].

Let a_j be 47 base-45 digits of integer Z with zero padding. Publish relation identity, B, the complete claim/UTXO/branch/anchor/window/context and intended native checking key/path, D=U XOR Z, V=K XOR U, and

    p_j = B^T*s_j + epsilon_j + 1455*a_j*e0 (mod q).

Off-chain Release verifies the restricted predicate Rker(B,w), computes r_j=w^T*p_j, finds the unique cyclic center 1455*a within distance E=727, reconstructs Z and K=V XOR D XOR Z, verifies pk(K), and signs only the intended challenge path. The canonical 256-bit Z fits since 45^46 < 2^256 <= 45^47; the wraparound gap from the last center to zero is at least 1455. DISTINCT valid w may have distinct intermediate states; no canonical witness or common preimage is required. All honest algorithms are classical PPT asymptotically for polynomially bounded parameters. This is a random-kernel puzzle, NOT an external ORIGINAL burn/NP compiler; the random SOURCE is not guaranteed to yield an efficiently obtainable witness even when true.

## All-witness proof, including adaptive witness choice

For every (h-1)-subset S of {1,...,n-1}, let w_S=e0+sum_{i in S} e_i; N=binom(n-1,h-1), X(B)=number of such w_S with B w_S=0, mu=N/q^d. Distinct anchored w_S are pairwise linearly independent, so the uniform-B kernel events are pairwise independent:

    E[X]=mu, Var[X]=mu*(1-q^-d),
    delta_false=Pr_B[X=0] <=(1-q^-d)/mu <q^d/N <2^-136.

The new guarantee is NOT a single-witness average. Let G be the event that EVERY valid restricted w, simultaneously for EVERY one of the ell ciphertexts, has |w^T epsilon_j|<=727. The errors are independent of uniform B, and for fixed w the projected error is a sum of h independent uniform ternary variables. At t=ln(7/4), its exact coordinate moment is (7/4+1+4/7)/3=31/28. Two-sided Chernoff and a union bound over all N potential witnesses and all ell ciphertexts yield

    Pr[not G]
      <= ell*(N/q^d)*2*(31/28)^h*(4/7)^(E+1)
      =47*N/65537^256 * 2*(31/28)^2120*(4/7)^728
      <2^-133.

The inequality is certified by INTEGER arithmetic, not an estimate: write num=2*47*N*31^2120*4^728 and den=65537^256*28^2120*7^728, and check num*2^133 < den and N >65537^256*2^136. Since Pr[X>0]>1-2^-136, Pr[not G|X>0]<2^-132, also integer-certified. On G, every accepted w satisfies w^T p_j=1455*a_j+w^T epsilon_j (mod q), so ALL accepted witnesses recover the identical a_j, Z and precommitted K, EVEN if a QPT adversary selects w after observing all public ciphertexts. This is negligible-error over honest setup and noise, not the earlier PERFECT correctness for every possible noise draw; that precise limitation is retained.

## Full joint public-view QPT assumption and reduction

For an unconditioned uniform B target, ordinary decisional LWE is the arbitrary-QPT indistinguishability of (B,B^T s+epsilon) and (B,y uniform), using exactly q=65537,d=256,n=4240,chi=uniform ternary and efficiently generated independent quantum advice. This is an INDEPENDENT assumption, not proven 128-bit security or a classical-to-quantum lift. A straight-line, target-only, ell-column hybrid inserts the challenge as p_j=y+1455*a_j*e0; all other target columns are honest and all independently keyed SOURCE siblings remain real. In the final hybrid p_j are uniform; for each FIXED genuine native K, the map (U,Z)->(D=U XOR Z,V=K XOR U) is exactly bijective and produces jointly uniform D,V even conditioned on the ACTUAL native checking key pk(K). The native QPT EUF-CMA challenger supplies that genuine key and answers permitted classical signing queries; recovering usable K enables a fresh signature, and a fresh intended-path forgery is directly its EUF-CMA win. No SOURCE opening oracle, supplied adversarial representation, random-oracle programming or rewinding appears.

The ENTIRE classical public transcript includes Rker, B, capsules, checking key, intended context, auxiliary data, related independently keyed/independently sampled-B capsules and classical adaptive sibling openings/signatures. Target-secret-dependent hidden auxiliary inputs, a target opening, shared-B siblings, malicious setup retention, and coherent quantum signing/oracle queries are outside the claim. Arbitrary QPT adversaries may coherently process all classical data and efficiently sampled independent quantum advice. One unopened target conditioned TRUE obeys

    Pr[unauthorized usable target seed OR fresh native path signature]
      <=47*Adv_QPT-DecLWE(256,4240,65537,chi)
        +Adv_QPT-EUF-CMA(native)+delta_false.

Conditioning uniform B on TRUE changes the complete jointly sampled view by at most delta_false, and coherent postprocessing cannot increase this distance. The correctness event G is NOT conditioned on in this security bound. Multiple independent targets incur the corresponding target-hybrid sum, and sharing target B with an opened sibling invalidates this game. Furthermore any QPT distinguisher on 4240 samples gives one on the previous 4500 samples by discarding 260 samples: the new LWE premise is no stronger at fixed q,d,chi. Neither is certified for concrete 128-bit quantum hardness.

## Measured resource change and executed checks

Predecessor uniform-B true-source illustration: n=4500,h=2250, deterministic E=2250, base14, 68 columns, 306,000 ciphertext field elements and 1,152,000 B field elements. New: n=4240,h=2120, statistical E=727, base45, 47 columns, 199,280 ciphertext elements (**34.875817% fewer**) and 1,085,440 matrix elements (**5.777778% fewer**). Matvec work per capsule drops from 78,336,000 to 51,015,680 field multiply-adds; total matrix-plus-ciphertext elements drop from 1,458,000 to 1,284,720 (~11.885%). Public objects still occupy megabytes; no practical BTC deployment claim follows.

Published check.py is the EXACT executed offline standard-library checker. Its captured output is checks.jsonl (two identical complete runs). It verifies the large integer inequalities, all 45 distinct pairs of a toy kernel candidate-event family, and two distinct valid toy witnesses' digit recovery whenever the joint good-error condition holds. An EXTENDED independently executed local checker additionally passed 76,737 assertions TWICE with identical output, exhausted 2,187 ternary toy errors, and tested twelve complete 256-bit same-K openings. Extended local files and full note are preserved in a separately downloadable archive, but only the published checker is claimed as a GitHub-executed version. Toy PRNG, toy digest and planted toy B are not used for security sampling and are not native-PQ implementation.

## EXACT missing ORIGINAL equation and untouched security requirements

Still missing: one classical polynomial-time compiler mapping EVERY arbitrary original (R,x) and EVERY valid original W to a SOURCE-dependent public B_x and opening f_x(W,capsule) such that EVERY ORIGINAL W recovers the SAME precommitted native capability; full correlated relation/capsule/checking-key/auxiliary/related-capsule false-instance QPT simulation; and arbitrary hard-true unauthorized recovery or native forgery -> ORIGINAL W or INDEPENDENT justified QPT break without requiring an attacker-supplied intermediate representation. The prior stacked-row simulator has an ordinary-LWE short-kernel opening incompatibility and is not repaired here. Random true-source binding does not authenticate actual SYS/BTC evidence. The N-of-N honest-erasure ceremony, no bypass, useful abort handling, one-of-N watchers, PoW/DA/fork/tag/window validation, native PQ checking keys, conditional P2MR-like Bitcoin output and transaction graph are all unproved. This restricted efficiency lemma is not practical generic NP witness encryption; keep the research automation enabled.
