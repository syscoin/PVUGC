# Dual-LWE short-preimage SOURCE: genuinely distinct openings, common native capability

**Outcome: positive restricted cryptographic component, NOT completed generic-NP witness-KEM.** This construction replaces the preceding primal bounded-error LWE SOURCE with a dual short-preimage SOURCE. A witness-free Build operating on its public SOURCE can release ONE precommitted capability through genuinely different valid SOURCE witnesses, with a straight-line complete-public ordinary QPT decisional-LWE simulator. The missing compiler from arbitrary ORIGINAL R,x, every-fixed-false security, and malicious setup/Bitcoin endpoint remain unsolved.

**Provenance:** offline 2026-10-28 automation turn 11, syscoin/PVUGC open/draft/unmerged PR #1, branch research/pq-wkem-validation-20260918; start 7f1b34f1a1df893664f13395ef63dc4700f63adc. Latest substantive ordinary comment 6487533091. Read exact starting-version predecessor global_A_cross_source_20261028/RESEARCH.md (blob 782140e07064322cb04d53693c62999a85e9f1ee), batched_matrix_lwe_source_20261028/RESEARCH.md (blob fcc271ce0f9bcab661f28b2b0e5158ae57b94490), and failed two_tier_public_proxy_20261028/RESEARCH.md (blob 6fca0ecbb6aa733039be88fda3ab315d69fb956a). No external web or literature research.

## Exact algorithms and distributions

Let q be an odd prime, m>n, positive d,t,h,kappa, 2h<q, g=2h+3<q, radix T=floor(q/g)>=2, ell=ceil(log_T(2^kappa)), L=ceil(ell/d). Noise chi is uniformly independent {-1,0,1}. Let S(m,h) be all signed integer m-vectors with L1 norm exactly h, of cardinality

    N(m,h) = sum_{k=1}^{min(m,h)} 2^k C(m,k) C(h-1,k-1).

An exact classical polynomial sampler picks support cardinality k according to these integer weights, uniformly picks its k support positions, a uniformly random positive composition of h into k integers, and independent fair signs. A production implementation requires CSPRNG and unbiased integer sampling; checkers are deterministic toy tests.

For a **restricted planted-TRUE SOURCE** sample A uniform in F_q^(n x m); independently sample d columns z_j uniform from S(m,h); compute U=A Z in F_q^(n x d). The public SOURCE is A,U, and Build receives NEITHER Z NOR a SourceOpen oracle. The restricted ORIGINAL witness relation is ANY integer matrix W of d columns satisfying A W=U (mod q), with each column L1 norm at most h, plus the exact public claim/path/relation/context/checking-key bindings. This is NOT generic arbitrary NP and is NOT itself authenticated Bitcoin evidence. Planting Z means the SOURCE creator knows an opening immediately; this is disallowed as a bypass in the eventual future-fork application. No source-generator erasure or malicious setup is proved.

For the honest Build, generate native capability K and actual public native verification key pk(K), plus independent uniform kappa-bit U0, XOR shares Z_1,...,Z_t. Publish D=U0 xor XOR_i Z_i, V=K xor U0. Encode each share in base T and zero-pad the last d-digit batch. For each share and each batch sample fresh independent s uniform in F_q^n, e uniform chi^m and eps uniform chi^d. Publish complete ciphertext

    c = A^T s + e                 (m field elements)
    v = U^T s + eps + g*a         (d field elements)

where a is that batch's d radix digits. Never reuse coins across batches. Public transcript is R,x,A,U, genuine pk(K), D,V, all c/v, claim/UTXO, branch, anchors/window, contextual verification identity, permitted auxiliary data and related capsules. Large evidence and ORIGINAL verification remain OFF CHAIN. Honest SOURCE/Build/Release are classical PPT.

## Pointwise EVERY-ORIGINAL-witness correctness

For EVERY valid accepted restricted witness W, independently of its relationship to planted Z,

    v - W^T c = g*a + eps - W^T e (mod q).

For each coordinate |eps_j-w_j^T e|<=1+||w_j||_1<=h+1. Centers g*a are at least g=2h+3 apart cyclically, including the wrap gap q-g(T-1)>=g. Hence nearest cyclic center unambiguously decodes every digit for ALL honest coins and ALL valid W. Recover all XOR shares and compute exactly K=V xor D xor XOR_i Z_i. The resulting native K is the ONE precommitted K regardless of distinct W and distinct intermediate residual states. Source preimages are not required to be canonical or equal. The published checker obtains TWO genuinely distinct accepted W under a sampled (not deliberately singular) uniform toy A and obtains identical K through both.

## Complete-public planted SOURCE statistical lemma

For z,z' distinct in S(m,h), 2h<q ensures z-z' nonzero mod q. For random A, A(z-z') is uniformly distributed over F_q^n. Thus

    E_A Coll(Az|A) = 1/N + (1-1/N)/q^n,
    TV((A,Az),(A,U_uniform)) <= delta_src = (1/2)sqrt((q^n-1)/N).

For d SOURCE columns independently drawn given the SAME A, conditional tensorization and averaging give TV((A,AZ),(A,U_uniform_matrix)) <= d*delta_src. This is a JOINT distribution bound averaged over honest uniform A, NOT a per-fixed-A result. Revealing planted W or witness-dependent auxiliary data invalidates this simulation. Independently generated genuine native checking keys, correlated XOR shares, permitted public context, independently generated related capsules and classical Open transcripts are simulatable channels applied to this joint public distribution; classical total variation/quantum data processing preserves the bound. Independently planted non-target U_j under shared A with their source W_j and coins revealed are simulatable by the reduction, provided the target source witness remains secret.

## Exact ordinary QPT decisional-LWE simulator and adaptive openings

After replacing planted U with uniform, H=[A^T;U^T] is exactly a uniform (m+d) by n matrix. Each honest ciphertext with its known plaintext shift removed is y=(c,v-g*a)=H s+nu, where s uniform F_q^n and nu uniform chi^(m+d): EXACTLY an ordinary decisional-LWE challenge distribution, rather than a marginal pad-hiding claim. Given one real-or-uniform (H,y), the straight-line simulator embeds y into any selected hidden target share's chosen batch, shifts its final d components by g*a, generates every other share/batch using known independent coins and the SAME H, and generates genuine pk(K), D/V, typed context, auxiliaries and eligible related capsules. It does not know the challenge s or source Z, nor invoke SourceOpen, quantum rewinding, a random-oracle extractor, or any adversary-volunteered representation. The selected hidden share's L independent batch ciphertexts can be hybridized at cost L*Adv_QPT-DecLWE(n,q,m+d,chi).

Open(i) is a classical query disclosing an entire target share AND all encryption coins (s,e,eps) for every batch, which exactly replay public c/v. The adversary may adaptively open at most t-1 WHOLE shares. Guess uniformly a survivor J and count success only if it never opens J; every successful transcript has probability at least 1/t of retaining the chosen survivor. Only J's ciphertexts are replaced; other Open replies are genuinely coin-consistent. In the final native-signature simulator, use real native pk(K) from the QPT EUF-CMA challenger without K, sample independent uniform D,V, keep other shares/coins genuine and J ciphertexts uniform. For fixed unknown K and other shares, the mapping (U0,Z_J)->(V,D) is a bijection, so the full public checking-key/XOR distribution is EXACT. Forward classical signing queries and require freshness on the intended path. An output usable native K produces a fresh valid signature, or an adversary's fresh native signature directly wins EUF-CMA.

Therefore under honest planted restricted SOURCE, ordinary QPT DecLWE at the EXACT uniform-secret ternary-noise (n,q,m+d) distribution, and independently QPT-EUF-CMA native signatures, for arbitrary QPT processing of classical public data and challenge-independent efficiently preparable quantum advice, with classical signing/Open interfaces:

    Pr[unauthorized usable K OR fresh path-native forgery]
      <= t * ( d*delta_src + L*Adv_QPT-DecLWE + Adv_QPT-native-EUF-CMA ).

No quantum superposition signing/opening oracles, hidden-witness-correlated auxiliary leakage, target source witness disclosure, all t target share opens, malicious target setup, or arbitrary malicious related-capsule secret-release oracles are included. One must not silently lift a classical security argument to QPT. There is NO certified concrete QPT hardness for the chosen numeric illustration. If an unauthorized adversary outputs K, this proof supplies an INDEPENDENT QPT LWE/native break for this restricted average distribution, not an actual ORIGINAL NP witness.

## Exact resource example and executable verification

At illustrative q=65537,n=128,m=1600,d=14,h=800,t=3,kappa=256: log2 N=2770.7393955503; log2 delta_src=-362.368288904 and log2(d*delta_src)=-358.560933982. g=1603, T=40, ell=49, L=4. SOURCE A has 204800 elements, U has 1792, and encrypted capsules use 3*4*1614=19368; public SOURCE+ciphertext is 225960 field elements versus 228904 in the previous primal matrix-LWE source, a 1.286% total saving for one capability, excluding keys/context. Shared-A per-claim incremental public data is 1792+19368=21160 versus 22400+1704=24104. Ciphertext by itself is FAR LARGER than the prior primal design because it has m rather than n components. This is storage arithmetic, not a timing benchmark.

The EXACT committed JavaScript checker is generated from the same function actually executed twice in the connected V8 tool: PASS 22698 assertions each time, matching deterministic outputs; 12 complete 64-bit mock capability recoveries under TWO distinct accepted short source openings; full plaintext/coin replay; exhaustive 125 toy matrices with exact average one-/two-column total variations; and exact high-dimensional sphere cardinality/resource checks. The mock K is NOT SLH. An independent extended LOCAL-ONLY Python checker and its separate exhaustive finite-source checker additionally ran twice identically (9664 and 3750 assertions); they are in the downloadable local archive but not claimed to be committed. No quantum cryptanalysis was performed.

## Next exact unsolved equation and graph obligations

Need a classical polynomial-time public witness-FREE Comp(R,x,claim,context,pk)->(A_x,U_x,capsule) for ARBITRARY ORIGINAL NP, and OFF-CHAIN Phi(R,x,W) such that for EVERY valid ORIGINAL W:

    A_x Phi(R,x,W) = U_x mod q, max_j ||Phi_j||_1 <= h,
    Release(Phi(R,x,W),capsule) = the SAME precommitted K.

Distinct ORIGINAL W must be permitted distinct Phi states, without a canonical witness, common short preimage or a planted SOURCE witness retained by a setup entity. The compiler must hide its COMPLETE public output on EVERY FIXED FALSE ORIGINAL x and transform arbitrary unauthorized HARD-TRUE final-key recovery/fresh native forgery into an actual ORIGINAL W or an independently justified QPT break, jointly simulating all checking-key/auxiliary/multiple-capsule correlations. The current planted TRUE SOURCE cannot do this: appending an unrelated R(x,W) makes its preplanted short z a bypass. The earlier 3CNF/two-tier publicly cancellable pseudo-moment counterexamples remain fatal to those proposals. This is the precise unfinished compiler obligation, NOT a solved generic witness-KEM.

Also open: malicious N-of-N preauthorization with one honest party/erasure/no bypass; abort and prefunding DA; optional keyless Build with malicious coin retention; correct SYS/BTC tagged AuxPoW/header/ancestor/lag/window/best-chain evidence, censorship/reorg assumptions; and a hypothetical no-EC-key-path native PQ-only Bitcoin endpoint. None were implemented or deployed. Keep the continuing research automation enabled.
