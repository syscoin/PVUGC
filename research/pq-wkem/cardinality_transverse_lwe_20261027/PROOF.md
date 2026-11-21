# Cardinality-pinned transverse-LWE: lower-noise SAME-key release

Research-only, bounded offline 2026-10-27 continuation of mixed_linear_fourier_and_20261027/PROOF.md, starting draft PR #1 head baba2181129a3c719c6d7ae9500aca518d2c78b1. This is an **independently instantiated improvement for an unplanted random-linear reference relation**, not a Bitcoin PoW compiler or complete generic-NP post-quantum witness KEM.

## Explicit source-dependent classical release

Let q=2^a, g=2^nu, nu<a, d>=1, n>=h>=1, h|g, c=g/h, c*n<q. Let chi be independent per-coordinate LWE noise supported in [-beta,beta], with g>2*h*beta. The ordinary QPT decisional-LWE assumption used below is for EXACTLY dimension d, n samples, modulus q, and error chi; no parameter set is claimed 128-bit secure. Let NativeGenSeed generate a uniform k-bit actual native signing seed K and real checking key pk(K). The claim, UTXO, relation identity, branch, window, anchors, native verification key and intended signing path are explicitly bound into public context ctx. Let a public vector b'=(1,h_2,...,h_(d+1)) depend deterministically on pk and ctx, before fresh B is drawn.

Sample **B uniform in Z_q^(d x n)**. Set alpha=(c,...,c), A_1=alpha, A_(i+1)=B_i+h_(i+1)*alpha, and b=g*b' (mod q). Publish B, ctx, pk; A,b are publicly reconstructed. Define the ORIGINAL reference relation

    R_card(B;w) = [ w in {0,1}^n, wt(w)=h, B*w=0 (mod q) ].

For ALL binary w, the first row of Aw=b enforces c*wt(w)=g mod q. Because c*n<q and g=c*h, that is equivalent to wt(w)=h; the remaining rows then enforce B*w=0. Thus the two predicates are exactly equivalent **only for this particular structured reference source**.

Choose U uniformly in {0,1}^k, V=K XOR U, r=a-nu and ell such that ell*r>=k, and a fixed full-row-rank linear L from ell*r bits to k bits. Independently for each j, choose t_j uniform Z_q, u_j uniform Z_q^d, e_j from chi^n; compute

    p_j = alpha*t_j + B^T*u_j + e_j (mod q),
    z_j = t_j mod(q/g),
    D_L = U XOR L(z_1 || ... || z_ell).

Equivalently set s_j=(t_j-sum_i h_(i+1)*u_(j,i),u_j), which is uniform on Z_q^(d+1) and obeys b'^T*s_j=t_j, A^T*s_j+e_j=p_j. This is the ACTUAL source construction, with no SourceOpen oracle and no assumed planted witness. Independently, use the existing full-quotient Fourier/polar compiler and its true physical sampler to encrypt V under the arbitrary ORIGINAL NP relation R_N(pk,B,ctx;v). Publish the complete capsule: B,A,b,all p,D_L, NP SOURCE/ciphertext/public dither, native pk and checking/context/allowed-auxiliary metadata. Protect or erase U,V,K,s,t,u,e and NP-side mask coins according to the declared honest-erasure model; this is not keyless Build or a malicious MPC setup proof.

Recover with any R_card-accepted ORIGINAL binary w and any R_N-accepted ORIGINAL NP witness v: calculate y_j=w^T*p_j mod q; round to the nearest multiple of g around the q-cycle and output zhat_j in Z_(q/g). Since B*w=0 and wt(w)=h,

    y_j = g*t_j + sum_(i:w_i=1) e_(j,i) (mod q),

and the absolute error is at most h*beta<g/2. Therefore zhat_j=z_j simultaneously for **EVERY** valid w, with zero noise failure under the supported chi. Reconstruct Uhat=D_L XOR L(zhat), recover Vhat using the inherited polar decoder with v, output Khat=Uhat XOR Vhat and verify the real native pk(Khat) before OFF-CHAIN intended native signing. Every valid pair opens the identical PRECOMMITTED K except the previously certified NP-side simultaneous all-witness polar decoder failure epsilon_N. Different ORIGINAL witnesses and states need not coincide.

## Exact FULL-joint ordinary-QPT-LWE hybrid

Here A is not uniform, and no claim of uniform A is made. Crucially the public transverse B **is** exactly independent uniform, even conditioned on pk, ctx and public alpha. The secret u_j is independent uniform and e_j follows exactly chi. A straight-line challenge simulator receives standard LWE samples (B,c_j) where c_j=B^T*u_j+e_j or independent uniform. It generates the REAL K and pk, U,V, public b', alpha,A,b, t_1..t_ell, and all Fourier SOURCE/ciphertext coins of R_N protecting the actual V. It forms challenged p_j=alpha*t_j+c_j and constructs D_L with known t_j. Other columns are generated honestly or uniformly according to the telescoping hybrid. It also generates exactly simulatable related/native auxiliary material under the same chosen message/path game. No unknown LWE challenge secret or opening is requested. If c_j is real this is the exact real world; if it is uniform then p_j is uniform even conditioned on B, pk, t_j and all the non-target outputs. This is an ordinary QPT decisional-LWE embedding of source, opening and checking-key correlations TOGETHER.

After ell adjacent hybrids, p_j are independent uniform while every t_j remains independent uniform. Every z_j=t_j mod(q/g) is an independent uniform r-bit string, and rank-k L makes L(z) exactly uniform over k bits. For any fixed K and actual pk(K), (D_L,V)=(U XOR L(z),K XOR U) is a **joint uniform** 2k-bit pair, independent of K and pk; the real NP capsule is generated as a full conditional distribution given V. The native challenger, given only pk and the permitted signing/presigning interface, can generate the complete null public transcript with fresh uniform (D_L,V), uniform B and p_j, and actual independent Fourier SOURCE coins. Therefore for arbitrary coherent QPT full-transcript key recovery or truly unauthorized native signature forgery,

    p_real <= eps_native(B*) + ell*Adv_dec-QPT-LWE(d,n,q,chi;B*).

B* includes the complete simulator and attacker costs, quantum advice and permitted oracle/circuit access. QPT advice must be independent of the fresh target LWE secret/errors; arbitrary setup-coin-correlated advice, target-opening coins or unrestricted same-key selective openings are NOT covered. The challenger must simulate the actual native checking key, claim/branch message restrictions and all related capsules it advertises. The proof uses straight-line QPT hybrids, no quantum rewinding and no requirement that an adversary volunteer a representation.

If R_N is false, its entire Fourier quotient laws P_N,0 and P_N,1 coincide, so the **complete** real joint transcript can be simulated from real pk without knowing K: generate U and the real linear capsule, then NP-null columns. This remains true even if R_card has witnesses and allowed linear-side coins are disclosed, provided the NP protected share V and masks are not revealed. For adversarial FIXED false R_card instances with true NP, average-case random-B QPT LWE does NOT give universal false-instance hiding. The above native/LWE bound holds for fresh random B reference sources; it is NOT a generic-NP false-instance theorem or an arbitrary adaptive selective-opening theorem.

## Independent exact true-source probability

Let W count binary weight-h kernel witnesses to uniform B; M=binom(n,h). For each such w, Pr[Bw=0]=q^-d. For distinct equal-weight binary w,w', there exist one coordinate belonging only to each support, so their 2-by-2 incidence minor is determinant +/-1, a unit even modulo 2^a. Thus their kernel events are pairwise independent over Z_q. Consequently

    E[W]=M/q^d,
    Var[W]=M*q^-d*(1-q^-d),
    Pr[W=0]<=q^d/M.

This constructs, without witness planting, almost-surely true random source instances when M/q^d is large. It is a combinatorial existence proof, not a search-hardness or quantum-LWE parameter proof. Conditioning on true sources requires the explicit conditioning loss q^d/M; no unconditional adversarial-x security is inferred.

## Efficiency and what remains missing

The original unrestricted binary-source threshold was g>2*n*beta. Fixed public cardinality replaces it by g>2*h*beta **without changing the transverse LWE challenger distribution (d,n,q,chi)**, so r=a-log2(g) can increase and ell=ceil(k/r) decrease. For illustrative, UNCERTIFIED q=2^20,n=4096,h=128,d=32,beta=1,k=256, old g=16384,r=6,ell=43; new g=512,r=11,ell=24, **44.186% fewer independent noisy n-vectors**. The deterministic A first row also does not need publication. Here c*n=16384<q and binom(4096,128)/q^32 >2^176; this is a source-existence calculation, NOT 128-bit QPT LWE security or Bitcoin mining performance.

The outstanding ORIGINAL-use-case equation is to construct a classical polynomial-time mapping f_x from EVERY real claim-bound Bitcoin/Syscoin header, AuxPoW/tag and arbitrary ORIGINAL NP witness to a binary w for which B_x*f_x(W)=0 and wt(f_x(W))=h, **while** the public B_x retains a full-joint standard-QPT-LWE challenge simulator. A fixed-weight encoding alone does NOT solve its random kernel equation. No such compiler was found or claimed. The arbitrary NP Fourier component still has exponential signal for general circuits. Malicious N-of-N setup/abort, multiple-capsule selective opening, the actual PoW work bound, Bitcoin challenge/timeout graph and native no-EC PQ endpoint remain unresolved.

## Exact executed checker and limitation

The published check_cardinality.js runs with Node >=18 and only the built-in assert module. The captured output.json corresponds to **186,974 exact assertions**, executed twice byte-identically offline. They test: all 64 candidate binary vectors for the local source, 139,968 three-valid-witness openings and full noisy vectors, all 4^6 B matrices and every pairwise witness frequency, the fixed native-K joint uniform pad distribution, and large-parameter integer arithmetic. They do NOT constitute a QPT security experiment, an independently certified native signature scheme, a Bitcoin hash-chain simulator or proof of a practical generic WKEM.
