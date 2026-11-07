# Sparse factor-local torsion source: every ORIGINAL witness, certified FALSE secrecy, and concrete 75% size reduction

## Provenance and exact scope
Offline research continuation on the existing open/draft/unmerged syscoin/PVUGC PR #1, branch research/pq-wkem-validation-20260918, expected starting head 66d8acf2321f082e6ff68e1daa5383643a28dcd1. Selected predecessor: prime_power_torsion_rank_pad_20261029, exact RESEARCH.md blob e76eb6310027751f75a6428e087b7c03d53f4c40 and check.js blob 0f0a10f3d6b6f8e2b3b4f9de215faa56a95755ba; latest ordinary substantive comment 6498612494. Current PR metadata/comments and only those predecessor files were read. No outside literature or unrelated sites/repositories. The present change is a **restricted construction efficiency, correctness, and original-representation extraction advance**, NOT a complete generic-NP witness KEM or 128-bit quantum security certification.

## Exact classical compiler, no planted witness
Take the public ORIGINAL relation R(x,W) and its deterministic classical polynomial-time bounded-arity Boolean-gate/CSP reduction. The statement x must bind relation/version, claim and whole UTXO, authorized branch/challenge path, actual burn/output/authorization, context, anchor/window, and genuine intended native checking pk. The real Bitcoin/SYS predicates and native-PQ endpoint are unimplemented here. Let factors F_j=(S_j,Gamma_j), j=1..M, have constant arity r and an explicit allowed-local-assignment table Gamma_j. For ordinary 3CNF clauses there are seven allowed triples. Four clauses expressing one exact 3-XOR truth table may be deterministically folded into its four-allowed-tuple parity factor without changing satisfying assignments; leave other clauses untouched. This grouping is local and publicly checkable, not NP search.

Introduce one source coordinate phi_(j,a) for each a in Gamma_j: L=sum_j |Gamma_j|. Add normalization row sum_a phi_(j,a)=1 for every j. For every Boolean variable v, choose a deterministic spanning tree on its factor occurrences. For each oriented tree edge (j,k), add the agreement row

   sum_(a in Gamma_j) a[v]*phi_(j,a) - sum_(b in Gamma_k) b[v]*phi_(k,b) = 0.

These integer equations define A of size Rrows x L with Rrows=M+sum_v max(deg(v)-1,0) and U=(1 for normalization rows; 0 for agreement rows). A's sparse coefficients are 0,+1,-1. Build A,U from public factors alone, then reduce mod q=2^k. No planted SOURCE witness, SourceOpen service, trapdoor or undisclosed source-dependent secret.

For **EVERY valid ORIGINAL W**, deterministically extend W through its verification circuit to a global satisfying Boolean assignment w_hat. Let Phi_(j,a)(W)=1 exactly when a=w_hat|S_j and zero otherwise. Then A*Phi=U **over the integers**, with exactly M ones and ||Phi||_1=M. Distinct valid W retain different Phi and nevertheless release the same K. If an *explicitly supplied* representation has entries exactly 0/1, exactly one selected tuple per factor, and A*phi=U mod q with q>=3, every edge agreement is in {-1,0,1} and therefore is zero over the integers. Tree connectivity makes local copies consistent, yielding a genuine global gate assignment and ORIGINAL W. This accepted-onehot-to-ORIGINAL extractor does NOT convert arbitrary native-key recovery or forgery to a representation; no adversary volunteering an opening is assumed.

## Actual honest public capsule and off-chain release
Generate the **genuine** classical native keypair (K,pk), with public checking-key correlation preserved. Let K be its complete B-bit native signing secret (the checker only uses 256 mock bits, not SLH). Choose t>=2 independent uniform B-bit XOR shares Z_i and publish Mask=K XOR Z_1 XOR ... XOR Z_t. With q=2^k, g=q/2, independently for each bit a of each share sample uniform s in Z_q^Rrows, and independent ternary e in {-1,0,1}^L and eps in {-1,0,1}. Publish all coordinates of

   c=A^T*s+e mod q;       d=U^T*s+eps+g*a mod q.

The full public output contains R,x, all source matrices and complete ciphertexts, true pk, Mask, domain binding, auxiliary outputs and related capsules. Build and Release are classical polynomial time for constant factor arity. All security statements require genuinely uniform private coins; the deterministic checker seed only reproduces algebraic identities.

A holder of valid ORIGINAL W verifies it OFF CHAIN, computes its own Phi(W), and for each ciphertext computes

   residual=d-Phi(W)^T*c = g*a+eps-Phi(W)^T*e mod q.

Since |eps-Phi^T e|<=M+1, choosing q>4(M+1) ensures nearest-cyclic-center decoding between 0 and g always recovers a. The recipient XORs the decoded shares with Mask, obtains the SAME precommitted K for every valid ORIGINAL W, and can produce an ordinary native challenge-path signature if that native endpoint is actually implemented. Bitcoin never evaluates R, a VM, a general proof, PCP or BitVM trace; BitVM is covenant-emulation plumbing only. No native PQ Bitcoin deployment is claimed.

## Public torsion certificate, directly from inconsistent XOR subsystem
Suppose selected factors are XOR constraints parity(a)=b_j and there is a public F2 linear dependency J_j in {0,1} with

   for every variable v, sum_(j containing v) J_j = 0 mod 2;
   sum_j J_j*b_j = 1 mod 2,

setting J=0 on other, non-XOR factors. Existence is decidable by F2 linear algebra in this *restricted* FALSE family, not for every FALSE NP statement. The chosen occurrences of each variable have even parity. On their spanning tree, find an edge indicator with boundary J. For the deterministic star rooted at occurrence r, put z_(r,j)=J_j for each child occurrence j; even parity enforces the root boundary. For factor-normalization rows set z_norm,j=J_j*b_j. For every local choice column (j,a),

   (A^T z)_(j,a) = J_j*b_j + J_j*sum_(v in S_j) a[v]
                  = J_j*(b_j+parity(a)) = 0 mod 2.

But U^T z=sum_j J_j*b_j=1 mod 2. This gives a public z with A^T z=0 mod2, U^T z=1 mod2. It remains valid when arbitrary additional nonselected factors are present. For the contradictory Pasch 3-XOR rows on (0,1,2), (0,3,4), (1,3,5), (2,4,5), parity (0,0,0,1), take J=(1,1,1,1). The compiled A has 10 rows, 16 columns, and z=(0,0,0,1,1,1,1,1,1,1), weight 7. All 64 global assignments violate at least one factor; all 256 possible local onehot tuple selections fail A phi=U.

## Exact full-public FALSE security, quantum adversaries, and related capsules
For any such publicly certified FALSE source, q=2^k, g=q/2, and any two encrypted plaintext bits a,a', define the bijection on *private coins only*

   s' = s + g*(a-a')*z mod q;       e'=e; eps'=eps.

Since g*A^T*z=0 mod q and g*U^T*z=g mod q, **both complete ciphertext components c,d are pointwise unchanged** when interpreting the plaintext as a'. Uniform s remains uniform, even conditional on particular ternary errors. Thus the whole classical ciphertext distribution, not merely its marginal pad, is exactly plaintext-independent. Equality remains true against arbitrary coherent/QPT processing of complete classical public records, and independently generated quantum auxiliary advice. No ordinary-LWE claim, random-oracle extraction or quantum rewinding is needed.

For polynomially many *separately randomized certified-FALSE* capsules sharing one genuine native pk(K), require fresh independent encryption coins and shares in EACH capsule and at least one whole unrevealed share per capsule. A classical Open oracle may disclose up to t_i-1 whole shares together with ALL their actual s,e,eps coins, adaptively, and a permitted classical signing oracle forwards queries to the genuine native challenger. The straight-line simulator is given genuine pk and authorized signing access, samples all source-independent shares and coins, and sets each public Mask uniform independently of unknown K. After any classical adaptive opening trace, one unopened share per capsule is algebraically reinterpreted as the hidden value needed to reconcile the real K and public Mask; the per-bit z coin bijection preserves all ciphertexts, all opened coins, the entire auxiliary public transcript and the checking key. The bijection partitions completed adaptive transcripts without guessing an unopened index. Consequently the REAL and simulated classical transcript distributions coincide exactly; arbitrary coherent QPT processing preserves equality. Given independently justified native QPT EUF-CMA with classical queries, complete unauthorized target K recovery or fresh native target-path forgery yields a native fresh forgery, so the restricted success probability is bounded by the genuine native QPT EUF-CMA advantage, with no t or capsule-count loss.

The proof EXCLUDES related TRUE or uncertified capsules that legitimately reveal the same K, fully opened capsules, retained coins/signing seed, hidden K-correlated auxiliary data or reference registers, malicious setup, fake opening receipts, nonclassical opening/signing oracles, and insecure native signatures. Public coin equivocation is explicitly non-binding, so it cannot itself authenticate receipts. All permitted public context/auxiliary output must be simulatable from pk, public statement, public ciphertext and separately chosen coins without secret K. Classical honest algorithms are PPT; security against arbitrary QPT is only in the stated restricted game.

## Executed evidence and efficiency
The exact committed self-contained JS checker was invoked, with its JSON output saved separately. The extended **LOCAL-ONLY** Python standard-library checker passed 15,772 assertions in each of two byte-identical runs, including 138 randomized inconsistent XOR systems with repeated variable occurrences, onehot false-source rejection, a two-clause generic 3CNF fixture with 24 satisfying assignments, 8 different TRUE 6-variable Pasch-parity witnesses all recovering one 256-bit/three-share mock capability, and two related FALSE capsules preserving full ciphertexts during hidden-share coin reconciliation. This is finite algebra, NOT a QPT hardness experiment or native SLH implementation.

For the same certified FALSE Pasch source and protected 256-bit three-share capability, L=16, Rrows=10, ||Phi||_1=4 and noise <=5 permit q=32 (5-bit symbols). There are t*B*(L+1)=3*256*17=13,056 ciphertext field elements, or **8,160 bytes bit-packed**. The preceding degree-3 prime-power Macaulay source had L=42, q=256 and 3*256*43=33,024 raw ciphertext bytes. This is a **75.29% ciphertext-size reduction** in the same restricted FALSE secrecy model, excluding in both figures SOURCE matrix, headers/context, checking key and framing. Dense matrix entries fall from 17*42=714 to 10*16=160, with sparse local rows even cheaper. General bounded-arity systems have L<=2^r*M and Rrows<=M+sum_v(deg(v)-1); all true ORIGINAL witnesses retain onehot release.

## Remaining exact obligation
The full generic-NP witness-KEM is UNSOLVED. No theorem covers EVERY fixed FALSE ORIGINAL statement lacking a suitable public torsion certificate or arbitrary unauthorized hard-TRUE K recovery/native forgery. The indispensable missing reduction is

   (R,x,full public capsule,pk,aux,related capsules; QPT arbitrary successful K recovery/native forgery)
   -> actual ORIGINAL W OR independently justified QPT cryptographic break,

without assuming the adversary supplies phi, without a SourceOpen oracle or the builder retaining a bypass witness. No scalar LWE wrapper, uniform-source hybrid or local-factor soundness closes it. Also missing are malicious N-of-N preauthorization with one honest erasing participant/no bypass edges, useful abort/funding/pre-signature/DA graph composition, actual SYS/BTC AuxPoW/coinbase/interval/header/merkle/lag/window/challenge qualification with realistic censorship and reorg assumptions, and a hypothetical native no-EC P2MR-like SLH endpoint. Do not recommend deployment or disable ongoing research. No external research was used.

