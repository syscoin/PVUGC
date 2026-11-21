# Gaussian-tail all-witness transverse-LWE release: finite sampler, full-view QPT hybrid

Research only; 2026-10-27; run gaussian-transverse-tail-20261027-turn10. Based on exact prior cardinality source PROOF.md Git blob 2260a962953b11dd3bbcf1b92784e73d9460e439 and adaptive-independent source PROOF.md Git blob 6cf07e0374f5d303c3528c79caeb30a3aacf7301, PR #1. Starting branch head da17fa6654ffccd6d7905302314ddedd69c3e2f4.

## Actual constructive delta

The prior reference source requires bounded individual LWE errors |e_i|<=beta and deterministic g>2h beta to round the aggregate error for EVERY accepted fixed-weight witness. Here **the LWE source, uniform transverse B, noise law, actual native pk, share construction, and ordinary QPT LWE challenge embedding remain the same**. Change only the public rounding-spacing parameter g by proving an explicit negligible-probability *simultaneous over all valid witnesses* subgaussian correctness certificate. This supports unbounded discrete Gaussian and a strict-PPT finite dyadic approximation of it, without postselecting errors, choosing a witness at setup or altering the challenged noise distribution.

This is an efficiency improvement of a *surviving restricted random-kernel reference SOURCE*, not a generic ORIGINAL NP compiler, a Bitcoin PoW representation, or a practical completed WKEM.

## Complete honest algorithm

Let q=2^a, g=2^nu, 0<=nu<a, h|g, c=g/h, c*n<q, d>=1, k seed bits. The honest sampler's error law chi is a finite dyadic approximation, with support [-T,T] and P-bit probability integers, of the centered discrete Gaussian G_sigma(z) proportional to exp(-z^2/(2sigma^2)). Define ideal mass p_z=G_sigma(z). For |z|<=T put integer mass floor(2^P p_z) and allocate the remaining mass to z=0. Draw exactly P random bits, interpret as integer 0..2^P-1, and return the cumulative-interval symbol. This is *strict bounded-time* once the public integer mass table is fixed. For uniform parameter generation, polynomial-precision rational exp approximation gives the same probabilities within O((2T+1)2^-P) TV, without unbounded rejection; allow a small constant on that dyadic term for rigorously rounded implementations.

Writing delta=TV(chi,G_sigma), the exact ideal-mass table has

delta <= 2 exp(-(T+1)^2/(2sigma^2))+(2T+1)2^-P.

All source and error randomness are independent. Generate the actual native seed K and pk=NativePK(K). Let ctx bind relation identity, real claim/UTXO, burn/authorization/output, branch, authenticated anchors/window and intended native signature path. Public b'=(1,b'_2,...,b'_(d+1)) can depend on pk,ctx but not secret K or future witness/error coins. Choose B uniform in Z_q^(d x n); set alpha=c 1_n, A first row alpha and remaining rows B_i+b'_(i+1)alpha; b=g b'. The *actual reference ORIGINAL relation* is R_card(B;w)=[w in {0,1}^n, wt(w)=h, B w=0 mod q]. Under c*n<q this is precisely the binary A w=b relation. It is NOT the claim-bound SYS/BTC relation.

Generate U uniform {0,1}^k, V=K xor U. Set r=a-nu, ell=ceil(k/r), and fix public full-row-rank binary map L: {0,1}^(ell*r) -> {0,1}^k. Independently per j sample t_j uniform Z_q, u_j uniform Z_q^d, e_j~chi^n, publish

p_j=alpha t_j+B^T u_j+e_j (mod q),
D_L=U xor L( (t_1 mod(q/g)) || ... || (t_ell mod(q/g)) ).

Independently instantiate the previous physical Fourier/polar SOURCE and public dither capsule F for V under *actual arbitrary* ORIGINAL-NP relation R_N(pk,B,ctx;v). Publish B,A,b,p_1..p_ell,D_L,F, actual pk, full binding context, accepted native auxiliary information, related capsules and parameters. Protect/erase K,U,V,private t/u/e and NP sampler coins in the honest setup model. No SourceOpen oracle, witness at Build, canonicalization, Bitcoin-side NP proof checking, or online authority.

Recover using ANY accepted w and v. Compute y_j=w^T p_j mod q. Since wt(w)=h and Bw=0, y_j=g t_j+E_wj with E_wj=sum_(i:w_i=1) e_ji. Cyclic nearest-multiple-of-g rounding returns z_j=t_j mod(q/g) when |E_wj|<g/2. Recover U=D_L xor L(z_1||...||z_ell), recover V using the previous certified Fourier/polar decoder with ANY v, form K=U xor V, check real pk(K), sign the intended challenge path OFF CHAIN. All valid witnesses recover the SAME PRECOMMITTED K, except for explicitly bounded global setup/decoder failure. Different states remain different.

## Exact all-witness theorem (classical setup, unrestricted QPT attacker)

For X~G_sigma, E exp(sX) <= exp(s^2 sigma^2/2), all real s. Proof: complete the square; shifted Gaussian theta sum Theta(t)=sum_z exp(-(z-t)^2/(2sigma^2)) has Fourier/cosine expansion with positive coefficients exp(-2pi^2 sigma^2 m^2), hence Theta(t)<=Theta(0). The MGF bound follows and applies to any sum of h independent noise coordinates. By Chernoff,

Pr[|E_wj|>=g/2] <= 2 exp(-g^2/(8h sigma^2)).

There are at most M=binom(n,h) binary weight-h witnesses (even without the B-kernel restriction). Coupling n ell finite dyadic errors to independent G_sigma errors, the probability that **ANY** accepted ORIGINAL reference w rounds incorrectly in **ANY** column obeys

eps_round <= 2 ell binom(n,h) exp(-g^2/(8h sigma^2)) + n ell delta.    (CERT)

This is a simultaneous statement, not one favorable/canonical witness or an average-witness assertion. It is also uniform over fixed B for *correctness only*; false-instance security for adversarial B is NOT proved. Add the inherited independent Fourier NP all-witness decoder error eps_N. No conditioning of public errors on good setup occurs.

Pinned illustrative, UN-CERTIFIED-QPT parameters: q=2^20,n=4096,h=128,d=32,k=256,sigma=16/5,T=56,P=320,lambda=128. g=4096 yields c=32, c*n=131072<q, r=8, ell=32. Exact integer proof: binom(4096,128)<2^817; 2ell M<2^823; g^2/(8h sigma^2)=1600; since e>2, Gaussian term <2^(823-1600)=2^-777. Moreover (T+1)^2/(2sigma^2)=81225/512>158, hence delta<2^-157+2^-313. With n ell=2^17, the coupling term <2^-139. Thus CERT <2^-128 (and the independent 160-decimal-digit Python check gives tighter log2 bounds -1485.36681 and -210.87286). The SAME finite dyadic chi supported in [-56,56] would need deterministic g>2*128*56, hence dyadic g=16384,r=6,ell=43. **32 vs 43 noisy n-vectors saves 25.58%**, with unchanged source B, dimensions and exact LWE noise assumption. Neither set of illustrative numbers certifies quantum-LWE hardness or BTC performance.

## Entire correlated public view / ordinary QPT LWE proof

Assume decisional QPT LWE, exact parameters (d,n,q,chi), for (B,B^T u+e) versus (B,uniform), with fresh uniform B and u and independent errors. The reduction generates real native K, real pk, U,V, t_j, all other columns, full NP SOURCE/capsule F protecting the actual V, and all declared context and allowed native signing/presigning/related-capsule outputs, not merely an isolated pad. It embeds a standard LWE challenge (B,z) by setting p_j=alpha*t_j+z; real z gives EXACT actual column distribution, uniform z makes this column independent uniform even given t_j, native pk and all other public outputs. No secret challenge u/e or SourceOpen is needed. Telescope over ell columns with a **straight-line** QPT hybrid (no quantum rewinding).

In the all-null experiment, each p_j is independent uniform and each t_j mod(q/g) is independent uniform r bits; full-rank L yields independent uniform P=L(z_1||...||z_ell). Conditional on ANY fixed real K and its pk, since U,P are independent uniform, (D_L,V)=(U xor P,K xor U) is **joint independent uniform 2k bits**, not only marginal pad hiding. Actual physical NP coins/capsule may be simulated conditional on V, target NP coins may be disclosed as already allowed, and independently keyed/opened sibling claims may be simulated with their own coins. A native challenger with real pk and exact allowed path-signing interface therefore simulates the complete null public view without native signing seed K.

For arbitrary coherent QPT final-key recovery or genuinely fresh unauthorized native signature forgery in this exact advice/access game (advice independent of fresh target LWE challenge coins; NO target linear opening; independently keyed related capsules; legitimate native signing oracles only),

p_win <= eps_native(B*) + sum_(j=1)^ell Adv_QPT-decLWE_chi,j(B*).

For an ordinary ideal-discrete-Gaussian QPT LWE challenge, replacing chi by G_sigma incurs at most a conservative 3 n ell delta statistical term, by coupling and QPT data processing. The source and its challenge simulator are instantiated **together**; this is not a hypothetical SourceOpen oracle. This proves only the random unplanted reference source setting and its permitted selective-opening composition. A malicious N-of-N setup, arbitrary setup-secret-correlated advice, target linear share leakage, reused same signing keys in independently spendable claims or unrestricted correlated public capsules remain unproved. Numerical 128-bit QPT hardness is NOT claimed.

If arbitrary ORIGINAL R_N is FALSE, its inherited whole-quotient physical Fourier P0=P1 equality gives exact full-public native-key-free simulation of its protected NP share even with honestly generated chi-linear capsule and permitted linear disclosure, as long as the NP share and masks remain unopened. There is NO full adversarial false-R_card theorem. Underlying generic Fourier NP release still costs exponentially in independent nonlinear factors.

## Decisive ORIGINAL gap unchanged

The random reference relation R_card is NOT an actual Bitcoin 100-block light-client or general NP relation. For any fixed nonzero f_x(W) independent of fresh uniform B, Pr[B f_x(W)=0]=q^-d. The missing polynomial-time joint SOURCE compiler must take **every valid ORIGINAL claim-bound chain/AuxPoW/coinbase-tag/ancestor/burn NP witness** to a cardinality-h short kernel opening f_x(W) for the SAME key while preserving an **actual standard QPT LWE joint challenge simulation**, without admitting cheap false witnesses. The required equation remains: B_x f_x(W)=0 (mod q) for ALL accepted ORIGINAL W, wt(f_x(W))=h, with arbitrary recovery/forgery -> ORIGINAL W or independent justified PQ break. Adding a public NP test after releasing the linear share is bypassable. Actual QPT Bitcoin work model, qualified fork/broken-tag veto, source tags and DA/observation assumptions, malicious N-of-N/abort, full transaction graph and conditional SLH-like native Bitcoin endpoint remain unresolved. Nothing is deployed.

## Executed artifacts

Exact-source independent local standard-library Python checker: 113,026 assertions twice, byte-identical results, including 93,312 opening tests for three different valid reference witnesses, 12,769 dyadic noise pair contributions, exact Gaussian-tail computation and full-null pad histogram. Separately published self-contained JavaScript checker executes 100k+ exact finite-ring assertions and rigorous coarse *integer-only* certificate bounds. Neither is experimental QPT hardness evidence or a full SYS/BTC circuit run. No external research performed.
