# Two-pass, reused-column SOURCE release (LWE-only alternative to seed wrapping)

**2026-10-31; research only. This is NOT an ORIGINAL-witness KEM, not generic NP witness encryption, and not a 128-bit QPT security calibration.** Exact predecessor: `syscoin/PVUGC` PR #1 at `caded4c0c2cba544d6524107b224bf5629dc886b`, open/draft/unmerged on `research/pq-wkem-validation-20260918`; latest inspected top-level substantive comment `6540775101`. The earlier SOURCE direct-share baseline (`native_256bit_master_20261030`) had 103 independently planted target columns per packet and 114,816,192 illustrative public bytes. A later SOURCE seed-wrapper (`source_seed_wrap_prg_20261030`) reduced to 67,707,792 bytes by using 256-bit per-packet PRG seeds but explicitly added an unproved nonuniform-QPT PRG assumption. No outside literature, websites, searches or other repositories were consulted.

## Constructive delta: same SOURCE columns, two independent encryptions

Preserve the original packet-separated SOURCE relation. Work over prime `q=16777213` with `n=256`, `m=4469`, signed-unit source opening weight `w=2004`, digit gap `g=524287`, centered noise law `chi=Uniform{-128,...,+128}`, and a 512-bit native signing master `K=SK.seed || SK.prf` with independent 32-byte components. `Native.KeyGenFromSeeds` must produce the *genuine* checking key `pk`; it is hypothetical for this research and was not run by the checker. The native public seed and checking key are fully published and bound to relation identity, claim/UTXO, branch, anchors/window, context, challenge path and signing-verification key. Fresh `K` is necessary for each independently protected signer/claim/path scope.

Pick uniformly random shared `A in F_q^{n x m}` once for the modeled 400 scopes. Per independent scope, sample `V <- GF(256)^64` uniformly; define Shamir shares `S_i=K+alpha_i V` bytewise over GF(256), where `alpha_i in {1,2,3}`. Each share encodes to 103 canonical little-endian five-bit digits `a_{i,0},...,a_{i,102}` (the top digit has only two significant bits). For **each packet index i and only 52 columns l**, sample independently `Z_{i,l}` uniformly from the length-m signed-unit vectors having exactly w nonzero entries. Publish `U_{i,l}=A Z_{i,l} mod q`.

For each packet `i` and each encryption pass `j=0,1` independently sample `r_{i,j} <- F_q^n`, `eta^c_{i,j} <- chi^m`, and `eta^d_{i,j,l} <- chi` for each digit assigned to that pass. Publish

`c_{i,j}=A^T r_{i,j}+eta^c_{i,j}`

`d_{i,j,l}=U_{i,l}^T r_{i,j}+eta^d_{i,j,l}+g*a_{i,52j+l} mod q`, for `0 <= 52j+l < 103`.

Pass 0 encrypts 52 digits, pass 1 encrypts the remaining 51. **The same U columns are reused but the r/noise coins are never reused.** Do not reuse `r` between passes: differences of d-values would otherwise expose cross-digit plaintext differences. Fresh `U,Z,r,eta,V,K` across independent claims are essential; only A is shared in the restricted experiment. The encrypted SOURCE masks do not use SHAKE, another PRG, a hash assumption, or an ORIGINAL-conditioned sampler.

Off-chain `OpenPacket(i, z_0,...,z_51)` accepts exactly when every z is a legal signed-unit weight-w vector and `A z_l = U_{i,l}`. For both passes, decode the unique `a` whose centered residual `d_{i,j,l} - z_l^T c_{i,j} - g*a` is at most `B(w+1)` in absolute value; reject noncanonical shares and mismatched authentic checking key. Any **two distinct** packets give the same `K` by ordinary GF(256) two-of-three reconstruction. The SOURCE openings are hidden setup coins, NOT produced by arbitrary valid ORIGINAL witnesses. No caller should consider an off-chain checker a defense against unauthorized cryptographic key recovery.

## Exact correctness for every legal SOURCE opening

For any opening z satisfying the public conditions, `z^T A^T r=U^T r`, hence

`d - z^T c = g*a + eta^d - z^T eta^c (mod q)`.

The error is at most `B(w+1)=256640`. Correct unique decoding for all 32 possible symbols follows from `g-2B(w+1)=11007>0` and `q-31g-2B(w+1)=11036>0`. This proof includes alternative legal short openings, not just the planted Z. Each of the 103 recovered symbols is the authentic share digit; any two share indices reconstruct exactly the precommitted K. The deterministic toy checker also exercised an explicitly nonuniform duplicate-column collision fixture with an alternate short opening for every target. That fixture is *not* used to justify SOURCE entropy or security.

## Restricted full-joint-public QPT proof opportunity

Define a fixed protected signer/claim scope and the **entire classical public view** `V_pub=(A, all U_i, all c_{i,j}, d_{i,j,l}, genuine pk, public native seed, statement, bound claim/UTXO/path/context/anchors/window, manifest/authentication, permitted signing transcript, related independent scopes and permitted auxiliary functions)`. Honest algorithms are classical PPT. The adversary is arbitrary nonuniform QPT with independent quantum advice, coherent processing of this whole classical view, and classical adaptive disclosure of **at most ONE entire packet's** planted short SOURCE openings and/or its two passes' encryption `r,eta` coins, as well as classical permitted native-message signing queries. The coins exposed do NOT include K, V, other packet openings or another packet's encryption coins. There are no quantum leakage/signing-oracle queries, hidden-K-correlated advice, malicious N-1 honest-signer seed injection, unknown-one-honest abort grinding, or real ORIGINAL-conditioned openings in this model. Auxiliary functions may depend on the published view but may not receive private honest setup coins from a hidden channel. Separately authenticated, independent related scopes may be exposed only when their protected keys and sampler coins are independent; a 400-scope claim requires a 400-factor loss.

Assumptions: ordinary *nonuniform QPT decisional-LWE* over one uniform matrix `M=[A|U] in F_q^{n x (m+52)}` and one full vector `(M, M^T r+eta)` vs `(M, y_uniform)`, with `r <- F_q^n`, `eta <- chi^{m+52}`; native QPT EUF-CMA for the genuine scoped signing key and classical signing queries; authenticated manifest/scope and freshness of challenge paths. LWE concrete hardness of the selected q,n,m,B and native implementation security are **not calibrated**. All LWE hybrids include all ciphertext coordinates and the genuine native checking-key correlations.

Let `T` be the signed-unit weight-w set. For independently planted columns and uniform shared A, pairwise universal hashing gives per-column `epsilon <= 1/2 sqrt((q^n-1)/|T|)` with `|T|=2^w binom(m,w)`. Fix protected pair P of two packet indices and leave third packet k potentially exposed. Keep `(A,Z_k,U_k)` and all permitted k-side opening/coins **exact**. By independent planted targets, replace the `2*52` protected U columns by uniform with total variation at most `delta=104*epsilon`, *even with the two ciphertext passes*, by data processing. Never replace exposed k's U while revealing its Z.

For each protected packet, hybridize **both independent full-vector LWE samples** to uniform, keeping its sampled plaintext digits as a known additive offset in message coordinates. This is FOUR straight-line ordinary one-sample QPT-LWE hybrids across the two protected packets. During each individual LWE reduction the simulator samples K and derives its *real* native pk, so the protected plaintext digits are available to it. The challenge matrix's A is shared with the other matrices, whose U are sampled independently; other passes can be sampled honestly or uniformly. No rewinding or unsupported classical-to-quantum lift is used.

Once the four protected ciphertext vectors are uniform, no protected ciphertext carries S_i. The only at-most-one exposed share is `S_k=K+alpha_k V`, uniform and independent of K and its genuine pk/signing transcript. This final game can be simulated using a native EUF-CMA challenger with unknown K by sampling the one exposed share **uniformly**, while the protected ciphertexts stay uniform. A usable K enables a fresh native scoped signature, and a fresh accepted native forgery is directly an EUF-CMA win. For fixed P the reduction aborts if the adversary requests disclosure at P; on the event E_P (successful usable-key recovery/native forgery with no disclosure at P) this abort never happens. With at most one disclosed packet every success lies in at least one of the three E_P events.

Consequently, for one protected scope, the conditional bound is

`Pr[Win] <= 3 * (104*epsilon + 4*Adv_QPT-LWE-1sample + Adv_QPT-Native-EUF-CMA + Adv_QPT-auth)`.

Every term receives an additional factor 400 for four signers times 100 independent scopes using target guessing/union bound. **Note the reduction factor FOUR instead of TWO** for direct single-pass SOURCE; the security assumption is still ordinary QPT-LWE, but this factor loss and the increased public LWE samples require concrete calibration. Do NOT call this an established 128-bit secure system. The PRG-seed-wrapper has a smaller LWE term but adds separate QPT-PRG hybrids. Target-sharing does not require a new structured-LWE assumption for this SOURCE game because each protected U matrix is replaced by uniform first; it does not solve the ORIGINAL-dependent joint challenge simulation.

The exact cumulative planted-target statistical term has `J=400*3*2*52=124800` and is below `2^-128.198080` for w=2004. The integer check is

`J^2 * (q^n - 1) * 2^256 <= 4 * 2^w * binom(m,w)`.

It fails for w=2003 and passes for w=2004. This is solely one statistical union-bound term, not full 128-bit PQ security.

## Cost comparison and narrow contribution

Assume fixed raw 3-byte encodings of F_q elements (q<2^24), one shared A, 400 signer/claim scopes, and three packets per scope. For L=ceil(103/k) target columns reused across k independent passes, the SOURCE+packet bytes are

`3*n*m + 400*3*3 * (n*ceil(103/k) + k*m + 103)`.

`k=1`: 114,816,192 bytes (prior direct 512-bit SOURCE share). `k=2`: **83,902,992 bytes** (26.92407705% fewer than direct); `k=3`: 84,324,192 bytes. Exhaustive exact comparison for k=1,...,8 finds k=2 optimal under this cost model. The existing 256-bit-seed PRG wrapper is smaller at 67,707,792 bytes but has the additional QPT-PRG assumption; two-pass direct SOURCE is larger by 16,195,200 bytes and **does not use that PRG**. Native keys/signatures, manifests, setup/funding graphs, original evidence, on-chain/Bitcoin bytes and other overhead are excluded. The two-pass change has strictly more LWE samples than single-pass direct encryption, so do not infer identical concrete security from an uncalibrated LWE instance.

This is a **restricted SOURCE-only algorithm/size/assumption trade-off**, not the missing generic NP witness-KEM, not false/hard-true ORIGINAL security, and not progress on arbitrary key recovery -> ORIGINAL W. The independent-SOURCE known-TRUE-to-FALSE transfer remains if somebody merely attaches ORIGINAL identity/context to these U matrices. No all-ORIGINAL-witness `Lift`, no witness-free ORIGINAL-dependent `Comp`, and no complete full-public ORIGINAL-conditioned QPT simulator exist here. Malicious one-honest N-of-N setup, credential/path binding and authorized off-chain native signing, abort/DA/funding graph, SYS/BTC qualification and hypothetical Bitcoin PQ-native endpoint all remain to be proved before deployment.

## Execution/provenance

The exact `checker.py` alongside this record was executed offline twice with byte-identical captured JSON output. It reports 9,201 successful finite algebra and exact-integer assertions, including 16 independently generated 512-bit toy masters (three packet releases and all two-of-three combinations each), exhaustive GF(256) one-byte one-share uniformity for three alphas, legal alternative SOURCE opening recovery on a deliberately *nonuniform* collision fixture, all-symbol unique decoding, exact 400-scope statistical threshold, margins, q primality and raw-byte optimization over 1..8 passes. The toy RNG is deterministic, `pk` is a SHA-256 mock identifier, and this is not a QPT security, LWE concrete-hardness or native signature test. Captured output is `output.json`; `output2.json` was checked identical locally but is not needed for publication.

**Exact next unresolved equation:** an ORIGINAL-dependent witness-free classical-PPT `Comp(R,x,context,pk)` and public all-witness `Lift(x,W,...)` such that, together with the actual SOURCE-dependent full public distribution (not a planted SourceOpen oracle), all valid ORIGINAL W open the same native capability and arbitrary FALSE/unauthorized hard-TRUE usable recovery or native forgery implies an actual ORIGINAL W or an independently justified QPT break. This new SOURCE packing does not supply or assume such a compiler.
