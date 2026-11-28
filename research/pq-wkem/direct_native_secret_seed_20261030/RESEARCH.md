# Direct native SLH-style secret-seed release: remove the extra QPT PRG assumption

**Status, 2026-10-30 (offline run 11): RESTRICTED CONSTRUCTIVE IMPROVEMENT, not generic NP witness-KEM.** This builds solely on the 2-of-3 Shamir dual-LWE SOURCE research at commit d886caca6b0af77f7c0293b511c17af92c40d492. The ORIGINAL-witness compiler and arbitrary hard-TRUE extractor are NOT solved. No external literature, Internet research, PR-wide diff, or independent agents were used.

## Specific missing proof term removed

The predecessor samples a 256-bit secret K, uses SHAKE256 as a 256-to-384-bit secret-input PRG, and interprets its output as three native 128-bit signing seeds (SK.seed, SK.prf, PK.seed). The full-public security proof consequently adds an independent **unproved QPT PRG assumption for that SHAKE expansion**, in addition to QPT-LWE and native QPT EUF-CMA.

For the intended SLH-style key interface, **PK.seed is PUBLIC**: a verification key has the layout (PK.seed,PK.root), and the native uniform KeyGen draws SK.seed, SK.prf, PK.seed independently, each 16 bytes for an illustrative 128-bit setting. Therefore encrypt only K = SK.seed || SK.prf, exactly 32 random bytes, while independently sampling PK.seed as 16 public random bytes. Native.KeyGenFromSeeds(SK.seed,SK.prf,PK.seed) now has *exactly* the native honest KeyGen distribution, not a PRG approximation. NativePK already contains the public PK.seed. This eliminates both SHAKE expansion and the associated independent QPT-PRG hybrid at the SAME 256-bit encrypted master length and SOURCE matrix width.

This improvement is specific to a native signature algorithm with the stated exact uniform-seed interface. The executable checker models the PK.root function, and does **not** implement or validate native SLH-DSA signatures, Bitcoin consensus, or security parameters.

## Classical-PPT setup and complete public-output distribution

For honest protected signer h, draw A uniformly from F_q^(n x m) once. For each independent claim/path scope, draw U uniformly from F_q^(n x L), never reusing U, native seeds or packet randomness; sharing A across independently simulated scopes is permitted. Draw independently:
- SK.seed <- uniform 16 bytes; SK.prf <- uniform 16 bytes; PK.seed <- uniform 16 bytes;
- native SK,pk <- Native.KeyGenFromSeeds(SK.seed,SK.prf,PK.seed); pk=(PK.seed,PK.root);
- K <- SK.seed||SK.prf (the literal uniformly random 32-byte native secret); V <- uniform GF(256)^32;
- S_i = K + alpha_i*V bytewise over GF(256), alpha=(1,2,3);
- r_i <- uniform F_q^n, eta_c,i <- chi^m, eta_d,i <- chi^L independently for each of the three packets, with centered chi bounded by B.

Encode S_i as L=52 canonical little-endian five-bit digits a_i,l, and publish for each packet i:
 
    c_i = A^T*r_i + eta_c,i                         (mod q)
    d_i,l = U_l^T*r_i + eta_d,i,l + g*a_i,l          (mod q).

Finalize a signed/authenticated scope only AFTER native pk exists, binding version, ORIGINAL relation/statement, actual claim/UTXO, branch, anchors, window, context, pk, exact challenge-path, and setup session. Native KeyGen has no dependence on this scope, so the earlier self-referential pk/prelabel seed-expander problem disappears. Exact txid/output availability still requires a real pre-funding graph check.

The full public view includes the relation, x, complete scope, A, U, all three packets, genuine native pk including PK.seed, manifests/DA evidence, permissible native signatures, auxiliary and other related/independent-scope public outputs. The restricted theorem requires the protected signer to sample A/U/K/PK.seed/coins honestly and auxiliary/other-scope information to be efficiently simulatable from permitted public data. It does NOT allow an extra public hash of protected K, target SOURCE opening, target native seeds, unmodeled correlated malicious setup proofs, or target packet-coin leakage beyond one classical disclosure.

## Public off-chain Release and same-capability theorem

For any *legal SOURCE* opening Z whose coordinates have signs in {-1,0,1}, exact weight w, and A*z_l=U_l, decrypt each packet digit by cyclic nearest-rounding of d_i,l - z_l^T*c_i to g*a, a in [0,31]. With independent errors |eta|<=B, error magnitude is at most B(w+1). Unique decoding follows from both strict conditions:
 
    g > 2*B*(w+1),       q - 31*g > 2*B*(w+1).

For distinct indices i,j, use their independently decoded S_i and S_j, allowing different legal Z_i and Z_j. Reconstruct V=(S_i-S_j)/(alpha_i-alpha_j), then K=S_i-alpha_i*V over GF(256). Set SK.seed=K[0:16], SK.prf=K[16:32], PK.seed=NativePK[0:16]; derive native SK with the true native KeyGen and verify its actual public key equals the authenticated precommitted pk before ordinary native signing on the intended claim-scoped challenge transaction. Reject malformed, noncanonical or duplicated shares. Every legal SOURCE opening returns its authentic share and therefore ANY two packets recover EXACTLY THE SAME native signing capability.

This proves only SOURCE-opening correctness. It does not supply Lift(x,W,A,U) for even one ORIGINAL NP witness, let alone for every valid W.

## Full-public QPT reduction: no PRG hybrid

Define adversaries as arbitrary *nonuniform QPT* with quantum advice independent of the protected secret except through the specified full public view. They may process all fixed capsules coherently and request ordinary **classical** allowed-message native signatures. They can adaptively choose at most one target packet and receive its complete genuine classical encryption coins (r,eta_c,eta_d); arbitrary superposition leakage queries, source-opening disclosure and secret-correlated auxiliary outside the explicitly simulated interfaces are excluded. Win = full usable native secret recovery or fresh protected native-signature forgery.

For each unordered pair T of the three packets let E_T=Win AND no index of T was disclosed. Any transcript containing at most one disclosure leaves a pair unopened, hence pointwise 1_Win <= sum_T 1_E_T. This is a deterministic three-pair union bound, not an independence assumption.

For fixed T, twice embed an ordinary full-vector decisional QPT-LWE challenge at the honest uniform matrix [A|U], replacing one entire (c_i,d_i - g*a_i) vector with uniform F_q^(m+L) each time. The straight-line simulator samples all native seeds, pk, Shamir data and other packets/scopes honestly. If an index of T is selected for coin disclosure, output fixed zero, since E_T is false on such transcripts. This handles adaptive classical leakage after arbitrary coherent public processing with **no quantum rewinding**:

    |Pr_real[E_T] - Pr_H2[E_T]| <= 2*Adv_QPT-LWE.

In H2, both unopened packet vectors are uniform even after the hidden share-digit shifts. The third authentic packet encrypts S_k=K+alpha_k*V, which is exactly uniform *independent of K, PK.seed, native PK and permissible native-signature distributions*, even if its complete coins and share are exposed. A native QPT-EUF-CMA challenger now supplies genuine pk from the **identical uniform three-seed native KeyGen distribution**; the simulator independently samples that one remaining share and its packet, plus two uniform packets, and uses the native allowed-message signing oracle. It never needs K. A usable recovered secret yields a fresh signature; otherwise an accepted fresh challenge signature is directly a forgery. Manifest-authentication failure is an additional separately bounded QPT event.

Therefore, for one fixed protected honest signer/scope and the stated classical selective-opening interface:

    Pr_real[Win] <= 3*(2*Adv_QPT-LWE + Adv_QPT-Native-EUF-CMA + Adv_QPT-setup-auth).

**There is no Adv_QPT-PRG term.** For selection among N*C independently sampled protected scopes, separately account for an N*C guess/union factor and precisely specified shared-A, separately targeted-U and prior-scope leakage distributions. Published source-dependent setup proofs or correlations that cannot be simulated in the native EUF game are NOT covered. Neither the LWE nor the native EUF QPT assumption is proved or calibrated here; no ordinary classical rewinding, RO extraction or generic-model inference is invoked.

## Concrete dimensions and executable verification

The prior illustrative, uncalibrated parameters stay q=16777213, n=256, m=4469, w=2000, B=128, g=524287 and L=52. Both strict rounding inequalities remain true, and the original statistical planted-other-scope column count bound remains unchanged because both K and L remain 256 bits and 52 digits. For N=4, C=100, J=3 packets, three bytes/field element, the combined public SOURCE and capsule size remains **45,978,768 bytes**; native public keys/signatures, manifests, evidence and Bitcoin witness data are additional. Source uniformity and concrete QPT 128-bit hardness remain UNVALIDATED.

The exact committed checker is V8/Node-compatible, deterministic and self-contained. It checks GF(256) inverses and fixed-master single-share uniformity, direct independent 16-byte native secret seed sampling plus public PK.seed, a MOCK native pk.root, two distinct legal toy SOURCE openings, every 2-of-3 share combination, adaptive single-packet coin disclosure and remaining pair recovery, malformed-share rejection and the resource inequalities. Its toy A deliberately duplicates columns, so it is NOT an LWE hardness experiment. The separately preserved LOCAL-only extended Python checker executed twice with 407,328 assertions each and identical output; the published JavaScript checker/output are the exact executed GitHub artifacts.

## NEXT UNSOLVED CRYPTOGRAPHIC EQUATION

Instantiate witness-free classical-PPT Comp(R_original,x,context,NativePK) together with its actual correlated SOURCE setup/opening data, complete public checking key and straight-line QPT-LWE challenge simulator; construct public Lift(x,W,A,U,s) for **every valid ORIGINAL witness W** to produce legal openings of any two packets and the SAME precommitted real native sk. Prove false-instance full-public secrecy and arbitrary hard-TRUE unauthorized key recovery/native forgery -> ACTUAL ORIGINAL W or independent PQ hardness break without requiring a volunteered internal representation. This construction does not solve those problems. The unknown-one-honest malicious N-of-N setup, abort-safe pre-funding DA/graph, SYS/BTC qualification and conditional PQ-native Bitcoin endpoint also remain unresolved. No funding, merge, deployment or task completion is warranted.
