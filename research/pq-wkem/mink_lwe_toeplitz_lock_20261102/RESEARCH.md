# MINK-LWE-TOEPLITZ-LOCK-20261102-R14: whole-vector one-honest precommitment

**Result:** An explicit, restricted no-CRS commitment for authenticating a proof-CRS contribution before reveal, with statistically binding messages against a corrupt sender (even one choosing a malicious LWE matrix) and QPT computational pre-opening hiding of an honest sender. Its expander uses the exact ordinary QPT-LWE distribution below; this is not a generic witness-KEM or a full CRS ceremony. This continues the unfinished corrupt-contribution-locking step in MINK-EVC-20261102 and does not change MINK-QUAD-PACK-R13 SOURCE release.

## Public-matrix ordinary-LWE expander, including its challenge simulator

Fix security parameter lambda, q_L=2^k, n,m, ell_e, with m*k > n*k+m*ell_e. Let chi be uniform on [-2^(ell_e-1), 2^(ell_e-1)-1]. Define kappa=n*k+m*ell_e and delta=m*k-kappa. Sender i samples an independently uniform public A_i in Z_(q_L)^(m x n) and **authenticates/fixes A_i before receiver challenges**. An honest sender keeps its independent seed S secret until opening. The kappa bits of uniform S encode s uniform in Z_(q_L)^n and e consisting of m independent chi samples.

Define G_A(S)=LE_k(As+e mod q_L), exactly m*k output bits. Its QPT PRG property is the *ordinary decisional-QPT-LWE* assumption for the pair of classical distributions (A,As+e) and (A,U), where A and U are uniform, s is uniform, and the error law is exactly chi. There is no fixed A pseudorandomness assumption, random oracle, SourceOpen oracle, quantum rewinding, or extra independent PRG hypothesis.

To obtain D bits, split G_A(S_j) into its first delta bits O_j and last kappa bits S_(j+1), and concatenate O_0,O_1,..., truncating after t=ceil(D/delta) iterations. A is the *same public, honestly uniform* matrix throughout. A standard straight-line t-step QPT hybrid, replacing one uniform intermediate seed output at a time, gives

  Adv_QPT((A,F_A(S;D)),(A,U_D)) <= t * Adv_QPT-DLWE(n,m,q_L,chi).

For an honest sender, J independently seeded commitments under the same A cost at most J*t LWE advantages against one real-vs-uniform joint pre-opening view. An arbitrary QPT adversary may compute coherently from all public classical inputs; independent quantum advice is allowed. Auxiliary information already containing hidden seed S, a released opening, or a source-related private key is *not* covered.

## Exact commitment and opening

Let a canonical fixed-length message M be L bits, for example a vector of d F_65537 coordinates each encoded in exactly 17 little-endian bits with values >=65537 rejected. Fix lambda_bind and D=L+2*kappa+lambda_bind. Each recipient j independently samples a uniform binary Toeplitz D-by-L matrix T_j, encoded by D+L-1 random diagonal bits, **only after all sender A_i are fixed**. Any corrupt recipient may choose its T_j arbitrarily; the existence of at least one honest recipient h supplying uniform T_h is the binding guarantee.

For each pair (i,j), sender i samples independent uniform kappa-bit seed S_ij, then publishes the D-bit commitment:

  C_ij = F_(A_i)(S_ij;D) XOR (T_j*M_i)   over F_2.

All commitments of sender i must be to the *same* canonical M_i. On opening, i publishes M_i and all S_ij. Each participant recomputes every commitment and checks fixed lengths, canonical fields and signed/authenticated context (session, claim/UTXO, branch, relation identity, anchor/window, party i/j, and purpose). No pre-funding authorization can be issued unless every participant's complete opening and required source/graph checks succeed. Refusal or malicious last-minute withholding aborts funding; it is not a successful security-preserving settlement.

## Independent statistical-binding proof, arbitrary corrupt A_i

Fix arbitrary A_i *before* honest receiver h samples T_h. For every nonzero Delta M in F_2^L, T_h*(Delta M) is uniform over F_2^D. To open the same C_ih to distinct M and M', some seeds S,S' must satisfy

  T_h*(M XOR M') = F_(A_i)(S;D) XOR F_(A_i)(S';D).

For each fixed S,S',nonzero Delta M the event has probability 2^(-D). A union bound over at most 2^(2*kappa) seed pairs and 2^L-1 nonzero message differences proves the *global bad-matrix event*

  Pr[any accepted two openings to DIFFERENT messages] <= 2^(2*kappa+L-D) = 2^(-lambda_bind).

No computational hardness is assumed for this binding lemma. It holds against unbounded search and coherent quantum strategies since, outside the bad-matrix event, *no such pair of accepted openings exists*. Multiple different seeds opening the SAME message are allowed. Across at most N-1 corrupt senders and Q independently fresh ceremonies, use bound Q*(N-1)*2^(-lambda_bind). The adversary must not choose or replace its A_i after seeing honest T_h; that ordering is indispensable.

## QPT hiding against malicious recipient challenges

For uniform honest A_h and its fresh S_hj, any maliciously chosen T_j (possibly based on A_h and prior authenticated public inputs) yields C_hj indistinguishable from uniform D bits by the above LWE PRG hybrid; XOR with T_j*M_h is a known translation. A J-recipient joint pre-opening view differs from J uniform independent pads by <=J*t*Adv_QPT-DLWE. Two chosen honest messages cost at most twice that bound. This is an actual independent LWE challenge simulation of the commitment distribution, *not* a SOURCE opening simulator. The proof does not claim hiding after honest seed/message openings or against auxiliary correlated to those secrets.

## Exactly what this does and does not close

This component gives the one-honest recipient a **statistically binding lock** on corrupt sender messages and gives the honest sender QPT hiding of its own message *until opening*, using authenticated sender-first matrix broadcasts. Its public checking-key dependence is limited to the commitment's own public A_i,T_j,C_ij, context and independent auxiliary advice. It **does not** provide a polynomial-time extractor of a corrupt M_i from C_ih before its opening, a simulator that can equivocate the honest commitment, or a full-public joint distribution with native vk, SOURCE capsule, setup proof, related capsules and arbitrary auxiliary data. An adversary can selectively abort after seeing openings; no fully unbiased completed CRS, malicious one-honest MPC ceremony, adaptive corruption, or useful completeness against all aborts is proved. Statistical binding plus pre-opening hiding cannot be silently promoted to a programmable QPT-LWE CRS hybrid.

In particular MINK-QUAD-PACK's adversarial FALSE SOURCE with A=0 and sparse b still exposes the capability. The required generic-NP Compile/Build/Lift is absent; every valid ORIGINAL witness SAME precommitted capability is established only for the old restricted LWE-native relation, not an arbitrary ORIGINAL relation. Arbitrary unauthorized hard-TRUE seed recovery/native forgery => an actual ORIGINAL witness or independently justified QPT break also remains uninstantiated. No native Bitcoin PQ functionality or deployment claim follows.

## Parameters and bounded reproducibility

For the unassessed LWE PRG q_L=65536, n=256,m=4096,ell_e=10: kappa=45056 bits, delta=20480 bits. A proof-key-share contribution containing two 4800-coordinate F_65537 vectors has L=163200 bits. At lambda_bind=128, D=253440 bits, t=13, 31,680 commitment bytes per pair; 52,080 Toeplitz challenge bytes per receiver; 5,632 bytes of seed plus 20,400 message bytes per opening; each sender's public A_i takes 2,097,152 bytes and is shared over its pair commitments. These are size formulas, not executed full-scale timings or a 128-bit QPT hardness estimate. Locking the whole large proof matrix instead would be considerably more expensive.

The exact executed Node checker enumerates all 512 small Toeplitz matrices for a two-bit message and detects 39 matrices supporting two distinct-message openings, below the proved <=128 bound. It also checks toy LWE generation/PRG iteration, 25 sender/receiver commitments including one malicious A_i=0, same-message alternate seeds, tampered messages, balanced Toeplitz images and additive field uniformity. Two identical runs passed 1,087 assertions each. A separate local Python checker passed 1,400 assertions twice and is not GitHub-published as the Node checker. The first Python run had a deliberately corrected erroneous seed-uniqueness assertion; same-message multiple opening seeds are valid. Neither checker establishes QPT security, verifies a complete native-signature path, or executes a complete malicious setup ceremony.

**Next exact unsolved equation:** supply a straight-line, classical-PPT source-dependent simulator which can produce and open all public setup/checking-key/capsule correlations when one SRC opening is replaced by an ordinary QPT-LWE challenge *without knowing the challenge secret*, and prove universal adversarial-FALSE protection plus arbitrary unauthorized hard-TRUE recovered key/accepted native signature -> ORIGINAL witness or independent QPT break. This proof-component lock does not solve that release problem.
