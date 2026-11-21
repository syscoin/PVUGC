# Half-orbit projected SOURCE: exact width-halving construction

Research run: half-orbit-projected-source-20261028-turn11 (offline bounded iteration). Continuity: syscoin/PVUGC draft/unmerged/open PR #1, branch research/pq-wkem-validation-20260918, parent head cc0b0c9d1debad9d202f14af5872b150a1bbc661. Exact-version predecessor: research/pq-wkem/projected_source_spectral_20261028/README.md, blob f8f200e649fb4abc21a828ec1104ccf084731547; latest top-level substantive comment read: 6463829671. No web/literature research, no production modifications.

## Constructive efficiency delta and exact restricted release

The predecessor had prime q=257, 256 source coordinates, 255 source rows, and 46 ciphertext columns. Its source-noise Fourier product used both +j and -j modulo q even though the ternary factor (omega^-j + 1 + omega^j) is unchanged by sign. Retain exactly one representative per +/- pair. New parameters: q=257; m=128; r=127; normalized source kernel z=(1,2,...,128); anchor e=(1,0,...,0); independent source noise eps_i uniformly in {-1,0,1}; legitimate restricted ORIGINAL witnesses have binary entries, anchor one and Hamming weight 2. Keep radix spacing g=5, base floor(q/g)=51, 46 columns encoding every 256-bit pad.

The FALSE source C_false has row indexed j=2..128, with -j at coordinate 0 and 1 at coordinate j-1. Thus rank(C_false)=127, ker(C_false)=span(z), z_0=1, e^T z=1; the only normalized kernel vector z is NOT binary and there is no valid anchored weight-two ORIGINAL witness. Also e is not in row(C_false), so this is NOT the prior exact row-shift certificate. The same 257 modulus and source error distribution are retained. Public source ciphertext elements are cut from 256*46=11,776 to 128*46=5,888, exactly 50%. For a public n-by-r LWE matrix A per column, its sample width falls 255 to 127 (about 50.2% fewer A elements).

The ORIGINAL restricted relation is R(C,w): w in {0,1}^128, w_0=1, sum(w)=2, Cw=0 modulo 257. It is not a generic original NP compiler and does not authenticate Bitcoin or Syscoin evidence. Classical Build samples real 256-bit native signing seed K and its actual checking key pk(K) (conditional native deterministic seed-based signature interface), independent uniform 256-bit U,Z, publishes D=U XOR Z and V=K XOR U; also publishes the relation/statement, claim/path/anchor/context, admissible auxiliary information and related capsules. Encode Z as base-51 digits a_1,...,a_46. For each digit, independently sample public A in F_257^(n x127), private uniform s in F_257^n, LWE error eta from an independently specified chi^127, ternary eps in {-1,0,1}^128, compute

    y = A^T s + eta mod257  [secret, never published]
    p = C^T y + eps + 5*a*e mod257  [published]

The public OFF-CHAIN Release first checks the ACTUAL restricted original relation, and for every digit forms t=w^T p=5*a+w^T eps modulo257. For binary weight-two w, the centered integer error is in [-2,2]. All 51 cyclic codepoints 0,5,...,250 have gaps >=5, including the wrap gap 7; decoding is deterministic. Every accepted restricted ORIGINAL witness returns the identical precommitted Z and hence identical K=V XOR D XOR Z, even if valid witnesses produce different intermediate errors. A separate same-dimension TRUE source with first row (1,-1,-1,0,...), identity rows on coordinates 3..127 and one zero row has two different valid ORIGINAL witnesses (1,1,0,...) and (1,0,1,0,...). They recover one full 256-bit K in the executed checker. The true relation is EASY, not a hard-true construction.

## Exact new Fourier identity and whole-public-vector simulator

Let q be any odd prime other than 3, m=(q-1)/2, J={1,...,m} represent all nonzero residue pairs {j,-j}. For S=sum_{j=1}^m j*eps_j modulo q and N=3^m, the nontrivial characteristic function is

    E[omega^(tS)] = N^-1 * P_t,
    P_t = product_{j=1}^m (omega^(-tj)+1+omega^(tj)), t!=0.

Because each factor is even and multiplication by t permutes the +/- residue pairs, P_t is constant P for every t!=0. The square P^2 is the full nonzero-residue product. The identity (omega^-j+1+omega^j)=omega^-j*(omega^(3j)-1)/(omega^j-1) and the permutation j->3j yield P^2=1. Since P is a Galois-invariant algebraic integer, P=+1 or -1. Reduce modulo the cyclotomic prime (1-omega), where omega becomes 1 and the residue field is F_q. Each factor becomes 3, so P is congruent to 3^m modulo q; Euler's criterion identifies P with the Legendre symbol (3|q). For q=257, 3^128=256=-1 modulo257; hence P=-1 exactly.

Fourier inversion therefore gives the exact INTEGER counts among 3^128 noise vectors:

    count(S=0)=(3^128-256)/257;
    count(S=t)=(3^128+1)/257 for every t!=0.

Any nonzero shift Delta changes two count values by exactly one, giving TV(S,S+Delta)=3^-128 EXACTLY. With hidden uniform y, full-rank C_false^T y is uniform over row(C_false); the quotient is precisely z^T p=S+5*a, so the TOTAL VARIATION distance of the **ENTIRE publicly observed p vector**, not merely an assumed marginal, is

    TV(C_false^T u+eps+Delta*e, C_false^T u+eps)=3^-128, Delta!=0.

The 257-modulus exact integer distribution and all shifts were checked. Separate q=5 and q=7 complete public p-vector distributions were exhaustively enumerated, confirming TV=1/3^m without relying on the Fourier derivation.

## Ordinary-QPT-LWE joint-public security and limitations

For the explicit fixed false source only, the ordinary decisional-LWE challenge (A,y) is embedded by computing p=C_false^T y+eps+5*a*e. Real y=A^T s+eta gives the exact honest joint distribution; uniform y gives the intermediate game. The reduction samples true K, actual pk(K), U,Z,D,V, public context and independently keyed sibling capsules with their correct correlations. It needs no challenge secret, SourceOpen oracle, attacker-supplied representation, random-oracle extraction or rewinding. Switching 46 columns costs at most 46*Adv_QPT-DecLWE(n,127,257,chi).

With y uniform, the proven full-vector shift theorem gives statistical cost <=46/3^128 < 2^-197 for replacing all digit shifts with zero, pointwise in K,U,Z and genuine pk(K). Thus arbitrary coherent QPT postprocessing cannot amplify the classical transcript statistical distance (trace-distance monotonicity). In the resulting zero-digit game, p is independent of Z. Conditional on K, the map (U,Z)->(D=U XOR Z,V=K XOR U) is a bijection: D,V are independent uniform even given pk(K). An ordinary QPT native EUF-CMA challenger can now simulate all public output without knowing K, forwarding allowed signing requests for nonchallenge messages. Accepted fresh intended-path native forgery, or correct seed recovery followed by an independently fresh signature, violates that native assumption. For one fixed false target:

    Pr[correct unauthorized K recovery or fresh native forgery]
       <=46*Adv_QPT-DecLWE(n,127,257,chi)
         +46/3^128
         +Adv_QPT-Native-EUF-CMA.

This theorem assumes ordinary classical-PPT Build and Release, arbitrary QPT adversaries with independent classical/quantum advice, and independently simulatable public auxiliary/context data. Classical adaptive openings of independently keyed siblings can be simulated honestly; unopened same-key false siblings require additional hybrids. Opening a sibling that reveals the target key is excluded and would be a direct bypass. Secret-correlated arbitrary auxiliary leakage, malicious setup, and quantum-superposition opening-oracle access are not proven safe. The sample reduction 255->127 does NOT strengthen the *independently assumed* LWE hardness at fixed n,q,chi: any 127-sample distinguisher applies to 255 by discarding extra samples. The exact statistical margin worsens from 46/3^256 to 46/3^128 but remains beyond 197 bits, so this is an explicit target-128-bit statistical/size tradeoff, NOT identical statistical security. No actual n,chi 128-bit QPT estimator or native SLH implementation has been certified.

## Work performed and missing equation

Exact committed standalone check_pub.py was executed twice offline with byte-identical output_pub1.json and output_pub2.json, 3,119 assertions per run. Separate extended local checker check.py passed 5,821 assertions twice, including 500 exact LWE-challenge couplings and 20 full 256-bit same-K trials. The published checker and outputs, exact integer derivation, and local complete archive preserve provenance; tests do not establish quantum hardness.

**The intended recovery-to-ORIGINAL-witness theorem is STILL UNPROVED.** This only improves a surviving restricted fixed-false SOURCE component. For generic ORIGINAL (R,x), an efficient x->C_x and every-valid-W map f_x(W) must satisfy C_x f_x(W)=0 and e^T f_x(W)=1, full-public false-instance security must hold for all false x, and arbitrary unauthorized true-key recovery/native forgery must yield an ORIGINAL witness or independently justified QPT break without assuming that the adversary volunteers an internal representation. The uniform-y LWE hybrid cannot hide a true source from an available short opening. No hard-true source compiler, malicious N-of-N graph/ceremony, abort/evidence-availability, Bitcoin PoW/AuxPoW/source/DA/interval graph proof or native PQ signing deployment is established. Completion condition unmet; keep research automation enabled.
