# Unplanted random-linear SOURCE: true-instance work hardness and exact false shield

Research-only extension of `joint_linear_release_20261026` on `syscoin/PVUGC#1`, starting draft PR head `3936efe2e6672ae1fe9edd0ee5594f55ab7b10fe`. Offline derivation, not a generic-NP or Bitcoin bridge WKEM. The prior helper-aware full-joint QPT-LWE theorem is reused for its EXACT uniform-matrix distribution, not for an arbitrary circuit-compiled matrix.

## Classical release and model

Choose m>=2, n>=1, q=2^a, Delta=2^d|q with 0<d<a, r=a-d, k>=1, ell>=ceil(k/r), and independent chi errors e in [-beta,beta]^n with Delta>2n*beta. Fix b=e1=(1,0,...,0). Sample A uniformly from (Z_q)^(m x n). ORIGINAL reference relation R_(A,b)(w) means w is BINARY and Aw=b (mod q). No witness is planted, known, enumerated or needed by Build.

Generate uniform native seed K of k bits and public pk(K), independent of A. For each independent j=1..ell, choose s_j uniform Z_q^m and e_j~chi^n; set P_j=(s_j)_1, p_j=A^T s_j+e_j, h_j=P_j mod Delta, z_j=(P_j-h_j)/Delta. Concatenate the fixed-length r-bit encodings of z_j as Z, choose a fixed public full-rank k-bit linear projection L, and set D=K XOR L(Z). Publish (x,A,b,q,Delta,ell,(p_j,h_j),D,pk(K),bound context,allowed aux,related capsules). Retain no s_j,e_j,P_j,K under honest setup. This is not a keyless or malicious-secure N-of-N ceremony.

For EACH valid binary w, w^T p_j=P_j+w^T e_j. Because |w^T e_j|<=n beta<Delta/2, the nearest point in h_j+Delta Z_q on the q-cycle is uniquely P_j. Hence every ORIGINAL witness, even one selected after seeing the capsule, deterministically recovers the SAME precommitted K. No canonical witness or intermediary SOURCE state is required.

For b=e1 decompose A=[alpha;B] with alpha uniform Z_q^n and B uniform Z_q^((m-1)x n), independent; s_j=(P_j,u_j). Thus p_j=alpha P_j+B^T u_j+e_j. A standard decisional-LWE challenge (B,c=B^T u+e or uniform c) embeds as p_j=alpha P_j+c while the simulator itself samples P_j and therefore h_j, Z, D, and K, retaining pk(K), all other columns, context and admissible aux. Successive straight-line hybrids replace all ell opening columns. In the final hybrid p_j is independent uniform and z_j are uniform independent of p_j,h_j; hence L(Z) is EXACT uniform, so D is uniform even conditioned on pk(K). For arbitrary QPT algorithms in the matching challenge/advice model:

  Pr[exact K recovery] <= eps_native_seed + ell*Adv_LWE^QPT.      (J)

A fresh-message native signature forgery has the analogous EUF-CMA term, only when legitimate signing queries/pre-signatures and transaction-scope context are simulated by the native challenger. No native signature deployment or transaction-graph soundness is inferred.

## NEW: unplanted true ORIGINAL statements exist overwhelmingly

Let N(A)=#{binary w:Aw=e1}. Zero w is never accepted. Each nonzero binary w has a unit coordinate, so Aw is uniform Z_q^m. Distinct nonzero binary w,v have a 2x2 coordinate minor of determinant +1 or -1; thus (Aw,Av) is joint uniform even for composite q=2^a. Consequently the indicators 1[Aw=e1] are pairwise independent, giving EXACTLY

  mu=E N(A)=(2^n-1)/q^m,
  Var N(A)=mu*(1-q^(-m)),
  Pr[N(A)=0]<=delta=min(1,q^m/(2^n-1)).                   (E)

If n>=m*a+lambda+1, delta<2^(-lambda). Build sampled A without discovering any witness, yet A has many valid ORIGINAL witnesses in expectation and is true with overwhelming probability. For a QPT adversary tailored to this true-conditioned ensemble but with the SAME simulatable public context/advice, run its circuit on unconditioned A and use (J):

  Pr[recover K | N(A)>0] <= min(1,(eps_native+ell*Adv_LWE)/(1-delta)). (T)

This proves true-instance key hardness conditionally on ordinary QPT LWE and native hardness for THIS average-case source, not a hard-true theorem for fixed or adversarially chosen NP statements.

## NEW: finding the ORIGINAL binary witness directly breaks standard LWE

Let W(A,b,context) be any QPT witness-search algorithm with success p_find over uniform A. Given an ordinary LWE challenge (B,c), sample independent uniform alpha and construct A=[alpha;B], b=e1. Call W ONCE. If its output is not a valid binary w, reject. Otherwise test whether the centered cyclic distance |w^T c|_q <= n beta. For real LWE, Bw=0 and w^T c=w^T e, so the test always passes when W succeeds. For uniform c, the nonzero binary w is independent of c and has a unit coordinate; w^T c is uniform Z_q. Thus with tau=(2n beta+1)/q<1,

  Adv_LWE^QPT >= p_find*(1-tau),
  p_find <= Adv_LWE^QPT/(1-tau).                         (S)

This is straight-line QPT search-to-DECISION LWE without rewinding, unknown witness oracle, generic-SIS assumption or attacker-volunteered intermediate state. If a QPT finder instead receives the COMPLETE capsule and outputs a valid w, appending exact honest Recover gives a full-view K-recovery adversary, so (J)/(T) bound its success. No honest witness setup or earlier key exposure is silently assumed.

## NEW: fixed full-transverse-rank FALSE source has perfect public secrecy

For ANY FIXED A=[alpha;B], still b=e1, suppose B modulo 2 has full column rank n (requires m-1>=n). Its n-by-n invertible mod-2 minor lifts to a unit determinant mod q, so u->B^T u is SURJECTIVE onto Z_q^n. With uniform u, p=alpha P+B^T u+e is EXACT uniform even conditioned on P,A,e's independent law. Therefore z is uniform independently of all public p,h; across columns L(Z) uniform and D independent of K jointly with pk(K), context and permitted independent auxiliaries. The complete capsule has an explicit perfect classical simulator; arbitrary QPT/coherent postprocessing cannot distinguish it. And Bw=0 implies w=0 over Z_q, incompatible with alpha.w=1, so this x is FALSE even for unrestricted modular w.

For uniform A with m-1>=n, the probability B lacks full column rank mod 2 satisfies

  Pr[rank_2 B<n] <= (2^n-1)/2^(m-1) < 2^(n-m+1).      (F)

Thus m>=n+lambda+2 generates a certified false-protected source except with probability <2^(-lambda-1). This OVERDETERMINED false regime differs from the UNDERDETERMINED hard-true regime above. They do not combine into a generic-NP false-instance-security proof. The stronger rank property, not merely b outside the column span of A over a composite ring, is the exact sufficient condition established here.

## Scope, reproducibility, and unsolved bridge obligation

All honest sampling and recovery are classical polynomial-time in the emitted dimensions. Security statements (J),(T),(S) use ordinary decisional LWE for dimension m-1, n samples, q, exact bounded chi, assumed QPT-hard in the same nonuniform advice model; these exact parameters are NOT validated at 128-bit security. Advice/context must be efficiently simulatable and independent of unknown LWE secret and fresh private release coins. Source A cannot be adversarially substituted for a structured circuit A_x; arbitrary private setup coins retained by dishonest parties or opened same-key/related true capsules defeat the intended security game. Fresh independent unopened false capsules compose when their private release coins are independent; general adaptive selective opening and malicious abort are unproved.

The executed standard-library `check.js` checks exact random-matrix witness-count moments, unit 2x2 minors, full-rank fixed false-source conditional p/P law, two distinct true witnesses opening a common K, and the transverse small-error identity. Its captured `validation.json` is finite algebra only, not cryptographic benchmarking or a QPT experiment. A longer independent Python exact checker (169,352 assertions twice, identical outputs) is LOCAL_ONLY with complete mathematical elaboration; this shorter published note contains the FULL assumptions and proof of the four stated lemmas.

**Exact remaining gap for generic NP / real Syscoin bridge:** construct polynomial algorithms mapping each ORIGINAL bound light-client/burn/PoW statement x into public source (A_x,b_x,aux) with exact every-ORIGINAL-witness correctness and a QPT-indistinguishable FULL joint distribution that a standard LWE challenge can simulate WITHOUT the challenge secret. The actual compiled transverse B_x, checking key, helpers, claim/path/anchors and related capsules must all be included. No accepted nonbinary short pseudowitness is permitted. Nothing here authenticates Bitcoin best-chain membership, solves honest-observer inclusion or implements native PQ Bitcoin signatures. Practical arbitrary-NP PQ WKEM remains UNSOLVED; keep research automation enabled.
