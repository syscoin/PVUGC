# Projected-source LWE with exact false-source quotient smoothing (28 October 2026)

**Status:** Restricted, independently instantiated false-SOURCE composition lemma and real classical Release; **NOT** generic-NP witness-KEM, hard-true original-witness extraction, a concrete 128-bit QPT instantiation, or Bitcoin deployment.

**Provenance:** bounded offline run projected-source-spectral-20261028-turn11. syscoin/PVUGC PR #1, research/pq-wkem-validation-20260918; starting head 536c34ec3941ede9c9ddbe9725cad6ce4a573587, draft/open/unmerged. Exact predecessor research/pq-wkem/source_glued_lwe_residual_20261028/README.md blob 53e6c8375b66bf3609a5f7bc559a3de56dbe04c3, latest substantive top-level comment read 6462735285. No external research.

## Source, complete Build distribution, and public Release

For an odd prime q other than 3, statement x is a PUBLIC source matrix C_x in F_q^(r x m), with anchor e=(1,0,...,0). The **restricted ORIGINAL relation** is

    R(C_x,w) := [w in {0,1}^m, w_0=1, sum_i w_i=2,
                  C_x w=0 mod q].

This relation is genuinely the verified source for the experiment, not a separate planted random puzzle. It is NOT a compiler from arbitrary (R,x) or a statement proving an actual SYS/BTC burn.

Classical honest Build chooses an actual uniform 256-bit native signing seed K, its actual deterministic checking key pk(K) (conditional native-SLH-like interface only), independently uniform 256-bit U,Z, and publishes D=U XOR Z and V=K XOR U. Encode Z in radix b=floor(q/g) as ell=ceil(256/log2 b) digits a_j. For each j, choose uniform public A_j in F_q^(n x r), secret s_j uniform F_q^n, standard LWE error eta_j from independently specified chi^r and independent ternary eps_j uniform {-1,0,1}^m. Compute

    y_j = A_j^T s_j + eta_j           mod q,
    p_j = C_x^T y_j + eps_j + g a_j e mod q.

Publish C_x, A_j, p_j, genuine pk(K), D,V, relation/claim/context/aux and related capsules. Do **not** publish y_j, s_j, eta_j, eps_j. Related independent-key siblings retain their genuine keys and ciphertexts.

Off-chain Release(W) checks ORIGINAL R(C_x,W), lets w=W, then computes

    w^T p_j = w^T eps_j + g a_j mod q.

Since every valid binary weight-two w has |w^T eps_j|<=2, q=257, g=5, b=51, ell=46 give deterministic cyclic nearest-center decoding of ALL 256 bits (last codepoint 250 is separated from zero across the modulus by 7). Every valid W returns the **SAME** precommitted K=V XOR D XOR Z, even when its intermediate state differs. Unauthorized recovery must be analyzed separately: checking R inside an honest Release function does not stop arbitrary attackers decoding without that check.

## What changes relative to the predecessor

The old scheme published p_L and p_R=Rmix^T p_L+C_x^T t+eps+g a e; an observer simply subtracted the PUBLIC Rmix^T p_L. In this scheme the LWE vector y_j is **hidden**, and the public p_j contains only its C_x^T projection. Public kernel vectors still remove y_j, but leave the actual ternary quotient noise. We PROVE that this quotient statistically hides a for one explicitly fixed FALSE SOURCE, rather than postulating an unproved SourceOpen or scalar-pad interface.

## Explicit fixed FALSE x, no row-shift certificate

Take q=257, m=256, r=255, z=(1,2,...,256), e=e_0. Define C_false with rows j=2,...,256 having -j at coordinate 0, 1 at coordinate j-1 and zeros elsewhere. Its rows are linearly independent, C_false z=0 and ker(C_false)=span(z). Any anchor-one kernel vector equals z modulo q, so no binary weight-two ORIGINAL W exists. The relation is false. Also e^T z=1, so e is not in row(C_false) and there is **no exact false row-shift certificate**.

For uniform u in F_q^r, C_false^T u is uniform in row(C_false). Consequently p=C_false^T u+eps+g a e is uniform *within each rowspace coset* and all dependence on a is contained in one quotient:

    z^T p = S+g a mod q,
    S = sum_{j=1}^{q-1} j eps_(j-1) mod q.

For any primitive q-th root omega and any nonzero t in F_q, the characteristic function obeys the EXACT identity

    E[omega^(t S)]
      = 3^(-(q-1)) product_{j=1}^{q-1}
                            (omega^(-tj)+1+omega^(tj))
      = 3^(-(q-1)).

The product proof uses omega^(-j)+1+omega^j = omega^(-j)(omega^(3j)-1)/(omega^j-1). Multiplication by 3 permutes the nonzero exponents (q prime, q!=3), and the combined phase is 1 because q is odd. Fourier inversion gives exact integer counts N=3^(q-1):

    count(S=0)=(N+q-1)/q,
    count(S=t)=(N-1)/q  for every t!=0.

Only the zero residue has one extra occurrence compared with each other residue. Therefore for every nonzero shift Delta, the statistical distance between S and S+Delta is **exactly 1/3^(q-1)**; uniform rowspace masking implies that this is also the TV distance between the ENTIRE public vectors p and p+Delta e. For q=257 this is 3^-256, less than 2^-405.75. The q=5 **entire-vector** distribution was independently enumerated and has TV exactly 1/81. This is a *genuine fixed false-source* null simulator, without rank certificates or an assumed SOURCE oracle.

## Joint-public QPT reduction and native checking-key correlations

An ordinary decisional-LWE challenge (A,y) is embedded **exactly** by outputting p=C_false^T y+eps+g a e, while sampling the actual native seed K, pk(K), U,Z,D,V and every permitted independent sibling. The real challenge is the genuine Build transcript. The uniform challenge has independent uniform y; the reduction requires NO LWE secret, SourceOpen oracle, internal witness, quantum rewinding or random-oracle extraction. A columnwise hybrid costs at most ell times independently assumed QPT-DecLWE advantage for (n,r,q,chi). If public A is reused, other columns can be generated with independent known secret vectors using that same A.

After the LWE hybrid, condition pointwise on ACTUAL K,U,Z and all permitted publicly simulatable auxiliary data. Replacing every protected digit term g a_j e with zero changes the FULL joint public classical transcript by at most ell*3^-256, with the genuine checking key and XOR correlations unchanged. Statistical distance bounds arbitrary coherent QPT postprocessing by trace-distance data processing.

In the zero-digit game, p_j=C_false^T u_j+eps_j is independent of K,U,Z. Given any K, the map (U,Z) -> (D=U XOR Z, V=K XOR U) is a bijection; D,V are thus joint uniform and independent of pk(K). A simulator given only a genuine NATIVE EUF-CMA checking-key challenge pk can sample D,V and zero-digit p_j without knowing K. A new accepted intended-path native signature is an independent QPT native-signature forgery. Recovery of a correct seed K also gives a forgery by signing a fresh message using the seed-reconstructed native SK, PROVIDED the native seed deterministically determines that SK and the challenge message was not previously signed.

For the **explicit fixed false x only**, classical opening/signing interfaces, independently generatable nonuniform classical or quantum advice uncorrelated with the target secret/hidden errors, and independently keyed adaptive sibling openings:

    Pr[unauthorized target K recovery or fresh signature forgery]
      <= 46 * Adv_QPT-DecLWE(n,255,257,chi)
         + 46/3^256 + Adv_QPT-Native-EUF-CMA.

This theorem is independently conditional on ordinary QPT DecLWE and native EUF-CMA; it does NOT assume common hidden-value release or a SOURCE-opening oracle. Both checking key and all permitted sibling/public context correlations are inside the reduction. Multiple unopened target-key capsules with independent pads/noise incur corresponding additional per-column hybrids; *opening another capsule with the same target key* exposes K and is an excluded bypass. Auxiliary data must be publicly simulatable; secret-correlated side-channel leakage of target K, U/Z, y or eps is NOT covered. Signing queries may be forwarded to a standard native signing oracle for preauthorized nonchallenge messages. Arbitrary coherent computation on all classical public data and classical adaptive replies is allowed; quantum-superposition opening-oracle access is not granted. No concrete 128-bit hardness is certified for the illustrative q=257.

## A TRUE-source release with two distinct ORIGINAL witnesses, not hard-true secrecy

With the SAME q=257,m=256,r=255, define C_true with first row (1,-1,-1,0,...), identity rows at coordinates 3..255 and one zero row. Two distinct accepted ORIGINAL witnesses are w1=(1,1,0,...) and w2=(1,0,1,0,...). Their projected errors eps_0+eps_1 and eps_0+eps_2 differ, yet both decode every radix digit and the exact same 256-bit K. This true x is **easy** (the matrix rank even differs from the false example); anyone can find a witness. NO hard-true security conclusion is implied. Worse, even AFTER y is replaced with uniform, a valid short w still decodes the protected digit. The ordinary-LWE hybrid cannot make a true-source capsule independent of its seed, so the unauthorized true-key recovery -> ORIGINAL witness or independent PQ break remains UNSOLVED.

## Reproducibility, limitations, and next equation

The committed standalone standard-library check_pub.py was **actually run twice offline**, byte-identical outputs output_pub1.jsonl and output_pub2.jsonl: **11,473 exact assertions** per run, including exact q=5 full-vector TV, prime q=5,7,11,17,257 ternary Fourier-count/shift identities, and eight complete 256-bit SAME-K release trials for two ORIGINAL witnesses. The independent extended LOCAL-ONLY check.py passed **13,509 assertions twice identically** and additionally tested 260 joint source-LWE challenge couplings and fifteen 256-bit release trials. All local full derivation, exact executed scripts and outputs are preserved in the companion downloadable archive. Checks are arithmetic, NOT QPT cryptanalysis or native SLH operation.

**Exact missing equation:** find a single classical-PPT compiler x -> C_x and f_x(W) for *every* ORIGINAL NP relation and valid W, such that C_x f_x(W)=0, e^T f_x(W)=1 and every W releases the SAME precommitted capability; for every false ORIGINAL x simulate the COMPLETE public view under independently justified QPT assumptions; and for unauthorized hard-true recovery/native forgery, obtain a valid ORIGINAL W or independent QPT break **without requiring an internal representation volunteered by the adversary**. An independently instantiated efficient compiler and the hard-true extraction are NOT provided by the explicit false-source Fourier result.

No graph/ceremony/abort/erasure/DA/Bitcoin header/AuxPoW/tag/ancestor/reorg/fork/window/challenge-path proof, no generic NP relation authentication, no real SLH implementation, no keyless Build, and no production claims. Practical completion is UNMET; do not disable the ongoing research task.
