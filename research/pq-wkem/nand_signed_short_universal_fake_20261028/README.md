# Tight signed-short ORIGINAL extraction and universal public fake

Research record: nand-signed-short-universal-fake-20261028-turn11. One bounded **offline** iteration; no external web or literature. Repo syscoin/PVUGC, open/draft/unmerged PR #1, research/pq-wkem-validation-20260918; initial independently read head e3b8a354770fcefe745658183427e16058b63541. Predecessor exact NAND README Git blob e2c933e8731c9c1795cc04244862e25f4829c180; prior checker 8c58ce5ed07fbc7ed584f7ab705a90437255314d; latest ordinary comment read 6465962379.

**Verdict:** A stronger, unconditional SOURCE representation lemma is proved below. **NO qualified post-quantum witness-KEM security advance.** The predecessor's generic NAND + *linear projected-source* release is insecure on every false instance, and on hard-true instances with a publicly chosen rejecting input. The independently proved half-orbit theorem for its different *fixed* false source is not invalidated.

## 1. Exact ORIGINAL compiler and honest release

For any Boolean NAND verifier V(x,W) with a final NAND output, fix public input bits x; W is its actual private ORIGINAL NP witness. This includes all generic-NP verifiers through polynomial Boolean-circuit compilation (not a signature-only relation). Let v be its wire count and G the number of NAND gates, and set m=1+2v+4G and h=1+v+G. Form the public matrix C_x over prime F_q from an anchor z*=1, wire one-hot entries u_i^0,u_i^1, and four entries t_g^00,t_g^01,t_g^10,t_g^11 per NAND gate. Its homogeneous rows encode:

    u_i^0+u_i^1=z*                          for each wire
    t_g^00+t_g^01+t_g^10+t_g^11=z*       for each gate
    t_g^10+t_g^11=u_a^1                  input a
    t_g^01+t_g^11=u_b^1                  input b
    t_g^00+t_g^01+t_g^10=u_c^1          NAND output c
    u_i^1=x_i*z*                         public statement bits
    u_final^1=z*                         acceptance

All equations are modulo q. For valid ORIGINAL W, classical polynomial-time honest lifting f_x(W) evaluates the actual verifier, sets one 1 in each wire and gate group, and obtains C_x f_x(W)=0, anchor 1, L1 norm h. Distinct witnesses may retain distinct vectors. A Bitcoin application would also require x to bind the ORIGINAL verifier, actual burn/authorization/output, claim/UTXO, path, anchors and window, and native verification key, none of which is implemented here.

The attempted public off-chain release uses genuine native signing seed K and checking key pk(K), independent uniform 256-bit U,Z, public D=U XOR Z and V=K XOR U. Encode Z in ell base-b digits a_j, where g=2h+1, b=floor(q/g)>=2, ell=ceil(256/log2 b). For each column independently sample uniform A_j in F_q^(n x r), uniform secret s_j in F_q^n, eta_j from an independently specified LWE-error distribution chi^r, eps_j uniform on {-1,0,1}^m, hidden y_j=A_j^T s_j+eta_j and public p_j=C_x^T y_j+eps_j+g*a_j*e with e the anchor unit vector. The complete public transcript also includes original (R,x), A, p, D,V, genuine pk, context, auxiliary data and related capsules. Honest Release verifies the actual original W off-chain, forms f_x(W), projects p, decodes each digit within radius h and recovers Z and exactly the same precommitted K for every valid W. This correctness is deterministic for all ternary errors. Native SLH-like signature security, QPT LWE hardness, and Bitcoin's proposed native no-EC-key-path signature output are **not** established here.

## 2. New signed-short-to-ORIGINAL theorem, unconditional

**Claim.** If q>h+2, any centered integer lift z of an F_q vector with z*=+1, C_x z=0 mod q, and L1 norm at most h+1 is necessarily an honest Boolean one-hot opening of an actual ORIGINAL accepting W. The extractor simply returns the private input-wire values. Hence for any false instance every normalized kernel vector has L1 norm at least h+2.

**Proof.** Each of the v+G *disjoint* wire and truth-table groups has sum congruent to 1 mod q. The anchor contributes one and the entire remaining L1 budget is at most h, so the absolute value of each integer group sum is at most h. Since q>h+2, that sum is exactly 1, not 1±q. An integer vector with group sum 1 has L1 norm 1,3,5,...; the minimum 1 occurs only for one +1 and all remaining entries zero. The anchor plus v+G groups already require h units, and any non-one-hot group adds at least 2. Thus a total L1 budget h+1 forces every group to be genuine one-hot. Gate/public rows then enforce ordinary Boolean NAND semantics, because their values lie in {-1,0,1} and q>4. The private wire bits give a valid ORIGINAL witness. This is a classical constructive extraction algorithm with no SIS or other hardness assumption. It proves *short representation -> ORIGINAL W*, **not** *arbitrary recovered key/native forgery -> representation*.

## 3. Tight signed fake from any rejected input

Take any public/private input W0 rejected by V(x,W0); no satisfying witness is needed. Evaluate the NAND circuit honestly, then change only the last output wire from 0 to 1. As NAND(A,B)=0 implies A=B=1, replace the last gate's honest truth-table entries (0,0,0,1) with (-1,+1,+1,0) while leaving every other group one-hot. This satisfies all *linear* C_x equations, including forced accept, anchor 1, but is not Boolean. It is publicly constructible in polynomial time and has exactly h+2 nonzero coefficients ±1, hence L1 norm h+2. Combining this explicit construction with the theorem proves the h-to-(h+2) gap is exactly tight for all false NAND-compiled ORIGINAL NP statements, not only for the earlier example. It also applies to true x whenever an easy rejecting dummy W0 exists.

## 4. Complete classical false-source and hard-true key recovery

The public pseudo-opening z_fake directly projects any source ciphertext:

    z_fake^T p_j = g*a_j + z_fake^T eps_j  (mod q),

since C_x z_fake=0. **All LWE randomness cancels** irrespective of n, chi or any coherent quantum attack. Because z_fake has exactly h+2 coefficients ±1 and ternary errors are symmetric, its projected noise is a sum of h+2 independent uniform {-1,0,1} variables. The only sums outside [-h,h] are ±(h+1) and ±(h+2), with exact counts h+2 and 1 for each sign. Thus

    P_h = Pr[|z_fake^T eps_j|<=h]
        = 1 - 2(h+3)/3^(h+2).

Those in-radius events *guarantee* correct cyclic digit decoding, including wraparound. For ell independent columns the fake reconstructs the complete genuine K=V XOR D XOR Z with probability **at least** P_h^ell. At q=257, h=8, radix15, ell66 this is 0.9757056468873536; after five harmless NAND identity paddings h=28, radix4, ell128 the lower bound exceeds 0.99999999996. For polynomial ell and growing h with polynomial prime q keeping radix>=2, this bound approaches 1 exponentially. Padding or demanding a checked short vector inside the honest off-chain Release does not stop a direct public projection bypass.

This attack is **classical** and uses no accepted ORIGINAL witness or supplied representation. On a false x it breaks full-public false-instance hiding; on true x with an easily chosen rejecting W0 it breaks unauthorized hard-true recovery. The actual native checking key remains correlated with the *recovered* K. Ordinary-QPT decisional-LWE or native EUF-CMA assumptions cannot justify the broken full public distribution because the attack directly extracts the signing seed.

## 5. Exact checks, limits and handoff

Published source check.js was executed in a JavaScript runtime before committing the source; output.json captures its exact structured result: 86 assertions for the prior true and false NAND examples, five increasingly padded false examples, all evaluated original inputs, complete compiled C_x row equalities, signed L1 values, capacity of 256-bit radix packing, and exact independent ternary-convolution counts for h=2..12. An independent **extended local-only** standard-library Python checker was executed twice with byte-identical stdout and passed 239 assertions per run; it additionally sampled actual LWE-style A,s,eta, full 256-bit XOR pads, and checked final-key recovery across 12 independent capsules for each of seven source families. Its mock key hash is clearly **not** a native SLH implementation. Arithmetic samples and finite tests do not prove QPT hardness or endpoint security.

One exact **reusable** reduction is now established: normalized **integer signed-short opening** of the compiler (L1<=h+1) gives ORIGINAL W, without assuming z binary. This closes a representation-level normalization gap. **No final-key-recovery-to-ORIGINAL-witness reduction** was obtained. A real next construction must replace the entire linear projectable release with genuinely global source-dependent information; it must provide classical-PPT Build/Release for every ORIGINAL NP statement, all-valid-witness SAME precommitted K, full-public false-instance QPT security (real pk/context/auxiliary and sibling/selective-opening correlations), and an arbitrary unauthorized true-instance final-key recovery or fresh native-path forgery -> ORIGINAL W or independently justified QPT break, *without requiring an internal representation or SourceOpen oracle*. A source-dependent LWE setup and its challenge simulator must be instantiated jointly, not only an ordinary LWE marginal hybrid. No iO/WE-labelled assumption is substituted as a solution.

No malicious N-of-N setup/abort and protected erasure, pre-signature/DA, one-honest-watcher inclusion, header/AuxPoW/tag parsing, BTC best-chain security, SYS/BTC fork-window/propagation/censorship, Bitcoin transaction graph, native PQ signature, post-quantum parameter assessment or deployment is proved here. No production or workflow changes. The task's completion conditions remain unmet; do not disable its existing automation.
