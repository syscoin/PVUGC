# Spectral extraction of an ORIGINAL witness from arbitrary final-key recovery — restricted planted SOURCE

Research record: planted-source-spectral-extractor-20261028-turn11.
Offline, no outside literature. syscoin/PVUGC draft/open PR #1, branch research/pq-wkem-validation-20260918. Verified start head 26647ce15635d41e1a7eb74f2284636bab5e6777; predecessor research/pq-wkem/multi_quotient_source_20261028/RESEARCH.md blob 5fd1813a28d544ecb8b9d0d95de4743c47b691ec; relevant ordinary comment 6472541499.

**Result:** For a separately specified, **PLANTED anchored binary short-kernel ORIGINAL relation**, the actual final signing-seed-recovery or native-forgery advantage of an arbitrary QPT circuit (with fresh, independent invocations and classical external interfaces) yields a **classically extracted ORIGINAL witness**, without asking the adversary for an internal representation. The reduction uses a proved planted-code Fourier concentration bound and an explicit classical-query Fourier-list procedure. This is a genuine restricted hard-TRUE recovery-to-ORIGINAL extraction technique, **not** a generic-NP WKEM, not 128-bit planted-search hardness, and not a Bitcoin/Syscoin deployment.

## Source, full-public Build and all-original-witness release

Fix an odd prime q>3, M coordinates, an anchored binary witness of weight h, g=2h+1<q, b=floor(q/g)>=2, ell=ceil(kappa/log2 b). The ORIGINAL relation is exactly R(G,w)=[w in {0,1}^M, w[0]=1, weight(w)=h, G*w=0 modulo q]. The planted testbed chooses a uniformly random such w, then samples a uniform rank-r public rowspace of w-perp, r=M-k. The planted-search challenge supplies **only G**, not w. Every honest procedure is classical PPT; planted generation **knows w** and is not a witness-free compiler for arbitrary NP statements.

Honest Build samples the real seeded native signing secret K (kappa bits) and *actual* native checking key pk(K), independent uniform U,Z in {0,1}^kappa, publishes D=U xor Z and V=K xor U. Encode Z into ell radix-b digits a_j. For each independently sample hidden uniform u_j in Fq^r and independent ternary eps_j in {-1,0,1}^M. Publish
    p_j = G^T*u_j + eps_j + g*a_j*e0  (mod q).
The full public view contains R, G, all p_j, genuine pk(K), D,V, source/claim/UTXO/branch/anchor/window/context/checking-key bindings, admissible auxiliary strings and eligible sibling capsules. Such context bindings must be authenticated by the real ORIGINAL relation in an actual BTC/SYS use; this short-kernel example does **not** authenticate burns, AuxPoW, headers or output ownership. u and eps are never published.

Public OFF-CHAIN Release checks the actual R(G,w') and calculates
    w'^T*p_j = g*a_j + w'^T*eps_j modulo q,
with |w'^T*eps_j|<=h. Center distance is at least g>2h, including cyclic wrap, so **every valid ORIGINAL w'** decodes the same a_j, Z and exact precommitted K=V xor D xor Z, even if valid witness states differ. No Bitcoin VM/proof or external release authority is invoked. Honest setup is assumed; no keyless or malicious-ceremony claim.

An OPTIONAL LWE Build replaces uniform u_j by unpublished y_j=A_j^T s_j+eta_j, with public A_j and independent LWE samples. A standard QPT decisional-LWE challenge (A,y) embeds EXACTLY into the source-dependent p_j without a secret or SourceOpen oracle, and the real-to-uniform hybrid retains genuine pk/D/V, context, related capsules and checking-key correlations. If adversarial success changes, this yields an ordinary-QPT-decisional-LWE distinguisher at those explicit parameters; otherwise the uniform-source theorem below applies. Neither variant has an independently certified 128-bit parameter set.

## Whole-public Fourier concentration — independent calculation

Let H=im(G^T), E=law(eps), P_a=law(G^T u+eps+ga e0), and use Fourier coefficients indexed by z in Fq^M:
    hat P_a(z)=1{Gz=0} hat E(z) omega^(ga*z0);
    hat E(z)=product_i (1+2*cos(2*pi*z_i/q))/3.
For the UNKNOWN planted w, define P_a^(w) by drawing t=w^T eps+ga and drawing a uniform p from the affine fiber w^T p=t. This is a mathematical comparison distribution; the extractor NEVER samples it. By full-vector Parseval and Cauchy-Schwarz,
    TV(P_a,P_a^(w)) <= (1/2)*sqrt(V_G),
    V_G = sum_{z in ker(G) \ span(w)} |hat E(z)|^2.             (1)
This is the COMPLETE ciphertext vector, not a marginal pad or supplied-opening lemma.

Conditioned on planted w, ker(G) is a uniform k-subspace containing w. For every fixed z outside span(w), the exact inclusion probability is
    pi=(q^(k-1)-1)/(q^(M-1)-1).
Ternary independent errors give exact Parseval mass
    sum_{z in Fq^M}|hat E(z)|^2=(q/3)^M.
Hence, without cryptographic assumptions or an oracle,
    E_G V_G = pi * [(q/3)^M - sum_c |hat E(cw)|^2]
            <= pi*(q/3)^M.                                 (2)
By Markov, Pr[V_G>theta]<=pi*(q/3)^M/theta, pointwise for any planted w. GOOD means V_G<=theta; no efficiently checkable GOOD certificate is required.

One arithmetic illustration: q=65537, M=1024, k=32, rank(G)=992, h=128, g=257, b=255, ell=33 for kappa=256. Exact integer comparison yields pi*(q/3)^M<2^-1100. For theta=2^-512, BAD probability <2^-588 and the complete P_a is within 2^-257 of P_a^(w) for each a. Public G costs 1,015,808 field elements (~2.03 MB at 2 bytes each); one capsule p uses 33,792 elements (~67.6 KB). **These are not quantum-hardness estimates.** The planted distribution is very far from unplanted SIS: a random rank-992 matrix has expected anchored weight-128 binary kernel count <2^-15323. Therefore one MUST NOT import ordinary unplanted SIS hardness; the explicit planted distribution needs independent QPT cryptanalysis or a genuine reduction.

## Arbitrary QPT final-key/signature recovery -> ORIGINAL w

Let A return an exact valid native secret K or a fresh intended-path native signature, with all advertised full-public data and admissible classical signing/opening queries. Multiple **unopened** same-K target capsules may share this same planted G but must have independently sampled (U_i,Z_i,u_ij,eps_ij); there are L=t*ell target-key-bearing columns in total. Opened independent-key siblings are simulatable; a same-K sibling whose opening is released trivially reveals the target K and is excluded. Auxiliary information must be publicly samplable given G,pk and independent coins, not contain hidden source/witness/seed leakage; no one-use uncloneable quantum advice or superposition signing oracle is assumed. A may perform arbitrary coherent QPT computation inside each fresh invocation.

In H_0, replace ga_ij e0 by ZERO in all L target columns while preserving actual K/pk, D_i=U_i xor Z_i,V_i=K xor U_i, contexts and all siblings. Because the (U_i,Z_i) are jointly uniform, (D_i,V_i) are independent uniform pairs EVEN CONDITIONAL ON genuine pk(K). All zero-shift p are independent of K. A simulator given only genuine pk thus reproduces H_0 exactly and converts a correct K or fresh signature into a native QPT-EUF-CMA forgery (under proper claim/path freshness). In H_L, all L shifts are real. If A's real recovery advantage exceeds H_0 by eta, one hybrid column j has signed positive gap >=eta/L. Condition on its true digit a. Discarding digit values of individual probability <eta/(2Lb) shows some nonzero a of probability >=eta/(2Lb) has conditional positive gap Delta>=eta/(2L). It can be sampled in expected polynomial time. Enumerate all L,b possibilities; the reduction does not know the successful pair.

For each candidate j,a define a bounded function on **arbitrary classical ciphertext vectors p**:
    f_j,a(p)=Pr[A succeeds when the entire hybrid transcript is
                    honestly sampled conditional on digit a,
                    except its jth ciphertext is forcibly p].
Each function sample is ONE independently initialized QPT A invocation plus honest sampling, returning a Bernoulli outcome. The planted-search reduction knows K/pk and simulates everything from G without w. Its real-vs-zero gap is E_{P_a}f-E_{P_0}f. On GOOD G, (1) transfers this to the w-only distributions at loss <=sqrt(theta). Since those distributions have Fourier support only on span(w), expanding their difference gives
    max_{c !=0} |hat f_j,a(cw)|
       >= (Delta - sqrt(theta))/(2(q-1)).                 (3)
This is an explicit **heavy hidden ORIGINAL-witness Fourier frequency** forced by arbitrary final-key/signature success, not by an A-supplied mode.

An executable **classical-query prefix Fourier-list algorithm** finds every Fourier frequency |hat f(z)|>=tau in polynomial (M,q,1/tau) time using only fresh classical-query runs of A. For prefix alpha in Fq^t define energy
    E_t(alpha)=sum_beta |hat f(alpha,beta)|^2
              =E_{y,x,x'}[ f(x,y)*f(x',y)*omega^(-<alpha,x-x'>) ].
Here y is a common uniform suffix; x,x' independent uniform prefixes; each f observation is a fresh Bernoulli QPT run. Estimate the real energy to additive tau^2/4 with O(tau^-4 log(Mq/tau)) pairs; enumerate q children of each retained prefix, keeping energies >=tau^2/2. Parseval bounds surviving prefixes by O(tau^-2) at every depth. With polynomial repetitions and concentration this outputs all heavy frequencies, in polynomial time with a large overhead, **without rewinding, A inverse, coherent oracle use, or a supplied representation**. For each list frequency z with z0!=0 normalize w*=z/z0 and check the ACTUAL ORIGINAL predicate R(G,w*). A c*w frequency in (3) yields precisely w. This proves, on GOOD planted G with classically simulatable auxiliary inputs and fresh nonuniform-QPT circuit access:
    any nonnegligible excess FINAL-K or native-forgery recovery
        -> actual ORIGINAL anchored binary witness w
        OR native QPT-EUF-CMA break;
    with optional real LWE masking: OR ordinary QPT-DecLWE break.
Polynomial extractor running time is not a concrete practical bound, especially for q=65537. This theorem is for a **restricted planted distribution**, not arbitrary hard-true NP x.

## Independently qualified false-source half

For uniformly random UNPLANTED rank-r G, replace the planted-subspace probability by (q^k-1)/(q^M-1), obtaining
    E_G sum_{z in kerG\{0}} |hat E(z)|^2
      =((q^k-1)/(q^M-1))*[(q/3)^M-1].
Thus overwhelmingly many uniform G produce a complete P_a statistically close to *uniform* (and hence to P_0), preserving genuine native pk, shares and independent-capsule correlations; a QPT EUF reduction handles final key/forgery after the statistical hybrid. Such a G is false for the anchored relation except with negligible probability. This is **average-case false security only**, not a theorem for arbitrary fixed/adversarial FALSE NP statements.

## Exact missing obligations

The planted-search assumption has NOT been independently QPT justified; the planted generator knows its w, which does NOT furnish a generic witness-free compiler for arbitrary ORIGINAL (R,x). No all-false-instance security, generic-NP hard-true reduction, unrestricted auxiliary/quantum-oracle/selective-opening simulation, malicious N-of-N honest-erasure/abort/graph proof, pre-funding signatures and evidence availability, Bitcoin headers/AuxPoW/tag/ancestor/fork/window authentication, or concrete 128-bit native no-EC-key-path SLH-like endpoint is established. A single honest watcher still needs timely admissible evidence and enforceable inclusion; no finite detection guarantee from tiny honest hash or safety under arbitrary BTC censorship. Nothing here deploys new opcodes or makes Bitcoin verify NP/proofs/PCPs. No iO/WE assumption has been renamed a proof.

Offline exact checker: verify.js was executed twice with byte-identical output (13 assertions), checking radix and asymptotic integer inequalities, exhaustive q=5 planted and unplanted subspace average spectral identities, and a finite prefix-Fourier-list recovery that receives only a success oracle, not a volunteered witness. Extended **local-only** Python checker additionally passed 3,454 assertions twice and retains full notes and outputs; that does not add a QPT hardness experiment. Keep research automation enabled; this is not a completed WKEM.
