# Direct native-seed repetition: exact false joint simulation and complete finite decoding

Research-only constructive checkpoint (2026-10-27 UTC). Record: direct-seed-repetition-20261027-automation4. Repo syscoin/PVUGC draft PR #1; parent ca41240b3ac6be598d587df5b62f9c2e29f529ae. Exact predecessor: research/pq-wkem/fourier_recovery_extraction_20261026/README.md, Git blob d68b015397f46caf30d579bff12220ad04e94d7c. No claim of practical generic-NP WKEM, LWE instantiation, deployed Bitcoin PQ endpoint, or PoW work hardness.

## Constructive release replacing the incomplete decoding interface

The predecessor hid a fresh random X of length L in Fourier columns and published a reconciliation helper W, a Toeplitz hash H, and a ciphertext T=K XOR H X. It left the finite-length reconciliation code uninstantiated. Here the actual native signing-seed bits K_i themselves become the hidden column shifts. An explicit odd repetition/majority decoder opens them. There is no secondary X, W, H, T, native-key tag, hash KDF or SOURCE-opening oracle. This trades potentially worse honest rate for a fully specified recovery algorithm and *exact* false-instance public-capsule simulation, without a leftover-hash error.

Take a public ORIGINAL deterministic Boolean verifier R_x(w), t witness input bits, with exact affine gates and g AND/NAND gates, and pin its acceptance. The fully bound statement x contains relation identity, claim/UTXO, branch, anchoring/window, actual authorization/burn/output and intended native verification key. Compile it to the predecessor's homogeneous GF(2) SOURCE matrix C_x with wire-bit one-hot coordinates, a constant coordinate v_0, four permitted assignment-label coordinates per nonlinear gate, incidence/normalization rows and exact affine rows. Every accepted ORIGINAL witness w produces its own normalized one-hot v_w in ker(C_x), with (v_w)_0=1; every such accepted source vector projects back to an ORIGINAL witness. Internal wire values need not be common across witnesses.

Let B be a public full row basis for ker(C_x), d=number of rows of B, and b=B e_0. Per release column independently draw gate-label error E: each four-label gate has probability 1/3 on 0000 and 1/6 on each of four singleton flips; all non-gate error coordinates are zero. Write P_z for the distribution of Q=B E+b z over GF(2)^d. The established *complete Fourier support law* for a normalized character a is

    Fourier(P_1)(a)-Fourier(P_0)(a) = -2 rho
        if a B equals a one-hot accepted ORIGINAL source;
      = 0 otherwise,
    rho=(2/3)^g.

This is the whole-column identity, not a selected-probe statement. A replacement correlated gate sampler with the same exact support identity and its own equal positive rho may be substituted, including qualified optimized star groups; that requires independent verification of its actual source convention.

Build: Generate uniform native seeded-key-generation randomness K in GF(2)^k and native pk(K). Generate the public ORIGINAL relation/source from (pk, public x/context), independently of private K except through available public pk; this permits binding to the specific intended native verification key. Select an ODD repetition count r independent of private error draws. For i=1..k and j=1..r, independently draw E_(i,j) and publish

    Q_(i,j)=B E_(i,j)+b K_i.

Publish V=(x, C_x/B or deterministic lossless description, pk(K), r, all Q_(i,j), allowed auxiliary data and scope context). Protect and erase K and all E after honest setup. This is not keyless Build, nor an N-of-N malicious-secure ceremony. An independent session key may be appended as additional uniform released bits; it need not derive from the native seed.

Recover(w): Verify the actual ORIGINAL R_x(w) off chain, compile its distinct one-hot SOURCE state v_w, solve alpha_w B=v_w^T publicly, and evaluate y_(i,j)=alpha_w Q_(i,j). Majority-decode each i across odd r observations to obtain Khat, optionally verify pk(Khat)=pk, and use the ordinary native signature only on the intended challenge path. Bitcoin does not run R_x, a VM or a proof verifier. The capability is bearer scoped to its transaction graph, not proof of designated ownership.

## Every ORIGINAL witness, same precommitted capability: explicit finite theorem

For every fixed valid w, each observation is y_(i,j)=K_i+(v_w)^T E_(i,j). For fixed i, the j-noises are independent BSC with correct probability (1+rho)/2; the marginal channel is IDENTICAL for every valid w. Correlation among different witnesses is permitted. Hoeffding gives for each w,i

    Pr[majority error] <= exp(-r rho^2/2).

If the deterministic verifier has t witness input bits, its number of distinct accepted inputs is N_x<=2^t. By a union bound over all accepted ORIGINAL witnesses and all k key bits,

    Pr_setup[there exists valid w,i with Dec_i(w)!=K_i]
       <= k N_x exp(-r rho^2/2)
       <= k 2^t exp(-r rho^2/2).

Choosing ODD integer r at least
    2*(t ln 2 + ln k + lambda ln 2)/rho^2
provides simultaneous recovery for every valid ORIGINAL witness with probability at least 1-2^(-lambda). This includes witnesses selected after seeing the public capsule; no canonical/common intermediate state is used. If a source has independent nondeterministic extensions, replace N_x by a bound on all accepted full source states. Build/Recover are classical polynomial time in emitted L=k*r and source size but r is exponential in generic g; **not classical PPT in circuit/security size for arbitrary NP**.

## Exact full-public false-instance secrecy and native reduction

For FALSE ORIGINAL x, there is no normalized witness Fourier mode and therefore P_0=P_1 as exact COMPLETE probability laws. Condition on actual K, pk(K), x/context and auxiliary classical or quantum information generated independently of the fresh secret E coins. Every Q_(i,j) then has law P_0 regardless of K_i, and all are independent conditional on the fixed public source and secret seed. The complete joint public release is EXACTLY simulated by receiving the actual native pk, reconstructing the public source, and sampling each Q independently from P_0, with no knowledge of K. This preserves arbitrary native pk(K) correlations: the capsule leaks **zero incremental information** on false x; pk alone need not conceal K information-theoretically. Equality survives arbitrary QPT coherent postprocessing and independent quantum advice.

A matching native seed one-wayness challenger, or native EUF-CMA challenger for a fresh signed message, can run that exact simulator and forward A's recovered seed or candidate signature unchanged. Legitimate pre-signatures and signing queries must be generated through the permitted native challenge interfaces. A transaction-graph bypass or replay of preauthorized signatures is not a new-message forgery. Source and context must be simulatable from native pk/public history; an x generated using undisclosed K beyond pk is outside the claim. False-related capsules with separately sampled E compose, even for a reused K, only until a TRUE same-key capsule opens; claim/path separation remains mandatory. Revealed challenge error coins, malicious source generation or target-correlated quantum setup advice are not protected.

## Coherent hard-true recovery-to-ORIGINAL extraction

Let s_x<=2^t be the number of accepted normalized SOURCE indices in the Fourier support. Let p_real be arbitrary QPT exact-native-seed recovery or accepted fresh native forgery probability on V. Let p_native be the success of an explicitly constructed native challenger adversary that receives the actual pk, samples the matching x/context and all columns from P_0 and forwards A's answer. Both quantities include declared correlated public auxiliary inputs and legitimate signing material, and the native challenger uses no undisclosed K.

Order the L=k*r columns. In hybrid H_j the first j columns use P_0, while later ones use their real P_(K_i), retaining the SAME public pk(K), actual bound source/context and all other columns. Conditional on all other components, changing one column makes zero difference if K_i=0, or if K_i=1 has success difference supported on ORIGINAL witness Fourier indices with coefficient -2 rho. The exact predecessor's *coherent circuit/inverse/success-phase reflection extractor*, applied to that selected column, returns a verified ORIGINAL witness with probability at least the squared conditional success gap divided by s_x rho^2. Averaging a uniformly selected hybrid, applying Jensen and telescoping yields

    eta=(p_real-p_native)_+
    p_ext >= eta^2/(L^2*s_x*rho^2)  if s_x>0,
    p_real <= p_native+L*rho*sqrt(s_x*p_ext).

For s_x=0 the distributions are identical and p_real=p_native in the matched experiment. Unlike the predecessor there is NO leftover-hash statistical error term epsilon_H. The extractor does not require the attacker to volunteer a SOURCE representation; it must have coherent code access to the attacker's circuit AND adjoint and one copy of allowed quantum advice, including a reversible winning-event check. Mere classical oracle access is not sufficient. No classical rewinding, QROM programming, or unproved LWE lift is invoked.

The theorem is resource-accounted, not a free hard-true security claim. A meaningful bound requires independent QPT witness-search hardness in the *same public history, auxiliary information, coherent code-access and extraction-budget model*, plus native QPT security. A true instance with an easy witness opens as intended. A fresh accepted native signature is covered by the winning-event reflection, subject to native scope and availability of a real signing-oracle simulator. The complete Bitcoin transaction graph and signed-preauthorization safety still need separate proof.

## Exact efficiency and limitations

The column payload is L*d=k*r*d bits (plus source/verification key/context), without public reconciliation/hash/pad fields. For independent local gates rho=(2/3)^g, r=Omega((9/4)^g*(t+lambda+log k)), still exponential; compared to a capacity-approaching polar code it may be LARGER, so do not claim general compression. The gain is an instantiated finite decoder, all-witness simultaneous correctness, and exact false-instance joint simulation without hidden-pad statistical assumptions. The recently optimized shared-input star sampler can improve rho on its qualified gate families, but the exponential group-count barrier remains. Neither bridge-specific work economics nor an actual Syscoin/Bitcoin light-client circuit was compiled or tested.

Not solved: polynomial-size generic-NP source-conditioned release, actual PoW work-bound/source correlation, N-of-N ceremony and malicious abort, future private coin retention, quantum selective opening, independent native PQ Bitcoin script availability, complete bridge path graph and censorship/DA/liveness. In particular no standard-QPT-LWE compiler from actual structured ORIGINAL statements has been constructed.

## Executed reproducible evidence

The published small pure-JavaScript checker builds actual homogeneous true and false one-NAND SOURCE kernels, enumerates the exact full P_0/P_1 laws, checks every Fourier mode, correct BSC bias, false full-2-bit native-pk-correlated transcript equality, odd-majority tail and its explicit bound, and a two-column real/native-null hybrid. The longer LOCAL-ONLY independent standard-library Python checker ran twice with identical output and 1,745 assertions, including mixed-affine, AND/NAND/two-gate true and false sources, rational Fourier/hybrid inequalities and finite majority tests. Those are finite mathematical checks, not cryptographic or Bitcoin implementation tests. The delivered archive preserves complete longer proof, Python source, captured validation and checksums.