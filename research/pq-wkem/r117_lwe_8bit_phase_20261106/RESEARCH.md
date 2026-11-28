# R117 — Exact conditional-moment proof for 8-bit LWE ciphertext phase packing

**Run:** R117-8BIT-LWE-PHASE-EXACT-COND-MGF-20261106.
**Continuity:** syscoin/PVUGC PR #1, draft/unmerged, branch research/pq-wkem-validation-20260918, starting SHA 86ae8255f4f6ceaf13097bb10f994a4528a54878. Exact predecessor R116 research blob 7b71d8b88816492a56a6f53e263bc8bc2f0d2975. Offline mathematical research only; GitHub only for authorized project continuity and research publication.

## Result, precise scope

A real constructive **restricted-source** ciphertext efficiency result: R116's 54,400 bytes per credential occurrence becomes **48,960 bytes (10.00% less)** by quantizing each public ciphertext phase from 16 bits to 8 bits. This preserves R116's authentic source-dependent key/opening law, exact bounded-L1 coin distribution, 85-group RS(85,79) code, qualifying CNF share policy, two genuine scalar-LWE pad blocks, one frozen presigned native capability, context and verification key. All underlying **ordinary scalar QPT-LWE/PKE and QPT-EUF-CMA native-signature security assumptions** remain unchanged. The conservative simultaneous 256-occurrence correctness bound changes from R116's 2^(-153.5094)+2^(-20502.54) to strictly below **2^(-147)+2^(-20502.54)**: negligible but not zero on all coin tapes. This is NOT an arbitrary ORIGINAL NP witness-KEM, NOT independently calibrated 128-bit QPT hardness and NOT a repair of R111/R112/R114's rejected generic sources.

## Full source, setup order and public-data distribution

Retain uniform A in F_q^(2000 x 256), q=65521. Honest capsule-local source keys are independently sampled S in F_q^(256 x 64) uniform and E in {-3,-2,-1,0,1,2,3}^(2000 x 64) uniform, then B=A S+E mod q. For every original **restricted LWE-credential** witness the source predicate checks the actual bounded (S',E') satisfying B=A S'+E'. A qualifying CNF policy requires a valid credential for every clause; distinct qualifying paths reconstruct the same XOR-shared secret T. Malicious B may depend on all A and honest B, and arbitrary nonuniform QPT quantum advice, but is selected before the independent encryption coins. Adversaries may use arbitrarily coherent joint QPT processing of all public information, classical permitted selective openings and multiple related capsules.

Preserve R115/R116's genuine source-dependent data: one common challenge-bound native signature sigma frozen under the intended native VK for a message binding relation identity, claim/UTXO, branch, anchors/window, N-of-N graph, challenge path and context. The secret T encodes two actual independent ordinary scalar-LWE secret/error pairs (s_h,e_h). Their outputs b_h=A s_h+e_h mask sigma once; T is split by uniform XOR shares across all CNF clauses. The capsule publishes all honest/malicious B, the exact quantized ciphertexts, native VK, masked signature, claim/context, manifest J, public checking key CK, auxiliary records and related capsules. All checking/auxiliary outputs must be simulatable deterministic public processing of the actual quantized challenge transcript plus independent known coins; no secret-dependent receipt, hidden signature digest in CK, private witness hint or SourceOpen oracle. Protected target-cut honest source secrets and challenge encryption coins are NOT selectively opened.

## Concrete classical PPT release algorithm

For every clause share, maintain R116's systematic RS(85,79) over GF(256): 79 true 32-byte data groups, six algebraic parity groups, 32 byte lanes; distance 7 corrects any three erroneous whole groups. Each group has 64 four-bit symbols mu_j in {0,...,15}. Draw an independent r uniformly from D={r in [-3,3]^2000: ||r||_1<=2729}, with R113's exact combinatorial sampler. Compute u=A^T r mod q and 64 full phases v_j=(B_j^T r+4095*mu_j) mod q. Publish u as 256 canonical 16-bit field elements (512 bytes), and for each canonical integer phase v_j in [0,65520] publish only its single byte c_j=floor(v_j/256), in [0,255]. **This is public deterministic rounding, not reuse of coins or source-secret-based compression.** Each group is exactly 512+64=576 bytes, versus R116's 512+128=640 bytes; 85 groups =48,960 bytes versus54,400. All A/B source keys and the once-per-capsule masked signature remain unchanged; 10% is ciphertext-only saving, not a claim about total key/transcript size. At 16 capsules and 16 occurrences per capsule, ciphertext saving is exactly 1,392,640 bytes.

Off-chain Open checks a supplied actual restricted credential (S',E'), reconstructs v'_j=(256*c_j+128) mod q, computes z_j=v'_j-S'_j^T u mod q, decodes the nearest among 4095*mu mod q on the circle, performs the real RS(85,79) bounded-distance decoder for each 32-byte lane, rejects invalid padding/uncorrectable groups, XOR-reconstructs T from qualifying clause shares, generates the same two scalar-LWE pad outputs and recovers the exact precommitted sigma, then verifies it under the challenge-bound native VK. This releases a public off-chain native signature. Bitcoin verifies only its native challenge transaction/signature; it does not execute the original NP relation, a VM, PCP, proof or BitVM trace dispute.

## Rigorous correctness: actual uniform bounded-L1 coin law, not a Gaussian model

For each canonical v, delta=(256*floor(v/256)+128)-v lies in [-127,128], including the final partial bin. The 16 codepoints 4095*mu mod65521 have minimum circular distance 4095. For any true source secret, after subtraction the effective error is e_j^T r+delta. Thus |e_j^T r|<=1919 implies |e_j^T r+delta|<=2047<4095/2, and a nibble error necessarily requires |e_j^T r|>=1920. The source error e_j can be adversarially fixed anywhere in [-3,3]^2000 BEFORE r, and all 64 symbol errors in a group may be correlated because they share r.

A tighter **exact conditional** exponential-moment calculation eliminates the acceptance-probability loss in R116's earlier tilted upper bound. For uniform r from D, independent uniformly symmetric signs conditional on the absolute coin values imply for every fixed bounded e and lambda>=0:

    E_r[exp(lambda * e^T r)] <= N(lambda)/D0,

    D0 = sum_{k=0}^{2729} [z^k](1+2z+2z^2+2z^3)^2000,

    N(lambda) = sum_{k=0}^{2729} [z^k]
       (1+sum_{a=1}^3 (exp(3*a*lambda)+exp(-3*a*lambda)) z^a)^2000.

The inequality follows termwise because cosh(lambda*a*|e_i|)<=cosh(3*lambda*a), including arbitrary signs/zero coordinates; it is uniform in the entire adversarial error column. Two-sided Markov/symmetry gives

    Pr_r[|e^T r|>=1920] <= 2 exp(-1920*lambda) N(lambda)/D0.

Take exp(3*lambda)=P/R=28/25, so exp(-1920*lambda)=(25/28)^640. Define Z=(P*R)^3=700^3 and integer polynomial coefficients H_0=Z, H_a=(P^(2a)+R^(2a))*(P*R)^(3-a) for a=1,2,3. Set NUM=sum_{k=0}^{2729}[z^k](H_0+H_1*z+H_2*z^2+H_3*z^3)^2000. Then N(lambda)=NUM/Z^2000, and the strict inequality p_symbol<2^(-50) is certified by the **exact integer inequality**

    2^51 * 25^640 * NUM < 28^640 * (700^3)^2000 * D0.

The committed Python 3 standard-library checker computes the two integer coefficient sums with the descending recurrence c_(i+1,k)=sum_(a=0)^3 H_a*c_(i,k-a), truncating at the ACTUAL L1 bound 2729. It compares these two enormous integers directly, not via floating-point logs, Monte Carlo, approximate Gaussian bounds, hardness estimates, or reliance on a simulator. D0 has 5,446 bits; the scaled numerator NUM has 62,206 bits. The captured output contains independent SHA-256 commitments to both integer encodings.

For any one RS group, p_group<=64*p_symbol<2^(-44), by union bound, without treating the shared 64-lane errors as independent. For each complete 85-group occurrence, independently sampled r values across GROUPS give

    p_occ <= choose(85,4)*(2^(-44))^4,

because RS distance 7 requires at least FOUR whole groups to be wrong. Across all 16x16=256 occurrences,

    p_any < 256*choose(85,4)*2^(-176) < 2^(-147),

and 256*choose(85,4)=518,344,960<2^29 is checked exactly.

The remaining global uniqueness event is inherited from R116: for uniform A, ANY B (even malicious chosen after honest B) has at most one bounded source representation per column except with probability at most (q^256-1)*(13/q)^2000<2^(-20502.54). Hence on the complement of that event no post-ciphertext alternate valid source error column can be picked to exploit coins; the simultaneous union bound covers any adaptively chosen valid restricted witness/path. No quantum extraction assumption is made here; this is an unconditional classical setup/coin event.

## Full-public arbitrary-QPT security reduction inheritance

The new ciphertext is the explicitly deterministic PUBLIC map f(u,v)=(u, floor(canon_q(v)/256)). Suppose a nonuniform arbitrary-QPT algorithm distinguishes complete compressed public challenge distributions including relation, statement, authentic/malicious B, checking keys, context, auxiliary data, related capsules, permitted classical corruption/opening history and retained quantum advice. An uncompressed-ciphertext adversary implements the compressed view by applying the same public map f to every ciphertext, and recomputes all public J/CK/Aux from THOSE compressed bytes. Thus any QPT distinguishing advantage against the compressed scheme transfers with no additional cryptographic assumption to the R116 restricted full-public genuine-LWE-PKE column hybrid and its subsequent two genuine scalar decisional-LWE pad hybrids and separate native QPT-EUF-CMA target-message forgery reduction. It does NOT assume a SourceOpen oracle, classical rewinding, generic-group oracles or independent PRG, iO or WE security. All allowed disclosed off-target keys/coins remain generated as actual known coins; protected-cut challenge key openings and target signing queries are excluded, as in R116. The adversary may be fully quantum/coherent but classical disclosures are fixed by this selective-opening experiment. Wrongly copying CK hashes computed from full uncompressed ciphertext would break the required joint transcript law and is explicitly prohibited.

This inherits only the restricted source model with independent honest source keys, honest-cut CNF policy and enumerably chosen cut, and known simulatable public auxiliary fields. Native QPT security and LWE parameters are NOT calibrated to an actual 128-bit attack cost. This deterministic compression does not improve general NP source soundness and does not solve malicious N-of-N ceremony/abort or arbitrary adaptive corruption of target honest cuts.

## ORIGINAL reduction remains explicitly missing

No classical-PPT arbitrary-ORIGINAL-NP compiler Comp(R_original,x) has been produced that constructs genuine source-dependent LWE setup/opening data and a challenge simulator of their complete public correlations while satisfying Open(Comp(R_original,x),w)=the SAME frozen native capability for EVERY valid ORIGINAL witness w. No reduction from arbitrary unauthorized QPT recovery or native forgery to an actual ORIGINAL witness or an independently justified PQ break, without requiring the adversary to supply its representation, has been proved. Generic FALSE full-public security is separately required. The R111/R112 false-source near-key attacks and R114 public Boolean-quotient extraction remain exact regression failures, NOT repaired by this ciphertext encoding. No canonical/common witness, common short preimage, local literal switching, arbitrary public polynomial mask or disguised WE/iO source assumption is introduced.

N-of-N preauthorization still needs one honest participant to exclude bypass paths and erase/protect secrets; pre-signatures, graph safety, data availability and verification before irreversible funding, challenge-credential scope, useful abort/completeness, one-of-N watcher liveness and enforceable timely admissible evidence are separate unproved composition obligations. For SYS/BTC witness data the original verifier must still bind actual headers, AuxPoW, authenticated coinbase tags and every relevant interval, proper ancestor/height/direction/lag/window rules and fork/reorg/censorship assumptions; parent work does not equal BTC best-chain membership. ChainLocks optional; no guarantee under arbitrary BTC censorship. The contemplated no-EC-path P2MR-like output and native SLH-like signatures are conditional, not deployed. No CAT, adaptor algebra, general Bitcoin proof verifier or online release committee is presumed.

## Executed reproducibility and provenance

The published checker.py is the **actual** Python 3 standard-library checker executed offline. It passed **253,915 assertions**, including independent exhaustive small-domain polynomial enumeration, the full exact integer Chernoff certificate, all 65,521 possible canonical phase bins, all 16 code points for error range [-1919,1919] with both worst perturbations, exact union bound and all size arithmetic. The accompanying captured.json is verbatim output of that corrected execution. A first local run failed on a mundane OLD-ciphertext byte-accounting assertion: it used 2*d+ell instead of 2*d+2*ell; this was corrected before the successful execution and publication. No quantum hardness is measured or proved by the checker. The earlier R116 actual GF(256) RS decoder, complete public-reduction assumptions and global-uniqueness proof are reused by exact-version reference, not silently substituted. No independent agent or external research was invoked.
