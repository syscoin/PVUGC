# ICSO-2: independent related-capsule sharing with adaptive complete-lane opening

**Status:** genuine restricted release/composition repair and mathematical straight-line security reduction, not generic-NP witness-KEM or the missing ORIGINAL-witness reduction. Run: ICSO-2-2026-10-31-T13. Prior component NCSR at a95c70b7895f2ba1caf337fd7559dffc7114966f, exact blob d6f41f0ec9bb63c21f2931bd8af31d8a56750fa8; inspected QGL exact blob 3978a53fe6d40bb54850b53e4618cbd161e3ae2e.

## Construction change and reason

NCSR shared the same three XOR secret-core shares across two related capsules. Opening lanes (0,1) in capsule 0 and (1,2) in capsule 1 reveals all three distinct shares, and therefore the complete precommitted native signing core. Thus it required one globally protected lane number across all capsules, a real limitation on independent selective opening.

Fix: for each capsule c=0,1, independently sample U[c,0],U[c,1] uniformly from 256-bit strings; set U[c,2] = core(sk) XOR U[c,0] XOR U[c,1]. This shares the SAME native signing core independently for every capsule. Encrypt each lane's 19 packed 14-bit symbols under the SAME uniformly generated binary-ISIS source (A,t), with fresh independent ordinary LWE secret/error coins for every ciphertext. The genuine native KeyGen supplies (sk,vk); an SLH-like canonical signing-key format is conditionally Compose(core,vk), with the public vk fields not encrypted. The source (A,t) is uniform, not adversarially programmed or planted with a retained witness.

A valid binary SOURCE witness W satisfying AW=t decrypts each lane using rho=tau-W^T beta, nearest-decodes symbols, XORs three full lane strings and returns exactly the precommitted Compose(core,vk). Different valid W can retain distinct intermediate residuals; all successful decodings give the identical capability. Source distribution and 114 ciphertext vector count are unchanged from NCSR. The previous simultaneous all-valid-SOURCE-witness honest-setup decoding-error bound applies unchanged; correctness is overwhelming-probability, not deterministic per generated capsule. At earlier uncalibrated parameters, total ciphertext storage is 11,788,170 bytes plus a 52,940,800-byte public source matrix. No storage savings are claimed.

Full source/scope binding must include relation identity, ORIGINAL statement x, actual claim/UTXO, spending branch, anchors/window/context, intended native vk and signature domain. The entire public view is source A,t, relation/scope, both capsules, actual genuine native vk, allowed preauthorizations, auxiliary data and adaptive opening transcript. Honest setup/encoding/evaluation are classical PPT. The constructor must erase sensitive coins/secrets in the honest-erasure baseline; the stronger optional retained-builder-coins model is not solved.

## Exact adaptive leakage model

An arbitrary nonuniform QPT adversary may coherently process the full classical public view and adaptively issue classical opening queries. It may obtain **at most two different complete lanes per capsule**, disclosing the selected lane plaintext and all genuine encryption randomness for that lane. The unopenable lane number may DIFFER across capsules. Opening choices may depend on ciphertexts and earlier answers; there is no selective choice made in advance by the adversary. Quantum superposition opening queries, individual-bit openings, leaking target-lane commitments/coins and arbitrary secret-core-correlated auxiliary advice are outside the theorem.

For any fixed core k and any sets O_c with |O_c|<=2, the joint disclosed plaintext shares are uniform and independent of k. Proof: any at-most-two components of a three-share XOR decomposition are uniformly distributed regardless of k; fresh independent coins per capsule give a product distribution. The adaptive plaintext-only transcript inherits independence by induction, since no permitted new share closes all three shares in a capsule. This lemma alone does not imply encrypted selective-opening security.

## QPT full-public simulator and reduction, with exact correction for adaptive survival

For two capsules guess G=(g_0,g_1) uniformly from {0,1,2}^2, independently before creating any public output. In the simulated opening oracle, abort immediately if the adversary requests guessed lane g_c of capsule c. For the final completed transcript O=(O_0,O_1) let N(O)=(3-|O_0|)(3-|O_1|). If the adversary gives a genuinely fresh native challenge-path forgery, accept it with additional independent probability 1/N(O), but only if no guessed lane was opened.

For EVERY possible completed transcript, even with adversarial adaptive choices, exactly N(O) of the nine possible guesses survive, so

  sum_{G} 1[G_c notin O_c for all c]/N(O) = 1.

In the wholly genuine game (independent of secret G), this implies

  Pr[weighted guessed-lane reduction wins] = Pr[real adversary forges]/9.

This is straight-line inverse-survival weighting, not an incorrect conditioning on a high-probability guessed lane, classical rewinding or a SOURCE-opening oracle. The output weighting uses only a classical coin and applies to an arbitrary QPT adversary making classical opening/signing requests.

For each guessed G, replace all 19 ciphertext vectors of guessed lane g_0 in capsule 0 and all 19 of guessed lane g_1 in capsule 1, one vector at a time, with uniform vectors. To embed one ordinary decisional QPT-LWE challenge, receive uniform M in F_q^((n+1)xd) and y equal either M*s+e with EXACT intended independent bounded-error distribution or uniform. Interpret M's first n rows as A^T and last row as t^T, and add known packing term g*m to y's final coordinate in the real arm. All other source-dependent ciphertexts use the same M with independently known encryption coins. The reduction knows native sk in these LWE hybrids, and creates real native vk, real allowed signatures, exact scope and independently simulatable auxiliary data. It answers every opening of a non-guessed lane with its real plaintext/coins. It never needs the unknown challenge error coins, because guessed-lane opening causes abort.

After all 38 protected ciphertext vectors are uniform, the two non-guessed plaintext share lanes in EACH capsule have a joint independent uniform distribution even conditional on core(sk) and genuine vk. The terminal simulator can therefore use an independent genuine native QPT-EUF-CMA challenge vk and its CLASSICAL signing oracle for allowed nonchallenge preauthorizations. It samples the non-guessed shares, the corresponding real LWE ciphertexts and all their opening coins, and makes protected ciphertexts uniform. No secret core or simulated checking key is required. An accepted fresh native challenge signature violates that separately justified native EUF-CMA assumption. The same applies if adversary outputs a usable native signing key: sign a fresh challenge and submit that as the forgery. No internal representation is requested.

For L=ceil(256/14)=19 and C=2, assuming arbitrary nonuniform QPT *single-challenge* decisional LWE for this public-matrix/noise distribution and genuine native QPT-EUF-CMA with CLASSICAL signing queries,

  Pr_real[unauthorized native forgery] <= 9 * (sum_{i=1}^{38} Adv_LWE(B_i) + Adv_native_EUF(B_sig)).

All simulators are classical PPT with straight-line black-box QPT adversary access and polynomial simulation overhead for exactly two capsules. If one conditions the honestly random SOURCE on TRUE, divide this security bound by (1-delta), delta=Pr_uniform[A,t][no binary SOURCE witness], from the already established second-moment source bound. No conditioned LWE sampling or oracle is assumed. The complete auxiliary and checking-key simulation assumes any public item beyond genuine vk/signing transcripts is simulatable from source/scope and honest independent ceremony keys. **Secret-correlated auxiliary inputs are explicitly excluded**, not waved away.

For C related capsules, this direct guess strategy loses 3^C; the current claim is **C=2**, not unbounded polynomially many capsules. There is no full quantum signing or opening oracle, no classical-to-quantum rewinding lift, and no QPT-128 parameter calibration.

## Exact limitations, ORIGINAL use case and stopping condition

This result DOES NOT satisfy adversarial FALSE or hard-TRUE generic ORIGINAL security. The prior chosen FALSE A=[1],t=[3] and public nonbinary z=3 still recover the signing core with supported small errors; independently resharing capsules does not block that attack. NOR does this repair the CORN, NGCE, QGL affine-feature/interpolation attacks. The QGL carrier cannot be called secure while awaiting only a proof. The previous pivot-SL2-Frobenius-Schur certificate-conditional extraction theorem does not turn arbitrary key recovery into a representation. An internal representation is never presumed to be volunteered.

Exact missing requirement remains classical-PPT witness-free Comp(R_original,x,scope,vk) with, for every valid ORIGINAL witness W,

  R_original(x,W)=1  =>  Lift(Comp(...),W)=K_precommitted,

and an independently justified arbitrary-QPT **full-public** adversarial-FALSE and unauthorized hard-TRUE recovered-key/native-forgery reduction to an ACTUAL ORIGINAL witness or a distinct PQ break, not SourceOpen or an assumed same-capability oracle. Bitcoin must only verify an ordinary native signature on an intended path; general NP evidence and all expensive verification remain OFF CHAIN. RSEG/SCFB funding/abort/DA, one-honest N-of-N setup, source integrity/censorship qualification and hypothetical no-EC native PQ Bitcoin endpoint remain independent unfinished obligations. No deployed functionality is asserted.

## Reproducible bounded tests and provenance

The exact published checker.js is the executed pure-JavaScript checker function wrapped for Node.js. It exhaustively checks all 49 two-capsule opening patterns and all two-capsule one-bit XOR-sharing coins, exact independence of core=0 versus core=1, the adaptive plaintext-opening regression, the old shared-lane cross-capsule disclosure and inverse-guess normalization. Captured output.json has 157 assertions, zero failures. The separately executed **local-only** longer Python checker tested the full toy source-dependent LWE encrypt/decrypt and real CLASSICAL Ed25519 signing-key correlation for two distinct valid SOURCE witnesses and two related capsules, alongside the same 49-pattern identities, with 652 assertions twice and identical output. It used hand-picked tiny SOURCE data and cryptography 46.0.4; it was NOT a quantum attack, native PQ signature, Bitcoin consensus test or computational security experiment. Its full research notes/source/output are preserved in the supplied local offline archive. One initial local toy rounding assertion failed for a zero byte with negative modular error; the checker was corrected by nearest-symbol decoding modulo 256 before two complete passing runs.

Repo syscoin/PVUGC PR#1 start head a95c70b7895f2ba1caf337fd7559dffc7114966f, open/draft/unmerged, branch research/pq-wkem-validation-20260918. Only this research folder and an ordinary top-level PR comment were authorized for GitHub writes. No literature or unrelated web fetch, no production change, and no independent agent was used.
