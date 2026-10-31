# Native-key-correlated setup attestation: full-public restricted LWE SOURCE simulator

Status: **restricted honest-erasure composition advance only.** It does NOT instantiate arbitrary-ORIGINAL-NP WKEM, publicly prove SOURCE validity, establish malicious N-of-N ceremony, or solve recovery-to-ORIGINAL-witness. All mathematics and checks in this iteration were offline; Github is used solely to preserve research on the authorized existing draft PR.

Provenance: syscoin/PVUGC PR #1, research/pq-wkem-validation-20260918, starting head 01cb89bdf1eef350477ad0e2bae91f2f8ff33529 (open/draft/unmerged). Exact predecessor research/pq-wkem/source_cert_joint_20261029/RESEARCH.md, Git blob 9369cc118188bb92be4d8b39d7a6d8449e3db51b; restricted adaptive SOURCE note research/pq-wkem/adaptive_cohort_lwe_20261029/RESEARCH.md, blob 1e46d73185d1e54a3543af2d44a002021b8e77e2. Latest substantive ordinary comment read: 6508151890. No whole-PR diff or unrelated/external research.

## Construction: authenticate complete SOURCE/capsule output with the *same genuine native key*

The prior impossibility applies to public, QPT-sound SOURCE-membership certificates: ordinary decisional LWE cannot replace a certified TRUE SOURCE by a mostly FALSE uniform SOURCE while preserving an accepting public proof under the SAME sound checking key. An authenticating signature is weaker: it certifies a native key holder signed this exact public statement, NOT that the SOURCE has a short preimage. For an explicitly honest-erasure setup, this weaker check can be instantiated and included in the full-joint LWE challenge and native-signature simulation. That exact same-native-key setup-signature correlation was missing from the preceding conditional statement about independent authenticators.

Parameters: security lambda, odd prime q, polynomial n,m,N,J,L, bounded error distribution chi with |e_i|<=B. Honest SOURCE: A uniform in F_q^(n x m); s uniform in F_q^n; e sampled from chi^m; b=A^T s+e mod q; H=[A;b^T]. Independently run genuine native KeyGen to obtain (pk,sk). Encode the COMPLETE serialized signing capability sk as base-8 digits a_l, checking final padding. For each l, choose N-1 uniform independent q-ary additive shares and choose the last as a_l minus their sum mod q. An honest dealer has sk before funding, authenticates the setup and erases sk and retained complete shares/coins afterwards; this is NOT the optional keyless-Build model. Contributors obtain their own shares privately.

For each j in 1..J related same-claim/path capsules, l in 1..L and contributor i in 1..N, sample independent r_(j,i,l) uniformly from T={r in {-1,0,+1}^m: ||r||_0=w}, with |T|=binom(m,w)2^w. Set g=floor(q/8). Publish complete individual contributor encryption:

    u_(j,i,l) = A r_(j,i,l) mod q
    v_(j,i,l) = b^T r_(j,i,l) + g z_(i,l) mod q.

The independent assembler sums u and v per digit without access to sk. The public record D includes protocol/version, ORIGINAL relation identity and x, claim/UTXO, branch, anchors, window/context, intended verification and challenge path, real pk, H and parameters, all individual and aggregate ciphertexts, contributor identifiers, the J same-scope capsule identifiers, and all permitted public auxiliary data. It is canonically serialized, with length-delimited fields and no ambiguous encodings. **Do not publish secret share or SOURCE-witness commitments without a separate simulation proof.**

The honest dealer computes a genuine same-key signature on the WHOLE exact canonical message, not a truncated public hash:

    M_setup = "PVUGC/SETUP-ATTEST/1" || CanonicalEncode(D)
    sigma = Native.Sign_sk(M_setup)
    Native.Verify_pk(M_setup,sigma) = 1.

M_setup must be syntactically disjoint from every admissible on-chain native challenge sighash; the target challenge message must be fresh and never signed. A concrete scheme may hash M_setup internally as part of its independent QPT-EUF-CMA assumption. The entire pre-funded J-capsule collection is signed at once; arbitrary new capsules after sk erasure are excluded. The native signature is an off-chain setup-authentication record and does not replace the Bitcoin native challenge-path signature, a SOURCE-membership proof, or a graph authorization.

For any bounded restricted SOURCE witness (s',e') with b=A^T s'+e' mod q and |e'_k|<=B, Release computes on each aggregate:

    d_l = v_l - s'^T u_l
        = g*a_l + e'^T sum_i r_(j,i,l) mod q.

When g>2NwB and the smallest circular gap between the eight centers is at least g, nearest-center decoding yields a_l for ALL valid SOURCE witnesses and all honestly sampled coins. Every valid restricted SOURCE witness thus obtains the SAME precommitted usable sk, can locally confirm it against genuine pk, and can sign the intended challenge off-chain. This is a SOURCE correctness theorem, NOT the missing map from every valid ORIGINAL W.

## Complete-public QPT theorem with native-key-correlated public attestation

Adversary: arbitrary nonuniform QPT, independent quantum advice, coherent processing of classical public transcripts, classical signing queries excluding target M_ch, and adaptive corruption of up to N-1 globally distinct contributors across the entire related-capsule collection. Corrupt(i) returns that contributor's q-ary shares for all digits, all J sets of encryption coins and any independently sampled authenticator secrets; it must reproduce public ciphertexts. Auxiliary data may depend on public H, pk, x, context and permitted corrupted openings plus independent randomness, but cannot carry hidden SOURCE s,e, native sk, protected contributor information, or secret-correlated quantum advice. No SOURCE-open oracle, quantum superposition signing/corruption, or public sound NP certificate is assumed. Native signature keys are scoped to one claim/path; there is no cross-scope key reuse.

Independently assumed against nonuniform arbitrary QPT: (1) ordinary decisional LWE for the EXACT H source distribution (q,n,m,chi), (2) native classical-interface EUF-CMA including one or more legitimate pre-funding nonchallenge signatures. Perfect setup erasure and honest SOURCE sampling are preconditions; no QPT hardness calibration follows from the tiny checker.

Define Win as unauthorized usable-sk recovery or accepted fresh native signature on an unqueried target. Win_h = Win AND participant h is never corrupted globally. The events cover Win because at most N-1 contributors are corrupted; apply the survivor union AFTER one global LWE game switch.

G0 to G1: replace H=(A,A^T s+e) by independently uniform H. The standard ordinary decisional-LWE challenger supplies H; the distinguisher INDEPENDENTLY runs genuine native KeyGen, generates all q-ary shares, contributor ciphertexts, D, and the real setup signature sigma=Sign_sk(M_setup(D)), and answers any permitted adaptive corruption/nonchallenge signing queries. All these are efficient classical transformations of H and independently sampled hidden sk/shares/coins, so the full-joint advantage costs at most Adv_QPT-DecLWE. No proof of SOURCE existence is attached.

G1 to G2(h): in uniform H, replace only h's J*L complete ciphertexts by encryptions of zero. For the complete (n+1)-coordinate public output H*r with r uniform on T, distinct r != r' yield different vectors mod q; universal linear hashing gives average statistical distance

    delta_T = (1/2) sqrt((q^(n+1)-1)/|T|)

from uniform. Changing encryption of fixed z_h into encryption of zero costs <=2 delta_T for each independently sampled protected r, hence <=2 J L delta_T by hybrid/product triangle even with shared uniform H. Conditional on sk, genuine pk, all other shares and coins, the same bound applies. In EACH hybrid, recompute the entire D and same-native-key real sigma on its new ciphertext data; signing is a channel applied to a random transcript, so statistical trace distance cannot increase. Adaptive classical corruptions and permitted auxiliary processing likewise cannot increase trace distance. Stop h-specific simulation if h becomes corrupted (Win_h then false). No rewinding is needed.

G2(h) to native EUF-CMA: get the REAL pk and classical nonchallenge signing oracle from the native challenger, and never receive sk. Locally sample uniform H. Choose N-1 uniform shares for all i != h and honestly encrypt those; use zero encryptions for h. Any N-1 additive shares are exactly uniform independently of native sk and pk. Construct full public D and **query the REAL native signing oracle on M_setup(D)** to obtain an accepting same-pk setup attestation, with no fake checking key or sk. Forward subsequent permitted nonchallenge signing queries and corrupt-opening responses for i != h. A usable recovered sk signs a fresh unqueried challenge and yields native EUF-CMA forgery; a fresh accepted target signature is already a forgery. The adversary is never asked to volunteer a representation or SOURCE opening.

Thus, for this RESTRICTED honestly TRUE-LWE SOURCE and permitted full-public interface,

    Pr[Win] <= Adv_QPT-DecLWE
             + N (2 J L delta_T + Adv_QPT-native-EUF-CMA).

The factor N is explicit. This is not a bound for fixed FALSE ORIGINAL instances, secret-dependent auxiliary leakage, malicious N-of-N source generation, or a generic NP source compiler. Quantum coherent postprocessing is covered by the QPT assumptions and trace-distance monotonicity, not by an automatic lift of a classical extractor.

## Negative control: signature does not establish SOURCE membership

The exact executable functional checker deliberately constructs false source A=0, b containing 1, B=0. No (s,e) satisfies b=A^T s+e, but the same native signing oracle authenticates the complete false statement. Signature verification succeeds. This proves that a signed assertion must NOT be called a proof of valid LWE preimage or malicious-setup soundness. To obtain that property under N-of-N malicious setup still requires a separately instantiated sound and simulatable proof/ceremony; the preceding source-certificate obstruction is not bypassed by pretending a signature proves its own truth.

## Bounded offline execution and limitations

The exact stand-alone Node checker check.js was executed twice with byte-identical OUTPUT_JS.json. It passed 2,846 assertions: 2 distinct restricted toy SOURCE preimages, 2 related capsules, 768 complete contributor ciphertexts, all 3 globally N-1-corrupted cohorts' complete opening equations, real full-secret recovery under both preimages, real same-private-key setup signature over the entire joint public record, a native signing-oracle interface, six tamper-rejection cases, a fresh challenge signature after release, and the false-SOURCE negative control. An independent extended offline Python checker passed 4,933 assertions twice identically with a genuine cryptographic signing-key correlation and multiple whole-secret recoveries.

Both checkers use Ed25519 as a NON-POST-QUANTUM functional signing mock, a tiny deliberately structured source, and no Bitcoin endpoint. They are NOT tests of quantum hardness, standard-LWE parameter validity, malicious setup, SLH native signatures, or real native-Bitcoin consensus. The independent extended research derivation and checker are preserved in the local downloadable archive.

## Exact remaining ORIGINAL-witness reduction (unsolved)

Need a classical PPT W-free compiler Comp(R_original,x,claim,context,pk) and classical PPT Lift(x,W) such that, for EVERY valid ORIGINAL witness W,

    R_original(x,W)=1  =>
    Lift(x,W)=(s_W,e_W), b=A^T s_W+e_W (mod q),
    ||e_W||_infty<=B, Release(D,s_W,e_W)=sk_star,

where sk_star is the SAME precommitted capability for all W. The compiler and source-dependent LWE challenge simulator must be instantiated TOGETHER. Every fixed FALSE ORIGINAL statement must have complete-public QPT hiding, and arbitrary unauthorized hard-TRUE final-sk recovery or native forgery must lead to an ACTUAL ORIGINAL witness or independently justified QPT break. No SourceOpen oracle, adversary-supplied representation, canonical/common witness, scalar LWE wrapper, signer's self-assertion, or independent uninstantiated witness-encryption assumption is allowed. Malicious N-of-N graph/erasure/abort, SYS/BTC SOURCE qualification and conditional no-EC PQ-native Bitcoin verification remain unresolved. Do not deploy, merge to production, claim solved, or disable the research automation.
