# Direct LWE-preimage SOURCE: joint non-oracle release and QPT reduction (RESTRICTED)

## Research scope and provenance

Offline continuation of open/draft/unmerged \`syscoin/PVUGC\` PR #1 on \`research/pq-wkem-validation-20260918\`, starting SHA \`52e21162ea22f540a7412443599fd66f1e0c092f\`. Read current PR metadata, latest relevant ordinary comment \`6501671294\`, exact-head \`signed_public_decoder_20261029/RESEARCH.md\` (blob \`045c506085bd6f74faa252c580d24eb2672aadc9\`) and \`factor_local_torsion_source_20261029/RESEARCH.md\` (blob \`d43f20656b4dd21bb9a192ba1fca092ce8c434f9\`). No web search, literature, entire PR diff, unrelated repository, historical archive sweep or independent agent.

**Constructive but restricted:** The previously broken factor-local general-3CNF SOURCE used a public linear pseudo-opening. Here SOURCE itself is an *ordinary LWE public-key preimage relation* and the genuine native secret is directly encrypted. Build has no SOURCE witness and the ordinary QPT-LWE challenge simulator is instantiated together with it. There is a complete explicit true-source native-key recovery/forgery reduction without any adversary-supplied representation. This is NOT a compiler from arbitrary ORIGINAL NP, does NOT give every-fixed-FALSE security, and cannot secure the generic SYS/BTC claim. The cryptographic foundation is ordinary Regev-style LWE encryption, not a new WE/iO or ideal primitive.

## Source distribution, relation and concrete classical algorithms

Take integer \`q>=4\`, dimensions \`n,m=poly(lambda)\`, bounded efficiently sampled error distribution \`chi\` supported on \`[-B,B]\`, \`g=floor(q/2)\`, and require \`q>4mB+2\`.

The SOURCE-specific NP relation is

    R_LWE((A,b),(s,e))=1 iff
       A in Z_q^(n*m), b in Z_q^m, s in Z_q^n,
       e in [-B,B]^m and b=A^T s+e (mod q).

**TRUE sampler:** \`A <- U(Z_q^(n*m)), s <- U(Z_q^n), e <- chi^m, b=A^T s+e\`. It outputs public \`x=(A,b)\`; its sampled witness \`(s,e)\` is not passed to Build. **Uniform/FALSE sampler:** \`A,b\` independently uniform, without any planted witness. Build accepts arbitrary *fixed* public SOURCE instances but only these specified distributions have a security theorem.

Generate the *actual* native signature pair \`(sk_N,pk_N)\`, encoding its complete usable secret \`sk_N\` into \`L\` bits. Bind relation identity, source, claim/UTXO, intended challenge path, branch, anchor/window/context and the exact \`pk_N\` in canonical domain-separated capsule metadata. Each secret bit \`a\` is encrypted with independent \`r<-U({0,1}^m)\`:

    (u,v)=(A r, b^T r+g*a) (mod q).

Full public view consists of the ORIGINAL statement label (restricted here to R_LWE), x, all L complete (u,v), actual checking key pk_N, all public context/capsule/auxiliary data and related capsules. Neither an internal SOURCE secret, a SourceOpen oracle, a planted original witness, nor a keyless Build is assumed. Build DOES know native sk_N and honest setup must erase/protect it, so optional keyless Build and malicious N-of-N setup remain unsolved.

**Off-chain Release:** With *any* valid (s,e), compute

    v-s^T u = g*a+e^T r (mod q),  |e^T r|<=mB.

Since \`q>4mB+2\`, nearest cyclic decoding to 0 or g recovers every bit deterministically. Thus **every valid R_LWE witness**, including distinct source preimages, recovers exactly the SAME precommitted full native sk_N. Check the actual pk_N and sign the intended challenge path using an ordinary native signature. The verifier on Bitcoin does NOT execute this SOURCE NP verifier; a no-EC/PQ-native path remains hypothetical.

## Full-joint QPT reduction (genuine checking-key correlation)

Independent assumptions: **QPT decisional LWE** for *this exact uniform-s, chi, q,n,m distribution* and **QPT native EUF-CMA** with classical signing queries. Neither concrete 128-bit hardness nor full SLH-native deployment is asserted. Adversaries are arbitrary (including nonuniform) QPT processing the complete *classical* public output coherently, with independent quantum advice and polynomial-size public/simulatable auxiliary data. No random-oracle extraction, quantum rewinding, generic-group/model assumption or attacker-provided SOURCE representation.

One predeclared target claim has native sk_N unknown to the final native reduction. Other related claims may share x=(A,b) or have independently/publicly derived source data, provided every other claim has a **fresh independent native key**, fresh encryption coins, and data generatable without target source secret or target native sk_N. Adaptive full **non-target** native-key and encryption-coin openings and classical target signing queries on nonchallenge paths are permitted. Leakage of *target* ciphertext coins/secret bits, a target SOURCE witness, a related claim reusing the *same native sk_N*, hidden secret-correlated auxiliary quantum registers, or fully malicious setup are NOT covered. Revealing another capsule's SOURCE witness for the shared target source would itself authorize the target, so such exposure is excluded; independent other-source witnesses may be disclosed when not target-correlated. An adaptive target choice among J keys costs at most a standard J guessing/union factor; the theorem below predeclares one target.

**Actual reduction access:** With an ordinary LWE challenge public (A,b), the source/capsule simulator samples an ordinary native keypair and ALL related public data, outputs real encryptions of known native key bits or encryptions of zero, and prepares checking-key, context and aux correlations. It never invokes SourceOpen. In the native reduction, the simulator is given *only* the actual native challenger pk_N and its classical signing oracle; it samples the public source and all other independent native claims itself and encrypts ZERO for target bits. Thus the final game is reproducible without the challenged native sk_N.

## Explicit statistical lemma and hybrids

For uniform \`H=[A;b^T] in Z_q^((n+1)*m)\` and uniform binary \`r\`, \`r!=r'\` has a difference with some coordinate +1 or -1, which is invertible even for composite q. Consequently \`H(r-r')\` is exactly uniform: the binary-input hash family \`r -> H r\` is pairwise universal. Direct second moment and Cauchy-Schwarz give the averaged whole-ciphertext statistical distance

    Delta = E_H SD( H*U({0,1}^m), U(Z_q^(n+1)) )
          <= (1/2) sqrt( (q^(n+1)-1)/2^m ).          (1)

For fixed H each encrypted bit translates the last coordinate by \`g*a\`, so by triangle inequality \`L\` independently randomized target ciphertexts of real native bits versus zeros have **average** distance at most \`2L Delta\`. This is a whole-(u,v)-distribution bound, not a marginal pad argument. It remains true under arbitrary QPT postprocessing and public/simulatable auxiliaries with no dependence on the target r or sk beyond pk and classical signing queries. Equation (1) is averaged over random H, **not** a per-fixed-FALSE certificate.

Use four straight-line QPT games:

- **G0:** real TRUE-LWE source; genuine native sk_N encrypted; actual correlated pk_N; independent-key related capsules and permitted openings.
- **G1:** exchange the entire (A,b) LWE public source for uniform H and generate every other source-dependent output faithfully; cost at most one ordinary QPT decisional-LWE advantage.
- **G2:** for this uniform H, replace **only target** encrypted native-key bits by encryptions of zero, preserving the true checking key, public metadata, all other native claims, their disclosed coins and allowed signatures. Cost at most \`2L Delta\` by (1).
- **G3:** replace uniform H back by TRUE-LWE public source, keeping **target-zero** ciphertexts. Cost one more ordinary QPT-LWE advantage. This entire G3 public output is directly simulatable from genuine native challenge pk_N, with unknown target sk_N, by the native reduction.

If a QPT adversary outputs usable target sk_N it produces a fresh authorized challenge-path signature; if it outputs a valid fresh native forgery it already breaks EUF-CMA. Therefore for this **honestly TRUE-LWE-sampled** SOURCE, a predeclared target and classical signing-oracle freshness,

    Pr[unauthorized final native-key recovery OR fresh forgery]
       <= 2 Adv_QPT_DecLWE + 2L Delta + Adv_QPT_native_EUF-CMA.  (2)

This is a reduction for *arbitrary adversary external output*, not a supplied short preimage or representation. The source/lattice simulator and the LWE challenger are instantiated jointly. It covers other independent-key capsules even if they are TRUE and their **native** keys are disclosed, but NOT reuse of the target native key, disclosure of target-source witnesses, target ciphertext-coin openings, malicious builder retention or arbitrary K-correlated auxiliary information.

For uniformly sampled H, the probability that it accidentally has **any** valid short-error R_LWE witness obeys the union bound

    Pr_uniform[exists valid (s,e)] <= q^n ((2B+1)/q)^m.      (3)

Combined with (1), this yields **average** full-public bit-hiding for uniformly sampled *typically FALSE* sources. It does NOT yield hiding for **every fixed FALSE** instance; a maliciously chosen fixed H can be far from the averaged distribution. Conditioning the uniform draw on FALSE costs a factor of at most 1/(1-bound(3)). This source-restriction is material, not a looseness in parameters.

## Exact executed offline checks and resources

The exact committed standalone Node \`check.js\` passed **101 assertions in each of two byte-identical runs**, with output in \`OUTPUT.json\`. Independently, an extended **LOCAL-ONLY** Python standard-library checker \`check.py\` passed **167 assertions in each of two byte-identical runs**. The latter derived genuine SHA256/SHAKE256 Lamport one-time checking keys from two independently generated 256-bit native-capability seeds, encrypted every seed bit, verified nine *different* valid SOURCE witnesses recover precisely the same seed, and signed and checked the intended off-chain challenge message; this is **not** an implemented native SLH Bitcoin endpoint or an EUF-CMA-QPT certification.

Both checkers tested full \`(u,v)\` equations, source witness validity, complete two-claim capability recovery, and source FALSE instances. The committed checker exactly enumerated all 2^16 binary encryption randomness strings for 12 uniform tiny sources \`q=17,n=1,m=16\`: their observed average whole-ciphertext TV was 0.0181147785473, below the **averaged** upper bound 0.0331456303681, and all twelve sources were FALSE with zero accepted zero-error witness. The independent Python checker obtained 0.0195683058020 average (different deterministic samples), with one individual fixed source at 0.0599835141720, expressly illustrating that the averaged bound cannot be asserted for each fixed FALSE input. A sampled \`q=257,n=2,m=18,B=1\` uniform SOURCE was exhaustively checked against all \`257^2\` possible s and had zero valid witnesses.

Illustrative *noncertified* \`q=2^24,n=256,m=6600,B=256,L=256\`: all-witness correctness holds, \`log2 Delta=-217\`, \`log2(2L Delta)=-208\`, bound (3) is about \`2^-92837.42\`. These numbers establish only statistical and correctness terms; the exact error/LWE instance has **not** been independently validated for 128-bit QPT hardness. Dense A requires 5,068,800 raw bytes and 256 complete native-secret-bit ciphertexts 197,376 raw bytes, excluding pk, b and framing. All large evidence remains OFF CHAIN. There is no QPT cryptanalysis or deployment test.

## Unsolved ORIGINAL requirement and exact next equation

**The direct-LWE SOURCE is not arbitrary NP-WKEM.** Its SOURCE is already a (possibly hard) LWE secret-preimage relation. A required generic classical PPT compiler \`Comp(R_orig,x,claim,ctx,pk_N)->(A_x,b_x)\` remains unknown, with a public witness map \`Phi_x(W_orig)=(s,e)\` obeying *for every valid ORIGINAL W*:

    R_orig(x,W)=1 => A_x^T s + e = b_x mod q, ||e||_infty<=B,
                      Release(Phi_x(W)) = the SAME bound native sk_N.   (4)

The compiler must NOT know/plant W, the reduction must simulate **all** source/capsule/checking-key/auxiliary/related-capsule correlations without a challenge secret, **every fixed FALSE** x must be secure, and arbitrary hard-TRUE final native-key recovery or forgery must yield an actual ORIGINAL witness or an independently justified QPT break without attacker-supplied representation. Ordinary NP-completeness of bounded-error inversion does not supply the distribution/security-preserving compiler (4). The previous factor-local SOURCE is concretely broken by a public signed decoder. This missing compiler/reduction and malicious N-of-N preauthorization, abort/funding/DA, SYS/BTC AuxPoW/header/coinbase/interval/ancestor/fork validation, and hypothetical PQ-only no-EC Bitcoin endpoint remain unsolved. No deployment or automation stop is warranted.
