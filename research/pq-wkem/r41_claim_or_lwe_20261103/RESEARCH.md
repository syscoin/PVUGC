# R41 — CLAIM-OR-LWE-SAME-CAPABILITY (2026-11-03, offline)

**A restricted constructive composition, NOT generic-NP PQ witness-KEM or recovery-to-ORIGINAL SYS/BTC witness.** Continues R40 at exact verified start head 63ef4af34c8fe90a1ada1f493f813e1629a127ed of syscoin/PVUGC PR #1. Read current PR metadata, recent substantive comments and only R39/R40 RESEARCH.md from exact starting SHA. No external literature/web consulted.

## Actual constructive delta

R40 independently generated source public keys and K per separate claim/path, proving disclosure of non-target witnesses did not expose a target. It did not meet the SAME-capability requirement for **different valid OR branches of a single claim**. R41 uses independently generated Regev public keys **per branch** but one shared K, one pre-signature and one DEM D **per claim**; different claims retain independent keys and sources. This instantiates a real OR-of-LWE-secret NP relation (not general arbitrary NP, and not Bitcoin/Syscoin ORIGINAL evidence). It proves every valid branch witness opens identical precommitted capability, and composes the resulting target with R40's non-target-claim source-witness openings.

## Exact classical release and public view

Let C,J_c,kappa,n,m be polynomial in λ, q an odd prime, χ supported on [-B,B], Δ=(q−1)/2, and mB<Δ/2. Independently for each claim c and branch j: A_cj←U(Z_q^{n×m}), s_cj←U(Z_q^n), e_cj←χ^m, b_cj=A_cj^T s_cj+e_cj mod q. Publish pk_cj=(A_cj,b_cj). The **restricted** NP claim relation is:

 R_c({pk_cj}_j,(j,s',e')) := [valid branch j AND b_cj=A_cj^T s'+e' mod q AND ||e'||∞≤B].

Generate native (sk_N,vk_N), assuming independent multi-use QPT-EUF-CMA security. For every claim, bind a distinct fully fixed message m_c=M(domain, relation ID, all its pk_cj, claim/UTXO, intended challenge path/branch, anchors/window/context, vk_N); privately pre-sign σ_c=Sign(sk_N,m_c) before irreversible funding. Signer messages may depend on vk_N and all source pk, but must be distinct for distinct claims and have fully known native sighash semantics. Independently K_c←U({0,1}^κ) **once per claim**; compute D_c=encode(σ_c) XOR G(K_c;domain,c,context) with an independently QPT-secure PRG and canonical native signature length L.

For every bit b, branch j and scope a, sample a fresh independent r_cjba←U({0,1}^m). Publish Regev (u_cjba,v_cjba)=(A_cj r_cjba, b_cj^T r_cjba+Δ K_c[b]) mod q. Every j/a encrypts SAME K_c; no r reuse. Distinct claims have independent source keys and independent K. Full public V includes relations, all pk and capsules, vk_N, all m_c, all D, canonical claim/UTXO/anchors/window/context, checking key CK and auxiliary data. CK and aux must be efficiently **reproducible from public fields/independent coins** (or disclosed non-target records); independent secret-correlated CK, target private source witness, target K, target σ, native sk advice, malicious setup leakage and target selective opening are EXCLUDED. In particular CK=H(public transcript) is merely publicly computable, not a new binding/soundness theorem.

Public OffChainOpen(c,j,s',e') validates restricted R_c, reconstructs each K_c[b] by decoding v−s'^T u nearest 0 or Δ, and obtains σ_c=D_c XOR G(K_c). Off chain check Verify(vk_N,m_c,σ_c). Only native signature is expected on the CONDITIONAL no-EC-key-path P2MR-like Bitcoin endpoint; Bitcoin never executes the original NP verifier/VM or trace dispute.

## Every-valid-witness SAME-capability proof

For ANY valid (j,s',e') of the restricted OR relation, even distinct from honest generated s_cj, and ANY r:

 v_cjba−s'^T u_cjba = e'^T r_cjba+Δ K_c[b] (mod q).

Because |e'^T r|≤mB<Δ/2, nearest-center decoding deterministically recovers every K_c[b]. This holds for every valid witness in every branch simultaneously, including adaptively chosen witnesses and different internal states; all obtain the SAME σ_c. It requires neither a SourceOpen oracle nor a canonical witness.

## Exact full-joint QPT fixed-target claim theorem

Choose target **claim** t before setup (not target branch). Open(c) for c≠t discloses every honest source secret (s_cj,e_cj), K_c,σ_c; Open(t)=⊥ for **all** its branches. All records can be simulated by the reduction and may be addressed by adaptive/coherent reversible table queries. The adversary can apply arbitrary QPT coherent processing, with nonuniform classical/quantum advice independent of setup-private target secrets and reproducible public auxiliary inputs. It does not receive a target-source witness, any target private opening, adaptive target selection, or secret-correlated public CK.

Let J=J_t, T=sum_j T_tj, and δ=½√(q^{n+1}/2^m). Assume exact-distribution QPT decisional-LWE for each independently honestly generated (A_cj,b_cj), QPT PRG security of G, and multi-use QPT-EUF-CMA native signatures on a never signed target message. Hybridize **each target branch** ciphertext collection from shared K_t bits to encryptions of zero, while preserving the same K_t in other target branches and ONE D_t; simulate other branch pk, non-target source witnesses/openings and native signatures honestly. For challenged branch j, the LWE→uniform-pk→LWE sandwich and strong leftover hashing of h_(A,b)(r)=(Ar,b^T r), with independent binary r, give

 |Pr[win H_j(real)]−Pr[win H_j(zero)]| ≤ 2 Adv_QPT-DLWE+2 T_tj δ.

All pk-dependent m_t, σ_t, CK, aux and related ciphertext correlations are re-generated as functions of the branch challenge pk in BOTH hybrids. The simulator knows K_t while executing the ciphertext hybrids and locally signs m_t, so correlated ciphertexts of *other* target branches are not an oracle. Strong leftover is average over uniform pk, NOT a per-key bound; deterministic derivation of CK/aux and coherent QPT postprocessing cannot amplify classical TV. Across all J target branches:

 |Pr[win real]−Pr[win zero-all]|≤2J Adv_QPT-DLWE+2Tδ.

With all target bits encrypted as zero, K_t is exposed only through D_t. Replacing G(K_t) with independent uniform L-byte bits costs Adv_QPT-PRG and makes D_t uniform even conditional on native vk and original σ_t. A straight-line native EUF-CMA simulator receives vk_N, generates all target pk and zero capsules without target sources, asks its signing oracle only for distinct non-target claim messages, produces their exact disclosed witness records, K and σ, sets target D_t uniformly and re-generates all CK/aux and the coherent non-target opening table. It makes **zero** target signing queries and invokes QPT attacker once, no rewinding and no requested internal representation. Therefore

 Pr_QPT[any accepted native signature on target m_t]
 ≤ Adv_QPT-EUF(native) + Adv_QPT-PRG(G)
   + 2J Adv_QPT-DLWE(n,m,q,χ) + 2Tδ.

Any algorithm producing exact K_t is converted *straight-line* into an accepted-target-signature algorithm by D_t XOR G(K_t), obeying the same bound. Independently justified QPT assumptions are explicitly required; this is not an assumption that all ORIGINAL valid witnesses can magically release a hidden value. Statistical budget 2Tδ≤2^(−λ) is sufficient if m≥(n+1)log2(q)+2λ+2log2(T), along with mB<Δ/2. **Neither inequality alone establishes actual LWE hardness/128-bit parameters.** Honest algorithms classical PPT for polynomial sizes. Public Regev cost Θ(T(n+1)log q) bits; new branches cost additional ciphertexts but NOT additional per-claim K, D or native pre-signature.

## Correct scope and exact missing reduction

The "witness" here is (j,s,e) for the OR of honest LWE secrets, **not genuine ORIGINAL SYS/BTC evidence**. One secret s_j bypasses any separate original burn/fork verifier that is merely ANDed to R_c. R39's adversarial FALSE A=0 example remains; the theorem is restricted to honest hard-TRUE LWE-source pk. Target-branch selective opening destroys SAME-capability target secrecy by design. No adaptive-target security, arbitrary false-instance full-output security, malformed setup, malicious N-of-N ceremony/aborts, untrusted-secret CK, complete graph safety, practical crypto parameters or deployed native Bitcoin PQ endpoint is claimed.

Next indispensable construction: Compile(actual arbitrary ORIGINAL statement x) from x alone into public release such that **every** valid actual w opens same K, no independently obtainable surrogate secret bypasses R(x,w), and arbitrary unauthorized QPT accepted native forgery/recovered K from complete (x,capsule,CK,vk,context,aux,related) implies ACTUAL ORIGINAL witness or an independently justified PQ break. This is unproved.

## Reproduction/provenance

CHECKER.js is the exact function executed twice in offline V8 before publication, with repeat-identical OUTPUT.json. The small algebraic toy uses q=257,n=2,m=12,B=1, Δ=128,kappa=16,two scopes, three claims, target OR of three branches, two non-target claims of two branches each. It exercises SAME K and σ across target branches and source-witness openings of two non-target claims, and negative controls for target branch opening and aliased source pk. Its deterministic xorshift generator, toy RSA over 3233 and toy PRG have NO QPT security. Executed code and captured output prove only arithmetic/syntax; the stated theorem is a mathematical conditional QPT reduction. An independently executed local Node checker with richer SHA256 toy fixture and longer 12KB RESEARCH.md exists only in the offline archive; not claimed byte-identical to this V8 checker.