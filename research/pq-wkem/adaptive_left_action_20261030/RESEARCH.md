# Adaptive invertible-left SOURCE: restricted joint-LWE transport, not an ORIGINAL-witness repair

**Classification: no positive generic-NP witness-KEM advance.** This preserves the existing honestly uniform dual-LWE SOURCE component under a restricted adaptive, malicious public row action. A public basis change is **not** a fix for malicious SOURCE creation, ORIGINAL-witness recovery, or unknown-one-honest shared-SOURCE generation.

## Exact provenance

Execution: automation turn 10, no separate UUID supplied. Repository syscoin/PVUGC; existing PR #1 open/draft/unmerged; branch research/pq-wkem-validation-20260918; starting verified head 7ee380eff2e9e50df0f187174afab2ca5bc65b80. Latest substantive ordinary comment read: 6518084607. Exact-version predecessor reads: receiver_indexed_coinflip_rejected_20261030/RESEARCH.md blob 7ee8cd45df8a0257715dab98b94a9fe08a1616c4 and uniform_target_batched_lwe_20261030/RESEARCH.md blob d1bc72cf6b2692ee73783d086931014917631859. No entire diff, archives sweep or external literature research.

## Classical setup and exact full-public distribution

Let q be an odd prime, n,m,L,J polynomial, d=m+L, and chi a classical-PPT integer error distribution with absolute bound B. Honest SetupSource chooses H=[A|U] uniform over F_q^(n by d), without generating or retaining a SOURCE opening. A genuine native signature pair (sk*,pk*) is independently generated. Public metadata binds the original relation and statement, claim/UTXO, branch, anchors/window, path, signing-key/capability identity, related-capsule IDs and authorization mode.

Before any honest ciphertext coins are sampled, a QPT malicious coalition, possibly retaining quantum state, sees H, genuine pk*, prior classical transcript and permitted public auxiliaries, and outputs a **classical** T in GL_n(F_q) as an adaptive function of these inputs. Reject singular or noncanonical T before accepting setup or funding. Publish the full (H,T,M=TH), not merely M. For each related capsule j, sample independent r_j uniform in F_q^n and eta_j from chi^d, then publish

    y_j=(TH)^T*r_j+eta_j+Delta(sk*) modulo q,

where Delta is zero over the first m coordinates and equals g times the corresponding complete native-key digits over L target coordinates. The authentic native pk*, setup-domain signatures and claim scope are unchanged. No challenge-path signing oracle is allowed.

**Exact reparameterization theorem:** Conditional on H,T and the coalition's pre-capsule quantum memory, T is public and invertible, while r_j is uniformly sampled afterwards. The map r_j -> r'_j=T^T*r_j is a bijection of F_q^n. Consequently

    (TH)^T*r_j+eta_j = H^T*r'_j+eta_j

as **identically distributed complete vectors**, including cross-coordinate correlations, per-digit shifts and J independent related capsules. The QPT DecLWE challenger provides a uniformly random H and one real-or-uniform vector y. The reduction runs the malicious coalition to learn T, publishes TH and the **unchanged** y, and generates the genuine signing-key/capsule correlations. It neither knows the challenge secret r nor invokes SourceOpen, nor quantum rewinding. In the uniform challenger branch, any fixed native-key digit shift leaves y uniform. All subsequent classically interfaced quantum postprocessing and legitimately simulated setup signatures preserve the hybrid indistinguishability.

For J fresh full-length ciphertext vectors a sequential hybrid costs at most J times the **ordinary QPT decisional-LWE advantage on exactly the uniform H, uniform r and chi errors above**. In the final all-uniform game, the reduction can use the actual native EUF-CMA checking key and legitimate classical setup-domain signature oracle. An accepted fresh target signature, or a usable recovered signing key used to make such a signature, is a native forgery. The conditional bound is

    Pr[unauthorized native signature or usable secret]
      <= J Adv_QPT-DecLWE + Adv_QPT-native-EUF-CMA
         + Adv_QPT-authenticator-forgery,

with an N-factor when guessing an unknown honest surviving signing slot. Nonuniform QPT advice must be independent of fresh H/r/eta/sk. There is no challenge-path signing, superposition oracle, decryption oracle, source-opening oracle, post-funding authority, challenge-secret-dependent auxiliary string or correlated retained honest secret; the same honest slot survives across all J capsules and all corrupt contributions are only modeled through permitted classical interfaces. Malicious auxiliary authenticators that cannot be simulated are excluded. These assumptions are independently named, not proven or concretely calibrated here; no security is asserted for arbitrary fixed FALSE SOURCE matrices.

**All-witness SAME-key correctness, restricted SOURCE only:** For every z, including any malformed or unbounded pseudo-opening, (TA)z=TU iff Az=U because T is invertible. Thus T preserves the entire short SOURCE-opening set exactly, does not introduce extra openings, and does not erase pre-existing bad openings. For each valid signed constant-weight z_l in the predecessor's T_w set, decryption gives

    d_{j,l} - z_l^T*c_j = g*a_l + eta_{j,m+l} - z_l^T*eta_{j,1:m}.

With |eta|<=B and signed weight w, the error magnitude is <=B(w+1). Strict g>2B(w+1) yields deterministic nearest-center recovery of the SAME native-key digit for every valid SOURCE opening and every related capsule.

## Explicit boundary and negative control

If T is singular (especially T=0), SOURCE M can collapse to the zero matrix and a publicly known short opening exists, bypassing witness gating. If the adversary generated H itself and retained a SOURCE opening, invertible T cannot remove it. If corrupt parties add an arbitrary matrix S to H instead, ordinary (H,H^T*r+eta) cannot be transformed into (H+S,(H+S)^T*r+eta) without the unknown S^T*r; the displayed exact simulator does not cover additive coin-flip cancellation. Thus this theorem **does not repair** the rejected receiver-indexed malicious-CRS ceremony, does not instantiate any unknown-one-honest shared SOURCE, and does not give a valid ORIGINAL Syscoin W any short SOURCE opening.

## Reproducible bounded evidence

Exact executed standard-library check.py, SHA-256 552dac801d808d7082433aa1f99479f7aca434db0257d50943b7ae9c8c4b93f5, passed 300 assertions in each of two byte-identical executions. For 72 deterministically sampled q=7,n=2,d=3 matrices and T chosen adaptively from H, it exhaustively compared the complete ciphertext-vector histograms over 7^2*3^3=1323 choices of r and eta, including key-digit shifts. It also tested two distinct legal signed SOURCE openings releasing identical digits in two fresh capsules under a nontrivial invertible T at q=97, and a singular-T bypass control. OUTPUT.json records those counts. Toy distributions and mocks are not QPT-hardness experiments or a native PQ signature implementation. Exact extended local research derivation and publication provenance are archived separately.

## Unchanged indispensable ORIGINAL equation

Need a witness-free classical-PPT Comp(R_original,x,claim/UTXO,branch,anchors/window,context,pk*) -> D and public off-chain Release(D,W)=sk* for **every** valid ORIGINAL W, all yielding the same precommitted native capability; FALSE-fixed full-public QPT secrecy over statement/capsule/checking key/context/auxiliary/related capsules; and any hard-TRUE unauthorized key recovery or native forgery -> an actual ORIGINAL witness or independently justified QPT break. The release compiler and source-dependent joint simulator must be instantiated together, without adversary-volunteered representations or SourceOpen. Also unproved are malicious any-one-honest N-of-N graph/funding/abort completeness, SYS/BTC authenticated fork-window evidence and the hypothetical PQ-native Bitcoin endpoint. No completion, merge, deployment or automation-disable claim.
