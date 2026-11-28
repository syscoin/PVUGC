# Simulatable canonical-proof hash gate — ORIGINAL release screen (NONQUALIFYING)

## Continuity and exact target

One bounded offline attempt at the **proof-to-release operation**, different from the previous explicit public matrix/finite-cover families and full-certificate identity labels. At this execution start the open/draft PVUGC #1 branch `research/pq-wkem-validation-20260918` had head `256766b86a9b2fea84721b9aaa99ae32a9b77ce8`, tree `b7746bf0e2d7efc7590de388a27d7fcee53ad538`, and current note `research/pq-wkem/r_global_identity_label_screen_20261123/RESEARCH.md`, blob `460917f0d66a4f0cbed93774ff246bf3e502143d`. Also read the directly prior public weighted-automaton note, blob `37abc1718fbed8bef0cccbdb587cd4f6edaa020e`. Top-level PR comments since 2026-11-18 19:24 UTC returned none. No web, other-repository access, new Core test, actual source-certificate execution, or native signature implementation was used.

The source relation remains the **original qualified OR** of same-anchor strictly greater Bitcoin cumulative work; finite authenticated fault/refutation of this claim's burn authorization; or qualified relevant Syscoin incompatible histories/tag fault at LC depth. Its public x binds protocol/chain, exact claim/UTXO, assertion/burn/amount/recipient/reserve/replay, real baseline and anchors/window, relevant source height and maturity, deadline/reset, exact safe native cancellation message/VK and capsule ID. The active contextual post-PQ canonical tag and modern chain ID apply; different valid parent certificates for the same child do not themselves constitute a fork. This screen does not change the relation, introduce a private source signer, require the winning Syscoin branch, or require another notary to respond.

## Named candidate: a *canonical simulatable proof* as the hidden hash input

The motivating difference from `mu(w)=H(CanonicalSerialize(w))` is to try to make the secret hash input independent of which ORIGINAL witness arrives.

Suppose a CRS generator returns `(crs,tau)`, where the builder privately keeps a simulation trapdoor `tau`. Propose algorithms `Prove(crs,x,w;r)`, `Verify(crs,x,pi)`, and `Sim(tau,x)` with the unusually strong **convergence** property

    for ALL R_x(w)=1 and ALL admissible proving tapes r:
        Prove(crs,x,w;r) = pi_star(x,crs) = Sim(tau,x).

The builder can compute `pi_star` before seeing any future witness and define

    K = SHA256("PVUGC proof lock" || sid || pi_star);
    C = (crs, ct = sigma_cancel XOR K, exact public statement/manifest).

After erasing tau and pi_star, any ORIGINAL witness w would compute the same pi_star, and `Open(C,w)=ct XOR SHA256(domain||Prove(crs,x,w))` would return the identical frozen sigma_cancel. No common witness hash or canonical fork would be demanded. The ceremony would use independent per-participant capsules and native N-of-N signatures, with one honest participant protecting their simulation trapdoor/signing capability. This is an algebraically correct interface **IF** its canonical-proof primitive exists and its public distribution is secure; this run does not instantiate that primitive.

## Exact joint-public security attempt, and where it stops

For FALSE x, a simulator trapdoor could produce an accepting `pi_star` even though no actual w exists; the hash pad could conceal sigma if `pi_star` remains computationally hidden in the entire public transcript. The complete transcript includes crs, any correctness proof/manifest, all native VK/message correlations, sibling capsules, source commitments, and malicious participants' retained coins. Hash preimage resistance alone does not establish this correlated hidden-proof property. With coherent quantum hash queries, a quantum query-measurement argument would also require a separately justified simulator and extraction loss, not an ordinary classical query log.

For hard-TRUE x, the desired proof would convert unauthorized recovery of a native cancellation signature into obtaining pi_star and then into an **actual ORIGINAL** certificate w. This conversion is *not* supplied by normal proof soundness. In fact, a public extractor `Extract(crs,x,pi)` that returned an ORIGINAL witness for **every** accepted proof is incompatible with simulatable false proofs: pick FALSE x, compute pi_star=Sim(tau,x), Verify accepts, and public Extract would output a witness for a FALSE statement. Consequently any sound knowledge extractor must have a restricted adversarial/prover interface excluding tau (or another carefully proved non-black-box interface). A successful adversary's bare hash query pi_star does not, by itself, supply such an interface. A QPT extractor cannot be asserted by applying classical rewinding.

Thus the security equation is still unproved:

    Pr[unauthorized native cancellation from entire public C]
      <= loss * Pr[extract actual R_x(w)=1 ORIGINAL evidence]
         + independently justified hash/native/setup failure.

No instantiated source-specific oracle simulation, private-trapdoor erasure proof, quantum extraction, or concrete parameter/work loss exists. A generic assumption that some `Sim/Prove` has exactly the above convergence and hidden proof security would be another way of **assuming the missing release capability**, not an independently derived construction.

## Original-source convergence test (symbolic, no synthetic pass claim)

The initial repair to an ordinary witness-dependent succinct proof is `pi(w)=H(CanonicalSerialize(w))`. That repair fails: different qualified competing Bitcoin header chains, different valid Syscoin forks, and even different authenticated parent work certificates attached to the *same child* can have different serializations. Under hash collision resistance those are different pi. Honest every-witness opening then gives `sigma XOR H(pi_star) XOR H(pi(w))`, not sigma.

A Fiat–Shamir or ordinary randomized NIZK transcript generally also varies with prover randomness even for fixed w, breaking the required all-tapes equality. Fixing r deterministically does not make proofs for different valid w equal. Taking `H(crs||x)` as a common proof key makes it public and trivially reveals sigma. Selecting lexicographically first future fork/certificate would require unavailable global information, could take unbounded work, and violates the requirement that **any** qualifying ORIGINAL witness can immediately challenge.

The only proposed repair is therefore a new efficient, trapdoor-simulatable, **source-witness-independent canonical proof** primitive together with its original-witness extraction and full-public hiding theorem. No construction from SHA/AuxPoW, hash-based signatures or existing source data was obtained in this iteration. A purported `Can(x,w)` or special `FE.Prove` would just rename the unimplemented operation. Do NOT promote this conditional design into a solution or assume a hardware/online release authority.

## Disposition and next precise equation

**Reject as a practical candidate unless the canonical-proof primitive itself is instantiated independently for the ORIGINAL relation.** The mathematical change from witness-hash pads was specified and tested against source representation multiplicity and the required false-proof extraction model; it did not survive that gate. No code was executed because ordinary transcript-hash or public-x-key regressions apply immediately, and no functional crypto algorithm was built. Nothing here demonstrates a complete-public FALSE/hard-TRUE QPT scheme, malicious setup, or an ORIGINAL release breakthrough.

The indispensable next construction remains

    Build_inc(x_W,sigma_cancel;rho) -> serialized public C,
    Open_inc(C,w) = identical frozen safe native capability for EVERY R_x_W(w)=1,

with an independently instantiated joint-public simulator/recovery-to-an-ORIGINAL-certificate argument. Future work should not re-run a proof-hash salt/canonicalization variant without a concrete algorithm that overcomes the stated all-witness convergence and extraction requirements. No user progress notice, top-level PR comment, Core edit, production edit, or automation change is justified.
