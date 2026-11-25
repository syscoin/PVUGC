# Universal committed-view extension and fixed-response transport — 2026-11-25 UTC (NONQUALIFYING)

## Selection, provenance and scope

PR syscoin/PVUGC #1, existing branch research/pq-wkem-validation-20260918, open/draft/unmerged. Start and pre-write head 1e60eadf5526b4dd69ec4ecc7615e4f46729bd2d. Read metadata, recent substantive discussion through R225, exact head commit and SOURCE_HIDDEN_PERMUTATION_TRANSPORT_20261125.md (blob e2d8a30c94293ea2b049c4ac1c53e64d77cdb69a). This new path was checked absent (404). No external literature/web, Core source read or new Core claim, full PR diff, native signing, or execution of a checker. Static algebra and algorithms below. No group/lattice assumption.

Missing original-source operation: a single public capsule must use any qualifying original certificate to reconstruct a fixed hidden response, not merely obtain a valid response for that certificate. Try changing from independently obtainable garbled labels (R289 split-mask splice) to *one public MPC view and a globally consistent extension*, using a shared hash commitment to bind the hidden responses. The mathematical difference is that the extension reconstructs all local wire shares and gate masks jointly from one original witness; it does not grant independent labels. The fixed-commitment repair is intended to exclude occurrence switching by binding complete views. This trial gives an explicit input-independent first message and complete extension algorithm, then fails at fixed-response transport, not at local MPC correctness. It is not an implemented WE or a security proof. No repeat of low-degree private-coefficient, disjoint permutation marker, or source-pad parameter sweep.

## 1. Source and a concrete universal extension

Let R_x(w) be the bounded ORIGINAL verifier with all three OR grounds, claim relevance, authentication and coverage unchanged. Its full Boolean circuit is a formal input; not a claim to have compiled actual Core or LC. For a Build that wants an available accepting execution, form Q(w,u)=R_x(w) OR [H_trap(u)=h], where h=H_trap(t) for independent uniform t; the source branch is the original relation, and finding the auxiliary witness is a separate preimage problem. Pad inputs and use a fixed-length circuit with XOR, NOT, AND, public constants. The construction below also works directly on R and does not need t for its initial public view.

Use bit arithmetic over F2. Each wire z has shares z_0,z_1,z_2 with XOR z. For every AND gate c=ab choose gate-local masks r_0,r_1,r_2. Indices are cyclic modulo 3. Define

    c_i = a_i b_i + a_i b_(i+1) + a_(i+1) b_i + r_i + r_(i+1).

XOR of these three equations gives c=ab: the nine cross terms occur once, and every mask occurs twice. XOR gates are sharewise; NOT adds one to share 0 only. Each local view i contains wire shares at i and i+1, its adjacent gate masks, and its own checked output-share equations. Overlaps are required identical, not independent labels. This is simply replicated Boolean sharing; no ZK property is assumed (indeed two views expose all input shares). It is used as a concrete algebraic representation, not advertised as a private MPC protocol.

Algorithm PublicView(Circuit):
* For each input and constant wire independently sample shares 0,1. The constant's share 2 will be determined by its public value.
* Visit gates in topological order. For XOR and NOT compute shares 0,1 by the prescribed local rules.
* At AND, sample r_0,r_1 independently; compute c_0 by the i=0 equation; sample c_1 independently and uniformly.
* Publish P consisting of all wire shares 0,1 and all AND masks r_0,r_1, plus circuit and context. These are exactly the variables visible in view 0. Use fresh coins per capsule. No source input is needed for P.

Algorithm Extend(P,v), where v is a complete circuit input (in the OR construction v=(w,u)):
* Evaluate the actual circuit on v to obtain every wire value z.
* For every wire set z_2=z+z_0+z_1.
* For every AND set

    r_2 = c_1 + a_1 b_1 + a_1 b_2 + a_2 b_1 + r_1.       (1)

* Return the canonical complete views 1 and 2 using these shares and masks.

This is a deterministic classical polynomial-time public algorithm on a serialized P and original input. Proof: the i=0 AND equation holds by construction, i=1 by (1), and i=2 follows by adding the first two equations to the true global equation c=ab. All XOR/NOT and constant equations hold by share reconstruction. All overlap equalities hold identically. In particular every original w with R_x(w)=1 gives a fully coherent accepting Q execution (choose u=0, for example). It also gives a coherent *rejecting* execution for an input on which Q=0. No honest-code if-check is claimed to be a cryptographic release gate.

For any fixed input, P and Extend produce exactly the distribution of independent uniform input/constant shares 0,1 and independent uniform masks r_0,r_1,r_2 followed by the prescribed gates. To see this, condition on earlier gates and the fresh r_0,r_1. Equation (1) is a bijection between the sampled c_1 and the remaining mask r_2; this holds gate by gate in topological order. Thus the marginal P is independent of v, and the extension gives a valid complete execution under one shared P for every input. This is an exact distributional identity, not a QROM programmability or privacy claim.

The significance for the proposed repair is that a global consistent response can be reconstructed without a private evaluator, without mixing intermediate labels, and without witness-specific setup. But the reconstructed response is not the fixed hidden response needed for the bridge.

## 2. Actual capsule trial, then fixed-commitment repair

Choose t and h as above, v*= (fixed dummy source input,t), sample P. Compute V*=Extend(P,v*). Build fixes a frozen safe cancellation capability S and exact native VK/message, claim and capsule context ctx. Consider the explicit serialized trial

    K* = XOF("response-pad",ctx,canonical(V*),|S|)
    C  = (x,h,P,ctx,S XOR K*).

Open computes V=Extend(P,(w,0)) and unmasks using the same XOF on V. This does not return S for every qualifying original witness. In fact Extend is injective in the input for fixed P: V contains share 2 of every input, so v is recovered by XOR with P's two shares. Thus V != V* whenever the actual input differs from the dummy trapdoor input. Correctness would require a collision of the two response pads. In a random-oracle idealization with distinct canonical inputs and fixed independent coins, equality has probability 2^(-|S|); it is not a correctness mechanism. No claim about statistical behavior of concrete SHA is made. Even if one particular source witness happened to give the same input, every-witness correctness is missing.

A natural repair is to commit to the two full hidden views:

    D_i = H_com("view",ctx,i,salt_i,canonical(V*_i)), i=1,2.

Then require Open to reconstruct openings to the *fixed* D_i. This would defeat independently selected view components via commitment binding (the Open code's check alone is not sufficient to gate raw key recovery). But it destroys alternate-witness completeness: view 1 contains share 2 of every input, hence if v differs from v*, the canonical view differs. Even if the salts are made public or are deterministically recomputed, a successful opening of a different view to the fixed D_1 is a collision in the domain-separated commitment hash. This is a deterministic implication; an arbitrary QPT algorithm outputting that different opening yields the collision directly, no rewinding or query log. It is not a general impossibility for transport of the *same* hidden view by an original witness. That would be a different operation, and is not supplied by Extend.

Another repair is to commit only to the input-independent P and to the final output share under acceptance. Since Q(v)=1 for all accepting executions, its share 2 equals 1+out_0+out_1. This is indeed common, and its commitment can be formed before the source witness. It is also publicly computable with no source evidence. Any pad derived only from that common output and public context can be unmasked on FALSE original instances, regardless of how correctly the honest verifier runs. Adding the full output sharing or a salt made available to every evaluator does not alter this. A hidden salt would need the missing release mechanism itself.

## 3. Challenge-response transport variant (two-transcript route)

Try using the view commitments only as first messages in a proof, and deriving the frozen capability via a second challenge response rather than hashing the whole view. This is a change from independently obtainable labels: the intended extraction is straight-line on two globally bound transcripts, not a request for adversary-provided internal representations.

For a standard hash-commitment-based transcript, binding fixes each committed view across all challenges. If the setup generates one accepting execution under the auxiliary preimage t and commits to the full views, a response for an alternate original input cannot change any opened input share without a hash collision. The missing operation is to use the original w to reconstruct the same hidden committed opening from the t execution, not to produce its own accepting transcript. In this concrete replicated-share construction two revealed complete views actually reveal t when the committed execution is v*, so publishing two such views at Build is already a trapdoor disclosure; do not assume ZK or publish them. Publishing only P is safe as a distributional fact but gives no hidden t response. For a different MPC-in-head protocol that is ZK, the same distinction between matching full commitments and reusing only the initial randomness still applies; no generic ZK impossibility is asserted.

With commitment only to P (or fixed random tapes) and a second-stage commitment to the actual hidden views after choosing w, a new witness can have its own accepting response. But the fixed first-stage commitment no longer binds all hidden views across the two transcripts. If two honest transcripts use different inputs, their view-1 strings are different by the exact injectivity argument above. Any straight-line two-transcript extraction theorem requiring the same first message that binds those strings must use the *second* commitment as part of the first message. Equality of that commitment is precisely what is missing. This cannot be repaired by treating the two complete transcripts as openings of the same execution. Binding the second commitment to the capsule ID or source hash does not make it equal across different valid witnesses.

In general, suppose a two-challenge proof of knowledge for an independent hash preimage t has a public first message A and a valid fixed response z0 to challenge e0. If a public algorithm can simulate a valid response z1 at a different challenge e1 *conditioned on this same A*, without source input or t, and a special-soundness extractor is straight-line on those responses, then it can recover t without the source. Ordinary honest-verifier simulation does not promise that conditioned response; it normally samples a fresh A together with its response. Giving an original witness the ability to perform the conditioned simulation is the desired missing source-dependent transport, not a consequence of the simulator. No QPT proof-of-knowledge extraction, quantum rewinding or general WE construction follows from this observation.

## 4. Exact reduction of the remaining representation problem

For fixed public P, the maps v -> Extend(P,v) and V -> reconstruct input from share 2 and P are efficient deterministic inverses on the image. Thus any outer wrapper over this universal complete-view representation can be replaced, exactly, by an outer wrapper over the original v: Build samples P and uses the same private setup; public Open first computes Extend and then invokes the outer wrapper. Conversely any wrapper over v can reconstruct v from a complete view. For public adversaries, all published bytes, native VK/message, auxiliary data, and sibling capsules remain exactly the same; no simulation of quantum adversary state or proof-system extraction is involved. This is a representation equivalence, not a claim that all wrappers fail. The extension contributes no independently hidden source-dependent input from which a wrapper could obtain a common key.

Equation (1) also has the form

    r_2 = [c_1+a_1 b_1+r_1+a_1(b_0+b_1)+b_1(a_0+a_1)]
          + a_1 b + b_1 a,

with every bracketed coefficient and constant public. Thus each missing mask is affine in the actual gate input-wire values. Subtracting the public affine part to remove witness variation makes the residual public. A hidden weighted combination of these expressions is not a repair: that would re-enter the low-degree private-coefficient family already screened in R327, with the private public-evaluation problem unchanged. Do not repeat coefficient/rank fixtures. Hashing the complete varying response merely returns to the failed first trial. A nonlinear hidden projection that is constant on accepting inputs, computable publicly from any valid response but not from a fabricated one, needs its own explicit algorithm and proof.

Next search target: a genuinely source-dependent method for transporting a *fixed* hidden response/opening from different globally consistent accepting executions, rather than proving that each witness supplies some consistent response. Required equation, for every qualifying original w, is

    Transport(public capsule, Extend(P,(w,0))) = fixed safe S

with full-public FALSE hiding and arbitrary hard-TRUE recovery/native forgery implying an ORIGINAL certificate or independent justified QPT break. The representation equivalence makes clear that simply postulating Transport adds no progress. Avoid repeating fixed hash commitments, public-tape-only commitments, local response normalization or conditioned HVZK simulation without a concrete new mechanism. The exact serialized PublicView/Extend algorithms above do not supply Transport.

All original source/endpoint/network requirements remain in force, including R316 coverage correction, R225 slot-global or true activation-specific native message, all three OR grounds, no online issuer, one-honest erasure, malicious setup and multi-capsule/auxiliary security. No new Core claims, native signature generation, test execution, practical release or full-public theorem. NONQUALIFYING; no ordinary PR comment or user notification.
