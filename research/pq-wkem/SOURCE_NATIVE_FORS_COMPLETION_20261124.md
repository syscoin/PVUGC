# 2026-11-24 — Native FORS incomplete-signature carrier (NONQUALIFYING)

## Continuity and selection

Actual PR #1 at start: syscoin/PVUGC, open/draft/unmerged, branch research/pq-wkem-validation-20260918, head 467c8bd086e621e9ad3e7e51a34e8e172ad1240c. Read metadata, latest substantive comments (through R225), exact-head SOURCE_MPC_VIEW_WITNESS_SWITCH_20261124.md (e9a825706cdc3ce3f3e7ad1b79e8585b86f889be). Its fixed-view and late-bound transcript failures stand. No new Core source claim, web or literature, no whole-PR diff.

Missing ORIGINAL operation: compile a capsule for an arbitrary future qualified certificate, such that every one produces the SAME frozen cancellation signature and unauthorized recovery or native forgery implies qualifying ORIGINAL evidence or an independent justified hash/native break. This iteration changes the *placement* of the cryptographic condition: rather than translate source-dependent labels into a hidden PRF seed, test whether an incomplete native hash-based signature can directly carry the source obligation. The native verification itself would test the missing hash preimage; no honest-code check after secret recovery. In particular this avoids the fixed-view switch premise and intermediate garbled-label mixing entirely for the isolated carrier. The question is whether the actual source relation supplies the native preimage for every witness, not whether a verifier can be implemented. Work is analytical and conditional on the stated SLH-like native verifier, not a claim about deployed Bitcoin.

## 1. Actual partial-signature generator

Use the conventional FORS + WOTS + hypertree verification structure of an SLH-like hash signature. This is a structural description, not a new signature specification or a claim of compliance with a particular deployed parameter set. Let n be the native hash-output length in bytes, P the public seed, A an address in the selected FORS tree, F(P,A,z) the leaf hashing function on an n-byte secret z, and T(P,A',left,right) the addressed tree compression. The higher-layer WOTS and Merkle verification is unchanged. Context, exact native message M, and verification key VK are fixed, and the capability may authorize only safe cancellation. All the original source relevance, network, maturity and activation-scope conditions are still part of R_x(w), not part of the native signature algorithm.

The hypertree public root is generated from the WOTS/hypertree signing seed, independently of FORS leaf secrets: FORS roots are signed as messages by the bottom-layer WOTS key. This permits an incomplete signature with a chosen *leaf digest* even when its preimage is not known, without a root/message/digest circularity. Explicit candidate:

    PartialBuild(M, choose_digest):
        generate the ordinary independent public seed P and hypertree seeds
        compute public hypertree root and VK
        sample a signature randomizer R0
        derive FORS indices and hypertree address from H_msg(R0,VK,M)
        choose one selected FORS leaf coordinate A
        y = choose_digest(P,A)
        for the selected FORS forest:
            generate the ordinary leaf secrets at all other coordinates
            substitute y for F(P,A,z) at precisely coordinate A
            compute the tree roots and selected authentication paths
        compress FORS roots to its public key
        sign that public key and higher roots with the ordinary WOTS/hypertree keys
        serialize signature with exactly the n-byte z field omitted
        return VK,R0,A,y,partial_signature

    Complete(C,z):
        insert z at the specified missing field; return the native signature

All operations except choose_digest are the standard finite signing/tree operations with one leaf substitution. With fixed native parameters the complexity is the ordinary hypertree/FORS work; for asymptotic parameters it is polynomial only if the ordinary leaf/tree generation costs are polynomial. No exponential enumeration of ORIGINAL witnesses. No native signature key is required by Complete. If F(P,A,z)=y, the selected tree root is exactly the one computed by PartialBuild, every other tree root matches, and all the fixed higher-layer signatures verify. This is a real algebraic correctness path for a *single fixed preimage condition*. The selected missing secret need not have existed in Build's memory. It is not an honest native Sign distribution in general, and PartialBuild is not Build_inc(x_W,sigma_cancel) for a supplied full signature.

For a pre-existing full signature sigma_cancel with a known z*, the simpler variant is to keep every byte except z*, publish y=F(P,A,z*), and use the same Complete. This meets the frozen-signature byte requirement if z=z*, but selecting a digest from a future certificate is then impossible without the missing source translation.

## 2. Joint fixed-hole simulation and its exact scope

Here is a useful property of this construction, distinct from treating native verification as a proof of release. In an ideal addressed random-oracle model, after P,A are determined, sample a uniform secret z* independently of all other leaf secrets and setup coins, and set y=F(P,A,z*). The full public partial signature (including VK,M,R0,A,y, all other signature fields and auth paths) can be generated from P,A,y and the independent signing coins, WITHOUT knowing z*. At the selected coordinate all subsequent computations depend on z* only through y. This is equality of the actual deterministic downstream computations, not merely a match of individual marginal distributions. A simulator for the partial view runs exactly those computations with y supplied by its preimage experiment. The experiment must specify the challenge at the chosen P,A; it is not a reduction from an arbitrary external SHA challenge with a different input format. Address/domain separation prevents another honest leaf query from being an evaluation at that selected coordinate. The simulator does not program a concrete SHA function.

For an adversary filling only the fixed field, the reduction reads the returned n-byte z directly (no volunteered representation or query log). If F(P,A,z)=y, it solves the addressed preimage problem. Otherwise the native verifier, following the fixed auth paths, has to merge the two distinct node computations at some higher compression, or change the FORS PK and nevertheless return the same hypertree root. If all other bytes are fixed, an explicit collision can be extracted at the first merging hash node by evaluating both traces: if different FORS PKs are mapped to identical WOTS reconstructed keys, compare the addressed chain computations, taking care that different chain starts can give a forward continuation rather than a collision. Thus the simple *unconditional* implication is only for an opener required to return a valid preimage of y, not for arbitrary native-valid signatures. Do not promote this into a strong-unforgeability claim. Changing R, auth paths, WOTS bytes or higher layers needs a separate arbitrary-signature argument (including same-message forgeries and auxiliary/sibling data). Ordinary EUF for honestly sampled native Sign alone is insufficient here. No such argument is supplied.

This fixed-hole simulator is classical and can be used as an explicit public-view generator relative to the chosen oracle, but no QROM programming bound or arbitrary-QPT preimage theorem with the actual source/native correlations has been proved. In particular a source miner's retained coins may contain additional inputs correlated with the source digest. They cannot be assumed independent in a bridge theorem.

## 3. Attempt to supply choose_digest from ORIGINAL evidence

A candidate that would actually use the original evidence is:

    choose_digest(P,A) = D(x_W,P,A)
    Open_inc(C,w):
        z = E(x_W,P,A,w)
        return Complete(C,z)

Here D must be classical PPT from the public statement at Build, and E must be classical PPT using any genuine original certificate at Open. The necessary equation is

    F(P,A,E(x_W,P,A,w)) = D(x_W,P,A)       for every R_x(w)=1.

For the already-frozen signature variant, strengthen it to E(...,w)=z* for every w. For the more permissive capability-only variant, any two honest witnesses yielding different z for the same y give an explicit collision of F. Therefore, barring an independent hash collision, the native leaf cannot absorb differing witness states by treating each as a different valid preimage. The missing common release equation has simply moved inside a native verification field.

Try the concrete source-digest assignment: set D to an authenticated baseline commitment (or a domain-separated hash of one) and E to the canonical header or proof bytes of the original evidence, reduced to n bytes by a public hash. This is NOT correct. The addressed native leaf function includes its own P,A and fixed-width n-byte input; source commitments authenticate different input encodings under source hash domains. Even if one candidate w contains a source preimage of the baseline commitment, no identity makes the native F(P,A,H(w)) equal to that commitment or H(commitment). In an idealized independent-domain experiment, for a fixed genuine w independent of the setup-selected native address and with F at the proposed z not used to construct D, the equality holds with probability 2^(-8n), not useful completeness. Publishing D=F(P,A,z_public) gives the preimage to unauthorized parties as well. Choosing D=F(P,A,E(w0)) from one known certificate w0 does not allow a different valid certificate w1 to complete it without the same preimage or a collision. The source-ground definitions do not require such a common preimage: alternate PoW histories, finite invalid/missing-burn evidence and relevant incompatible Syscoin histories are independently sufficient and can be produced by different participants. No new source admission claim is needed for this design check.

Consider using the signature randomizer instead to select a different native leaf for each source witness. This relaxes the exact frozen signature requirement, and is not an original solution even if it works. The selected FORS indices and hypertree address are functions of H_msg(R,VK,M); the rest of the partial signature was built for R0's indices/address. If one publishes a table of complete or fillable partial signatures indexed by R or by the derived indices, any table entry having a publicly available leaf preimage is an unauthorized native capability. If the leaf preimages are hidden, each entry still requires the equation above at that coordinate. Merely setting R=H_source(w) supplies no access control: R is a native signature field, and for a postprocessor depending on w only via this fresh uniform hash output, an unauthorized party can sample uniform R with the same distribution (isolated random-oracle experiment, no source-dependent correlated setup). Keeping additional w-dependent processing might change that argument, but would require constructing its full joint correlation. A public verifier cannot repair the leaf-preimage equation by doing R_x(w) before insertion. This is not a proposal to enumerate the R-space or change the signature standard.

## 4. Handoff and limits

The useful narrow construction is the ability to generate a *native* preimage-conditioned incomplete signature without knowing the selected preimage; its fixed-hole public view is explicitly simulatable from the addressed leaf digest. It demonstrates where a native signature could enforce a source-derived condition without a secret evaluator, but the condition is equality to one fixed hash leaf and no qualifying ORIGINAL evidence-to-preimage map exists in this iteration. It neither constructs Build_inc on a supplied signature nor supplies a source-dependent joint simulator. Do not spend another run changing FORS tree counts, randomizer selection, public seed, native hash address, truncation, or source digest without an explicit mathematical source-to-preimage identity and full public correlation. The independent-OR grounds, source authentication and maturity, R225 activation binding, malicious setup, arbitrary QPT recovery/native forgery, and Bitcoin inclusion assumptions all remain intact and unresolved. The next candidate must supply a different mechanism for linking noncanonical original certificates to a common capability rather than using a native fixed preimage as if it were such a mechanism.

No real source evidence or native signing implementation, tests, code execution, signature/key generation, arbitrary QPT extraction or security proof in this analytical iteration. No new consensus source claims; no deployment or protocol modification. NONQUALIFYING: preserve only in research notes; no ordinary PR progress comment or user notification.
